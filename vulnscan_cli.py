import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich import box

from core.controller import scan_target

console = Console()
TOOL_CHOICES = ("sublist3r", "subfinder", "amass", "httpx", "nuclei")
THEME = {
    "accent": "bright_cyan",
    "accent_2": "bright_magenta",
    "ok": "bright_green",
    "warn": "bright_yellow",
    "muted": "grey70",
}


def banner():
    ascii_art = r"""
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

             Unified Vulnerability Scanner
"""
    console.print(
        Panel.fit(
            f"[{THEME['accent']}]{ascii_art}[/{THEME['accent']}]",
            title=f"[bold {THEME['accent_2']}]VULNSCAN[/bold {THEME['accent_2']}]",
            subtitle=f"[{THEME['muted']}]Author: Cyber_Abdul[/{THEME['muted']}]",
            border_style=THEME["accent"],
            box=box.ROUNDED,
        )
    )


def show_ports(open_ports, services, versions, cves):
    table = Table(
        title=f"[bold {THEME['accent']}]Open Services[/bold {THEME['accent']}]",
        box=box.SIMPLE_HEAVY,
        header_style=f"bold {THEME['accent']}"
    )
    table.add_column("Port", style=THEME["accent"])
    table.add_column("Service", style=THEME["ok"])
    table.add_column("Version", style=THEME["accent_2"])
    table.add_column("CVE", style=THEME["warn"])

    if not open_ports:
        table.add_row("-", "No data found", "-", "-")
    else:
        for port in open_ports:
            table.add_row(
                str(port),
                services.get(port, "unknown"),
                versions.get(port) or "-",
                cves.get(port) or "-"
            )

    console.print(table)


def show_cve_table(open_ports, services, versions, cves):
    table = Table(
        title=f"[bold {THEME['warn']}]Detected CVEs[/bold {THEME['warn']}]",
        box=box.SIMPLE_HEAVY,
        header_style=f"bold {THEME['warn']}"
    )
    table.add_column("Port", style=THEME["accent"])
    table.add_column("Service", style=THEME["ok"])
    table.add_column("Version", style=THEME["accent_2"])
    table.add_column("CVE", style=THEME["warn"])

    rows = 0
    for port in open_ports:
        cve = cves.get(port)
        if not cve:
            continue
        table.add_row(
            str(port),
            services.get(port, "unknown"),
            versions.get(port) or "-",
            cve
        )
        rows += 1

    if rows == 0:
        table.add_row("-", "-", "-", "No CVEs matched")

    console.print(table)


def show_subdomains(subdomains):
    table = Table(
        title=f"[bold {THEME['accent_2']}]Subdomains (Recon Tools)[/bold {THEME['accent_2']}]",
        box=box.SIMPLE_HEAVY,
        header_style=f"bold {THEME['accent_2']}"
    )
    table.add_column("Subdomain", style=THEME["accent_2"])

    if not subdomains:
        table.add_row("No subdomains found")
    else:
        for subdomain in subdomains:
            table.add_row(subdomain)

    console.print(table)


def show_results(data):
    console.print(f"\n[bold {THEME['ok']}]SCAN COMPLETE[/bold {THEME['ok']}]\n")
    console.print(f"[{THEME['accent']}]Target:[/{THEME['accent']}] {data['target']}\n")

    show_ports(
        data.get("open_ports", []),
        data.get("services", {}),
        data.get("versions", {}),
        data.get("cves", {})
    )
    show_cve_table(
        data.get("open_ports", []),
        data.get("services", {}),
        data.get("versions", {}),
        data.get("cves", {})
    )
    show_subdomains(data.get("subdomains", []))

    for plugin in data["results"]:
        console.print(
            f"\n[bold {THEME['warn']}]{plugin['plugin'].upper()}[/bold {THEME['warn']}]"
        )

        table = Table(box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("Severity", style=THEME["warn"])
        table.add_column("Issue", style="white")
        table.add_column("CVE", style=THEME["accent_2"])

        issues = plugin.get("issues", [])

        if not issues:
            table.add_row("-", "No issues found", "-")
        else:
            for issue in issues:
                table.add_row(
                    issue.get("severity", "-"),
                    issue.get("title", "-"),
                    str(issue.get("cve", "-"))
                )

        console.print(table)


def run():
    parser = argparse.ArgumentParser(description="Unified Vulnerability Scanner")
    parser.add_argument("-t", "--target", help="Target IP, hostname, or URL")
    parser.add_argument(
        "--disable-tool",
        action="append",
        default=[],
        choices=TOOL_CHOICES,
        help="Disable specific advanced tools (repeatable)",
    )
    parser.add_argument(
        "--no-recon",
        action="store_true",
        help="Disable recon subdomain enumeration tools",
    )
    args = parser.parse_args()

    banner()

    target = (args.target or "").strip()
    if not target:
        target = console.input(
            f"[bold {THEME['accent']}]Enter target (IP or URL):[/bold {THEME['accent']}] "
        ).strip()

    console.print(f"\n[{THEME['accent']}][+] Running scan on {target}[/{THEME['accent']}]\n")

    with Progress() as progress:
        task = progress.add_task("Scanning...", total=100)

        data = scan_target(
            target=target,
            no_recon=args.no_recon,
            disabled_tools=args.disable_tool,
        )

        progress.update(task, completed=100)

    show_results(data)


if __name__ == "__main__":
    run()
