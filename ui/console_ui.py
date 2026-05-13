from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()


def print_banner():
    banner = """
██╗   ██╗██╗   ██╗██╗     ██╗   ██╗███╗   ██╗███████╗
██║   ██║██║   ██║██║     ██║   ██║████╗  ██║██╔════╝
██║   ██║██║   ██║██║     ██║   ██║██╔██╗ ██║█████╗
╚██╗ ██╔╝██║   ██║██║     ██║   ██║██║╚██╗██║██╔══╝
 ╚████╔╝ ╚██████╔╝███████╗╚██████╔╝██║ ╚████║███████╗
  ╚═══╝   ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝

      Unified Vulnerability Scanner
          Author: CYBER_ABDUL
    """

    console.print(Panel.fit(banner, border_style="cyan"))


def show_progress():
    return Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
    )


def show_open_ports(open_ports, services):
    table = Table(title="Open Ports", header_style="bold cyan")
    table.add_column("Port")
    table.add_column("Service")

    for port in open_ports:
        table.add_row(str(port), services.get(port, "unknown"))

    console.print(table)


def show_results(results):
    for plugin in results:
        console.print(f"\n[bold yellow]{plugin.get('category','GENERIC').upper()}[/bold yellow]")

        table = Table()
        table.add_column("Severity")
        table.add_column("Issue")
        table.add_column("CVE")

        for issue in plugin.get("issues", []):
            table.add_row(
                str(issue.get("severity", "LOW")),
                str(issue.get("title", "")),
                str(issue.get("cve", "None"))
            )

        console.print(table)
