from core.engine import run_scan


def scan_target(target, no_recon=False, generate_report=False, disabled_tools=None):
    """
    Scan controller for VULNSCAN
    """

    scan_data = run_scan(
        target=target,
        no_recon=no_recon,
        generate_report=generate_report,
        disabled_tools=disabled_tools
    )

    return scan_data
