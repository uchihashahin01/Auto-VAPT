"""Auto-VAPT Command Line Interface."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from auto_vapt import __version__
from auto_vapt.config import ScanConfig, create_config_from_args, load_config
from auto_vapt.logger import setup_logging, get_logger
from auto_vapt.models import Severity

console = Console()
log = get_logger(__name__)

BANNER = r"""
   ___         __           _   _____    ___  ______
  / _ | __ __ / /_ ___  ___| | / / _ |  / _ \/_  __/
 / __ |/ // // __// _ \/___/ |/ / __ | / ___/ / /
/_/ |_|\_,_/ \__/ \___/    |___/_/ |_|/_/    /_/

  CI/CD Integrated Vulnerability Assessment Scanner
"""


def print_banner() -> None:
    """Print the Auto-VAPT banner."""
    console.print(
        Panel(
            Text(BANNER, style="bold cyan"),
            subtitle=f"v{__version__}",
            border_style="bright_blue",
            box=box.DOUBLE_EDGE,
        )
    )


@click.group()
@click.version_option(version=__version__, prog_name="auto-vapt")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output.")
@click.option("--json-log", is_flag=True, help="Output logs as JSON (for CI pipelines).")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, json_log: bool) -> None:
    """Auto-VAPT: Automated Vulnerability Assessment & Penetration Testing."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose=verbose, json_output=json_log)


@cli.command()
@click.argument("target_url")
@click.option(
    "-p",
    "--profile",
    type=click.Choice(["default", "quick", "full", "api", "ci"]),
    default="default",
    help="Scan profile to use.",
)
@click.option(
    "-c", "--config", "config_file", type=click.Path(exists=True), help="Path to config YAML file."
)
@click.option(
    "-o", "--output", "output_dir", default="./reports", help="Output directory for reports."
)
@click.option(
    "-f",
    "--format",
    "formats",
    multiple=True,
    type=click.Choice(["html", "json", "pdf", "sarif"]),
    default=["html", "json"],
    help="Report format(s).",
)
@click.option("--ci", "ci_mode", is_flag=True, help="Enable CI/CD mode with security gates.")
@click.option("--rate-limit", default=10, type=int, help="Max requests per second.")
@click.option("--timeout", default=1800, type=int, help="Global scan timeout in seconds.")
@click.option("--no-ssl-verify", is_flag=True, help="Disable SSL certificate verification.")
@click.option("--plugins", "plugin_dir", type=click.Path(exists=True), help="Directory with custom scanner plugins.")
@click.pass_context
def scan(
    ctx: click.Context,
    target_url: str,
    profile: str,
    config_file: str | None,
    output_dir: str,
    formats: tuple[str, ...],
    ci_mode: bool,
    rate_limit: int,
    timeout: int,
    no_ssl_verify: bool,
    plugin_dir: str | None,
) -> None:
    """Run a vulnerability assessment scan against TARGET_URL.

    Example:
        auto-vapt scan https://example.com -p quick -f html json
    """
    print_banner()

    # Load or create configuration
    if config_file:
        console.print(f"[dim]Loading config from:[/] {config_file}")
        config = load_config(config_file)
    else:
        config = create_config_from_args(
            target_url=target_url,
            profile=profile,
            output_dir=output_dir,
            formats=list(formats),
            ci_mode=ci_mode,
            rate_limit=rate_limit,
            timeout=timeout,
            verify_ssl=not no_ssl_verify,
        )

    # Display scan configuration summary
    _print_scan_config(config)

    # Load plugins if directory specified
    if plugin_dir:
        from auto_vapt.plugins import load_plugins
        count = load_plugins(plugin_dir)
        if count:
            console.print(f"  [green]✓[/] Loaded {count} plugin(s) from {plugin_dir}")

    # Run the scan
    from auto_vapt.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator(config)
    try:
        import asyncio

        report = asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan cancelled by user.[/]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]✗ Scan failed: {e}[/]")
        log.error("scan_failed", error=str(e))
        sys.exit(1)

    # Display results summary
    _print_results_summary(report)

    # CI mode: exit with appropriate code
    if ci_mode and not report.pass_fail:
        console.print("[red bold]✗ Security gate FAILED — vulnerabilities exceed threshold.[/]")
        sys.exit(1)

    console.print("[green bold]✓ Scan complete.[/]")


@cli.command()
@click.argument("scan_a")
@click.argument("scan_b")
def diff(scan_a: str, scan_b: str) -> None:
    """Compare two scans to show new, resolved, and unchanged findings.

    SCAN_A and SCAN_B are paths to JSON report files.

    Example:
        auto-vapt diff reports/scan-old.json reports/scan-new.json
    """
    import json
    from auto_vapt.diff import diff_scans

    for p in (scan_a, scan_b):
        if not Path(p).exists():
            console.print(f"[red]✗ File not found: {p}[/]")
            sys.exit(1)

    with open(scan_a) as f:
        data_a = json.load(f)
    with open(scan_b) as f:
        data_b = json.load(f)

    vulns_a = []
    for r in data_a.get("results", []):
        vulns_a.extend(r.get("vulnerabilities", []))
    vulns_b = []
    for r in data_b.get("results", []):
        vulns_b.extend(r.get("vulnerabilities", []))

    result = diff_scans(data_a, vulns_a, data_b, vulns_b)
    d = result.to_dict()

    delta = d["risk_delta"]
    delta_str = f"+{delta}" if delta > 0 else str(delta)
    delta_color = "red" if delta > 0 else "green" if delta < 0 else "dim"

    console.print(Panel(
        f"[bold]Scan A:[/] {scan_a}\n[bold]Scan B:[/] {scan_b}",
        title="Scan Diff", border_style="cyan",
    ))

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("New Findings", f"[red]+{d['summary']['new_count']}[/]")
    table.add_row("Resolved", f"[green]-{d['summary']['resolved_count']}[/]")
    table.add_row("Unchanged", str(d["summary"]["unchanged_count"]))
    table.add_row("Risk Delta", f"[{delta_color}]{delta_str}[/]")
    console.print(table)

    if result.new_vulns:
        console.print("\n[red bold]New Vulnerabilities:[/]")
        for v in result.new_vulns:
            sev = v.get("severity", "INFO")
            console.print(f"  [red]+[/] [{sev}] {v.get('title', 'Unknown')}")

    if result.resolved_vulns:
        console.print("\n[green bold]Resolved Vulnerabilities:[/]")
        for v in result.resolved_vulns:
            sev = v.get("severity", "INFO")
            console.print(f"  [green]-[/] [{sev}] {v.get('title', 'Unknown')}")


@cli.command(name="config-check")
@click.argument("config_file", type=click.Path(exists=True))
def config_check(config_file: str) -> None:
    """Validate a scan configuration YAML file.

    Example:
        auto-vapt config-check configs/default.yaml
    """
    try:
        config = load_config(config_file)
        console.print(f"[green]✓ Configuration is valid![/]")
        _print_scan_config(config)
    except Exception as e:
        console.print(f"[red]✗ Configuration error: {e}[/]")
        sys.exit(1)


@cli.command()
def profiles() -> None:
    """List available scan profiles and their descriptions."""
    print_banner()

    table = Table(title="Scan Profiles", box=box.ROUNDED, border_style="cyan")
    table.add_column("Profile", style="bold cyan")
    table.add_column("Description")
    table.add_column("Depth", justify="center")
    table.add_column("Timeout", justify="center")
    table.add_column("Scanners", justify="center")

    table.add_row(
        "quick", "Fast scan — injection + misconfig only", "1", "10m", "2"
    )
    table.add_row(
        "default", "Standard scan — all OWASP Top 10 modules", "3", "30m", "10"
    )
    table.add_row(
        "full", "Deep scan — max depth, all modules, thorough", "5", "30m", "10"
    )
    table.add_row(
        "api", "API-focused — injection, access control, auth", "3", "30m", "3"
    )
    table.add_row(
        "ci", "CI/CD optimized — balanced speed with coverage", "2", "15m", "10"
    )

    console.print(table)


def _print_scan_config(config: ScanConfig) -> None:
    """Print scan configuration summary."""
    table = Table(
        title="Scan Configuration",
        box=box.ROUNDED,
        border_style="bright_blue",
        show_header=False,
    )
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Target", config.target.url)
    table.add_row("Profile", config.profile)
    table.add_row("Max Depth", str(config.max_depth))
    table.add_row("Rate Limit", f"{config.rate_limit} req/s")
    table.add_row("Timeout", f"{config.global_timeout}s")
    table.add_row("SSL Verify", "Yes" if config.verify_ssl else "No")
    table.add_row("Scanners", ", ".join(config.scanners.keys()))
    table.add_row("Report Formats", ", ".join(config.report.formats))
    table.add_row("CI Mode", "Enabled" if config.ci.enabled else "Disabled")

    console.print(table)
    console.print()


def _print_results_summary(report: object) -> None:
    """Print scan results summary table."""
    from auto_vapt.models import ScanReport

    if not isinstance(report, ScanReport):
        return

    summary = report.severity_summary

    table = Table(
        title="Scan Results Summary",
        box=box.HEAVY_HEAD,
        border_style="bright_blue",
    )
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="center")

    for severity in Severity:
        count = summary.get(severity.value, 0)
        style = severity.color if count > 0 else "dim"
        table.add_row(severity.value, str(count), style=style)

    table.add_row("", "", end_section=True)
    table.add_row(
        "Risk Score",
        f"{report.risk_score:.1f}/100",
        style="bold red" if report.risk_score > 50 else "bold yellow",
    )
    table.add_row(
        "Security Gate",
        "[green]PASS[/]" if report.pass_fail else "[red bold]FAIL[/]",
    )

    console.print(table)
    console.print()

    # Show top vulnerabilities
    top_vulns = report.all_vulnerabilities[:5]
    if top_vulns:
        vuln_table = Table(
            title="Top Vulnerabilities",
            box=box.ROUNDED,
            border_style="red",
        )
        vuln_table.add_column("#", justify="center", width=3)
        vuln_table.add_column("Severity", width=10)
        vuln_table.add_column("CVSS", justify="center", width=5)
        vuln_table.add_column("Title", min_width=30)
        vuln_table.add_column("OWASP", width=15)

        for i, vuln in enumerate(top_vulns, 1):
            vuln_table.add_row(
                str(i),
                f"[{vuln.severity.color}]{vuln.severity.value}[/]",
                f"{vuln.cvss_score:.1f}",
                vuln.title,
                vuln.owasp_category.name[:15],
            )

        console.print(vuln_table)
        console.print()
