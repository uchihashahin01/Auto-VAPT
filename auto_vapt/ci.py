"""CI/CD integration helpers — output formatting and security gate logic."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from auto_vapt.models import ScanReport, Severity


def evaluate_security_gate(report: ScanReport, fail_on: Severity = Severity.HIGH) -> bool:
    """Evaluate whether the scan passes the security gate.

    Args:
        report: The completed scan report.
        fail_on: Minimum severity that triggers a failure.

    Returns:
        True if the gate passes (no findings at or above threshold).
    """
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    threshold_idx = severity_order.index(fail_on)
    failing_severities = severity_order[: threshold_idx + 1]

    summary = report.severity_summary
    for sev in failing_severities:
        if summary.get(sev.value, 0) > 0:
            return False
    return True


def format_ci_summary(report: ScanReport) -> str:
    """Format a concise CI-friendly summary.

    Args:
        report: The completed scan report.

    Returns:
        Multi-line summary string for CI output.
    """
    summary = report.severity_summary
    total = sum(summary.values())
    gate = "PASS ✓" if report.pass_fail else "FAIL ✗"

    lines = [
        "═══════════════════════════════════════════",
        "  Auto-VAPT Security Scan Results",
        "═══════════════════════════════════════════",
        f"  Target:     {report.target.url}",
        f"  Profile:    {report.scan_profile}",
        f"  Duration:   {report.total_duration_seconds:.1f}s",
        "───────────────────────────────────────────",
        f"  CRITICAL:   {summary.get('CRITICAL', 0)}",
        f"  HIGH:       {summary.get('HIGH', 0)}",
        f"  MEDIUM:     {summary.get('MEDIUM', 0)}",
        f"  LOW:        {summary.get('LOW', 0)}",
        f"  INFO:       {summary.get('INFO', 0)}",
        "───────────────────────────────────────────",
        f"  Total:      {total}",
        f"  Risk Score: {report.risk_score:.1f}/100",
        f"  Gate:       {gate}",
        "═══════════════════════════════════════════",
    ]
    return "\n".join(lines)


def write_github_output(report: ScanReport) -> None:
    """Write GitHub Actions output variables.

    Args:
        report: The completed scan report.
    """
    github_output = Path(sys.environ.get("GITHUB_OUTPUT", "/dev/null"))
    summary = report.severity_summary

    with open(github_output, "a") as f:
        f.write(f"total_findings={sum(summary.values())}\n")
        f.write(f"critical_count={summary.get('CRITICAL', 0)}\n")
        f.write(f"high_count={summary.get('HIGH', 0)}\n")
        f.write(f"risk_score={report.risk_score:.1f}\n")
        f.write(f"gate_passed={str(report.pass_fail).lower()}\n")
