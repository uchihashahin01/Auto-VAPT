"""Scan diffing — compare two scan reports to identify changes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from auto_vapt.models import Vulnerability


@dataclass
class ScanDiff:
    """Result of comparing two scans."""

    scan_a_id: str
    scan_b_id: str
    new_vulns: list[dict[str, Any]] = field(default_factory=list)
    resolved_vulns: list[dict[str, Any]] = field(default_factory=list)
    unchanged_vulns: list[dict[str, Any]] = field(default_factory=list)
    risk_score_a: float = 0.0
    risk_score_b: float = 0.0
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_a_id": self.scan_a_id,
            "scan_b_id": self.scan_b_id,
            "new_vulnerabilities": self.new_vulns,
            "resolved_vulnerabilities": self.resolved_vulns,
            "unchanged_vulnerabilities": self.unchanged_vulns,
            "risk_score_a": self.risk_score_a,
            "risk_score_b": self.risk_score_b,
            "risk_delta": round(self.risk_score_b - self.risk_score_a, 1),
            "summary": self.summary,
        }


def _vuln_fingerprint(v: dict[str, Any]) -> str:
    """Create a fingerprint for a vulnerability to match across scans."""
    title = v.get("title", "")
    url = v.get("url", "")
    param = v.get("parameter", "")
    cwe = v.get("cwe_id", "")
    return f"{title}|{url}|{param}|{cwe}"


def diff_scans(
    scan_a: dict[str, Any],
    vulns_a: list[dict[str, Any]],
    scan_b: dict[str, Any],
    vulns_b: list[dict[str, Any]],
) -> ScanDiff:
    """Compare two scans and return the diff.

    Args:
        scan_a: The baseline (older) scan metadata.
        vulns_a: Vulnerabilities from scan A.
        scan_b: The comparison (newer) scan metadata.
        vulns_b: Vulnerabilities from scan B.

    Returns:
        ScanDiff with new, resolved, and unchanged vulnerabilities.
    """
    fp_a = {_vuln_fingerprint(v): v for v in vulns_a}
    fp_b = {_vuln_fingerprint(v): v for v in vulns_b}

    keys_a = set(fp_a.keys())
    keys_b = set(fp_b.keys())

    result = ScanDiff(
        scan_a_id=scan_a.get("id", ""),
        scan_b_id=scan_b.get("id", ""),
        risk_score_a=scan_a.get("risk_score", 0),
        risk_score_b=scan_b.get("risk_score", 0),
    )

    result.new_vulns = [fp_b[k] for k in keys_b - keys_a]
    result.resolved_vulns = [fp_a[k] for k in keys_a - keys_b]
    result.unchanged_vulns = [fp_b[k] for k in keys_a & keys_b]

    result.summary = {
        "new_count": len(result.new_vulns),
        "resolved_count": len(result.resolved_vulns),
        "unchanged_count": len(result.unchanged_vulns),
        "total_a": len(vulns_a),
        "total_b": len(vulns_b),
        "risk_delta": round(result.risk_score_b - result.risk_score_a, 1),
        "improved": result.risk_score_b < result.risk_score_a,
    }

    return result
