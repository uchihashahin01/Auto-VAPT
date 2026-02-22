"""Core data models for scan results, vulnerabilities, and reports."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """CVSS v3.1 severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        """Rich console color for this severity."""
        return {
            Severity.CRITICAL: "red bold",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]

    @property
    def cvss_range(self) -> tuple[float, float]:
        """CVSS score range for this severity."""
        return {
            Severity.CRITICAL: (9.0, 10.0),
            Severity.HIGH: (7.0, 8.9),
            Severity.MEDIUM: (4.0, 6.9),
            Severity.LOW: (0.1, 3.9),
            Severity.INFO: (0.0, 0.0),
        }[self]


class OWASPCategory(str, Enum):
    """OWASP Top 10 (2021) categories."""

    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_DATA_INTEGRITY = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery"


class Vulnerability(BaseModel):
    """A single discovered vulnerability."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    description: str
    severity: Severity
    cvss_score: float = Field(ge=0.0, le=10.0, default=0.0)
    owasp_category: OWASPCategory
    url: str = ""
    parameter: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cwe_id: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    false_positive: bool = False
    scanner: str = ""

    @property
    def risk_label(self) -> str:
        """Human-readable risk label."""
        return f"[{self.severity.value}] CVSS {self.cvss_score}"


class TargetInfo(BaseModel):
    """Information about the scan target."""

    url: str
    ip_address: str = ""
    hostname: str = ""
    open_ports: list[int] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    server: str = ""
    powered_by: str = ""
    framework: str = ""
    cms: str = ""
    os_guess: str = ""
    http_methods: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    robots_txt: str = ""
    sitemap_urls: list[str] = Field(default_factory=list)


class ScanStatus(str, Enum):
    """Status of a scan."""

    PENDING = "PENDING"
    PROFILING = "PROFILING"
    SCANNING = "SCANNING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanResult(BaseModel):
    """Result from a single scanner module."""

    scanner_name: str
    owasp_category: OWASPCategory
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    duration_seconds: float = 0.0
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def vuln_count(self) -> dict[str, int]:
        """Count vulnerabilities by severity."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts


class ScanReport(BaseModel):
    """Complete scan report aggregating all scanner results."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: TargetInfo
    scan_profile: str = "default"
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    status: ScanStatus = ScanStatus.PENDING
    results: list[ScanResult] = Field(default_factory=list)
    total_duration_seconds: float = 0.0
    config_used: dict[str, Any] = Field(default_factory=dict)

    @property
    def all_vulnerabilities(self) -> list[Vulnerability]:
        """Get all vulnerabilities across all scanner results."""
        vulns: list[Vulnerability] = []
        for result in self.results:
            vulns.extend(result.vulnerabilities)
        return sorted(vulns, key=lambda v: v.cvss_score, reverse=True)

    @property
    def severity_summary(self) -> dict[str, int]:
        """Count total vulnerabilities by severity."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for vuln in self.all_vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        score = 0.0
        for vuln in self.all_vulnerabilities:
            score += weights.get(vuln.severity, 0)
        return min(score, 100.0)

    @property
    def pass_fail(self) -> bool:
        """Determine if scan passes security gate (no CRITICAL/HIGH findings)."""
        summary = self.severity_summary
        return summary["CRITICAL"] == 0 and summary["HIGH"] == 0
