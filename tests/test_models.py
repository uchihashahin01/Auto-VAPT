"""Tests for Auto-VAPT core models."""

import pytest
from auto_vapt.models import (
    Severity,
    OWASPCategory,
    Vulnerability,
    ScanResult,
    ScanReport,
    TargetInfo,
    ScanStatus,
)


class TestSeverity:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.INFO.value == "INFO"

    def test_severity_color(self):
        assert "red" in Severity.CRITICAL.color
        assert "yellow" in Severity.MEDIUM.color

    def test_cvss_range(self):
        assert Severity.CRITICAL.cvss_range == (9.0, 10.0)
        assert Severity.LOW.cvss_range == (0.1, 3.9)


class TestVulnerability:
    def test_create_vulnerability(self):
        vuln = Vulnerability(
            title="Test SQLi",
            description="SQL Injection found",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            owasp_category=OWASPCategory.A03_INJECTION,
            url="https://example.com/login",
            parameter="username",
        )
        assert vuln.title == "Test SQLi"
        assert vuln.severity == Severity.CRITICAL
        assert vuln.cvss_score == 9.8
        assert vuln.id  # Auto-generated

    def test_risk_label(self):
        vuln = Vulnerability(
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            cvss_score=7.5,
            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        )
        assert "[HIGH]" in vuln.risk_label
        assert "7.5" in vuln.risk_label


class TestScanReport:
    def _make_report(self, vulns: list[Vulnerability]) -> ScanReport:
        result = ScanResult(
            scanner_name="test",
            owasp_category=OWASPCategory.A03_INJECTION,
            vulnerabilities=vulns,
        )
        return ScanReport(
            target=TargetInfo(url="https://example.com"),
            results=[result],
        )

    def test_empty_report(self):
        report = self._make_report([])
        assert len(report.all_vulnerabilities) == 0
        assert report.risk_score == 0.0
        assert report.pass_fail is True

    def test_report_with_critical(self):
        vuln = Vulnerability(
            title="Critical",
            description="Critical finding",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            owasp_category=OWASPCategory.A03_INJECTION,
        )
        report = self._make_report([vuln])
        assert report.severity_summary["CRITICAL"] == 1
        assert report.pass_fail is False
        assert report.risk_score > 0

    def test_severity_summary(self):
        vulns = [
            Vulnerability(title="C1", description="", severity=Severity.CRITICAL, cvss_score=9.0, owasp_category=OWASPCategory.A03_INJECTION),
            Vulnerability(title="H1", description="", severity=Severity.HIGH, cvss_score=7.0, owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL),
            Vulnerability(title="M1", description="", severity=Severity.MEDIUM, cvss_score=5.0, owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION),
        ]
        report = self._make_report(vulns)
        assert report.severity_summary["CRITICAL"] == 1
        assert report.severity_summary["HIGH"] == 1
        assert report.severity_summary["MEDIUM"] == 1
        assert report.severity_summary["LOW"] == 0

    def test_vulns_sorted_by_cvss(self):
        vulns = [
            Vulnerability(title="Low", description="", severity=Severity.LOW, cvss_score=2.0, owasp_category=OWASPCategory.A03_INJECTION),
            Vulnerability(title="Critical", description="", severity=Severity.CRITICAL, cvss_score=9.8, owasp_category=OWASPCategory.A03_INJECTION),
        ]
        report = self._make_report(vulns)
        assert report.all_vulnerabilities[0].title == "Critical"


class TestConfig:
    def test_load_default_config(self):
        from auto_vapt.config import create_config_from_args
        config = create_config_from_args(target_url="https://example.com")
        assert config.target.url == "https://example.com"
        assert config.profile == "default"
        assert len(config.scanners) == 6

    def test_quick_profile(self):
        from auto_vapt.config import create_config_from_args
        config = create_config_from_args(target_url="https://example.com", profile="quick")
        assert config.max_depth == 1
        assert len(config.scanners) == 2

    def test_ci_profile(self):
        from auto_vapt.config import create_config_from_args
        config = create_config_from_args(target_url="https://example.com", profile="ci")
        assert config.ci.enabled is True
        assert config.ci.sarif_output is True
