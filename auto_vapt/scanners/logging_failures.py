"""A09:2021 — Security Logging and Monitoring Failures Scanner."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, Severity, Vulnerability
from auto_vapt.scanners.base import BaseScanner, register_scanner

log = get_logger(__name__)


@register_scanner
class LoggingFailuresScanner(BaseScanner):
    """Scans for security logging and monitoring failures (OWASP A09:2021).

    Checks for:
    - Lack of failed login logging (no lockout / no differential response)
    - Missing security-relevant response headers for monitoring
    - Exposed log files
    - Missing error logging indicators
    """

    scanner_id = "logging_failures"
    scanner_name = "Logging & Monitoring Scanner (A09)"
    owasp_category = OWASPCategory.A09_LOGGING_FAILURES

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        http_client: httpx.AsyncClient = kwargs.get("http_client") or httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(15.0), follow_redirects=True
        )

        try:
            await self._check_exposed_logs(http_client, target_url)
            await self._check_login_monitoring(http_client, target_url)
            await self._check_security_txt(http_client, target_url)
            await self._check_reporting_headers(http_client, target_url)
        finally:
            if "http_client" not in kwargs:
                await http_client.aclose()

    async def _check_exposed_logs(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Check for publicly accessible log files."""
        log_paths = [
            "/logs/", "/log/", "/debug.log", "/error.log",
            "/access.log", "/app.log", "/server.log",
            "/var/log/", "/wp-content/debug.log",
            "/storage/logs/laravel.log", "/logs/error.log",
            "/tmp/logs/", "/application.log",
        ]
        for path in log_paths:
            url = urljoin(base_url, path)
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.text) > 50:
                    body = resp.text.lower()
                    log_indicators = [
                        "error", "warning", "info", "debug",
                        "exception", "stack trace", "timestamp",
                        "[error]", "[warn]", "log entry",
                    ]
                    if any(ind in body for ind in log_indicators):
                        self.add_vulnerability(Vulnerability(
                            title=f"Exposed Log File ({path})",
                            description=(
                                f"The log file at {url} is publicly accessible. "
                                f"Log files may contain sensitive information including "
                                f"credentials, session tokens, internal IPs, and stack traces."
                            ),
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                            url=url,
                            evidence=f"HTTP 200 — log content detected ({len(resp.text)} bytes)",
                            remediation=(
                                "Block access to log files via web server configuration. "
                                "Store logs outside the web root. Use centralized logging "
                                "(ELK, Splunk, CloudWatch) instead of file-based logging."
                            ),
                            cwe_id="CWE-532",
                        ))
                        return  # One finding is enough
            except httpx.RequestError:
                pass

    async def _check_login_monitoring(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Check if failed logins trigger any monitoring response."""
        login_paths = ["/login", "/api/login", "/auth/login", "/signin"]
        for path in login_paths:
            url = urljoin(base_url, path)
            try:
                # First check if page exists
                resp = await client.get(url)
                if resp.status_code == 404:
                    continue

                # Send multiple failed login attempts
                responses = []
                for i in range(5):
                    resp = await client.post(url, data={
                        "username": f"nonexistent_user_{i}",
                        "password": "wrong_password_12345",
                    })
                    responses.append({
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "has_lockout": any(w in resp.text.lower() for w in [
                            "locked", "blocked", "too many", "rate limit",
                            "temporarily", "wait", "try again later",
                        ]),
                    })

                # If no lockout detected after 5 attempts
                if not any(r["has_lockout"] for r in responses):
                    self.add_vulnerability(Vulnerability(
                        title="No Failed Login Monitoring Detected",
                        description=(
                            f"The login endpoint at {url} shows no evidence of "
                            f"monitoring or rate-limiting failed authentication attempts. "
                            f"5 rapid failed logins produced no lockout or throttling."
                        ),
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                        url=url,
                        evidence=f"5 failed logins — no lockout indicators in response",
                        remediation=(
                            "Implement login attempt monitoring with alerts. "
                            "Log all failed authentication attempts with IP, timestamp, "
                            "and username. Set up SIEM rules for brute-force detection."
                        ),
                        cwe_id="CWE-778",
                    ))
                    return
            except httpx.RequestError:
                pass

    async def _check_security_txt(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Check for security.txt (RFC 9116) which indicates security awareness."""
        for path in ["/.well-known/security.txt", "/security.txt"]:
            url = urljoin(base_url, path)
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and "contact" in resp.text.lower():
                    return  # security.txt exists — good practice
            except httpx.RequestError:
                pass

        self.add_vulnerability(Vulnerability(
            title="Missing security.txt",
            description=(
                f"The target {base_url} does not have a security.txt file "
                f"(RFC 9116). This file helps security researchers report "
                f"vulnerabilities responsibly."
            ),
            severity=Severity.INFO,
            cvss_score=0.0,
            owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
            url=base_url,
            remediation=(
                "Create a /.well-known/security.txt file with Contact, Expires, "
                "and Preferred-Languages fields per RFC 9116."
            ),
            cwe_id="CWE-1059",
        ))

    async def _check_reporting_headers(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Check for security reporting/monitoring headers."""
        try:
            resp = await client.get(base_url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check for Report-To / Reporting-Endpoints / NEL headers
            monitoring_headers = {
                "report-to": "Report-To",
                "reporting-endpoints": "Reporting-Endpoints",
                "nel": "Network Error Logging (NEL)",
            }

            missing = []
            for header, name in monitoring_headers.items():
                if header not in headers:
                    missing.append(name)

            if missing and len(missing) == len(monitoring_headers):
                self.add_vulnerability(Vulnerability(
                    title="No Browser Error Reporting Headers",
                    description=(
                        f"The target {base_url} does not implement any browser error "
                        f"reporting headers (Report-To, Reporting-Endpoints, NEL). "
                        f"These help detect client-side attacks and errors."
                    ),
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                    url=base_url,
                    evidence=f"Missing: {', '.join(missing)}",
                    remediation=(
                        "Implement Reporting-Endpoints and Report-To headers to receive "
                        "CSP violations, deprecation warnings, and network errors."
                    ),
                    cwe_id="CWE-778",
                ))
        except httpx.RequestError:
            pass
