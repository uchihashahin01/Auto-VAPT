"""A05:2021 — Security Misconfiguration Scanner."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, Severity, Vulnerability
from auto_vapt.scanners.base import BaseScanner, register_scanner

log = get_logger(__name__)

REQUIRED_HEADERS = {
    "X-Content-Type-Options": ("nosniff", Severity.MEDIUM, 5.3, "CWE-693",
        "Prevents MIME-type sniffing. Add 'X-Content-Type-Options: nosniff'."),
    "X-Frame-Options": ("DENY|SAMEORIGIN", Severity.MEDIUM, 5.3, "CWE-1021",
        "Prevents clickjacking. Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."),
    "Content-Security-Policy": ("", Severity.MEDIUM, 5.3, "CWE-693",
        "Mitigates XSS. Implement a strict CSP header."),
    "X-XSS-Protection": ("1; mode=block", Severity.LOW, 3.1, "CWE-693",
        "Legacy XSS filter. Add 'X-XSS-Protection: 1; mode=block'."),
    "Referrer-Policy": ("", Severity.LOW, 3.1, "CWE-200",
        "Controls referrer info leakage. Add 'Referrer-Policy: strict-origin-when-cross-origin'."),
    "Permissions-Policy": ("", Severity.LOW, 3.1, "CWE-693",
        "Controls browser feature access. Add a Permissions-Policy header."),
}

INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


@register_scanner
class MisconfigScanner(BaseScanner):
    """Scans for security misconfigurations: missing headers, CORS, debug endpoints."""

    scanner_id = "misconfig"
    scanner_name = "Security Misconfiguration Scanner (A05)"
    owasp_category = OWASPCategory.A05_SECURITY_MISCONFIGURATION

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        http_client = kwargs.get("http_client") or httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(10.0), follow_redirects=True,
        )
        try:
            await self._check_security_headers(http_client, target_url)
            await self._check_info_leak(http_client, target_url)
            await self._check_cors(http_client, target_url)
            await self._check_debug_endpoints(http_client, target_url)
            await self._check_default_creds(http_client, target_url)
        finally:
            if "http_client" not in kwargs:
                await http_client.aclose()

    async def _check_security_headers(self, client: httpx.AsyncClient, url: str) -> None:
        try:
            resp = await client.get(url)
            for header, (expected, sev, cvss, cwe, fix) in REQUIRED_HEADERS.items():
                val = resp.headers.get(header, "")
                if not val:
                    self.add_vulnerability(Vulnerability(
                        title=f"Missing Security Header: {header}",
                        description=f"The {header} header is not set.",
                        severity=sev, cvss_score=cvss,
                        owasp_category=self.owasp_category, url=url,
                        evidence=f"{header} header missing",
                        remediation=fix, cwe_id=cwe,
                    ))
        except httpx.RequestError:
            pass

    async def _check_info_leak(self, client: httpx.AsyncClient, url: str) -> None:
        try:
            resp = await client.get(url)
            for hdr in INFO_LEAK_HEADERS:
                val = resp.headers.get(hdr, "")
                if val:
                    self.add_vulnerability(Vulnerability(
                        title=f"Information Disclosure via {hdr} Header",
                        description=f"'{hdr}: {val}' reveals server technology.",
                        severity=Severity.LOW, cvss_score=3.1,
                        owasp_category=self.owasp_category, url=url,
                        evidence=f"{hdr}: {val}",
                        remediation=f"Remove or obfuscate the '{hdr}' header.",
                        cwe_id="CWE-200",
                    ))
        except httpx.RequestError:
            pass

    async def _check_cors(self, client: httpx.AsyncClient, url: str) -> None:
        for origin in CORS_TEST_ORIGINS:
            try:
                resp = await client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                if acao == "*" or acao == origin:
                    creds = resp.headers.get("access-control-allow-credentials", "").lower()
                    sev = Severity.HIGH if creds == "true" else Severity.MEDIUM
                    cvss = 8.1 if creds == "true" else 5.3
                    self.add_vulnerability(Vulnerability(
                        title="CORS Misconfiguration",
                        description=f"CORS allows origin '{origin}'" +
                            (" with credentials" if creds == "true" else ""),
                        severity=sev, cvss_score=cvss,
                        owasp_category=self.owasp_category, url=url,
                        evidence=f"ACAO: {acao}, credentials: {creds}",
                        remediation="Restrict CORS to trusted origins. Never reflect arbitrary origins with credentials.",
                        cwe_id="CWE-942",
                    ))
                    return
            except httpx.RequestError:
                pass

    async def _check_debug_endpoints(self, client: httpx.AsyncClient, url: str) -> None:
        debug_paths = [
            "/debug", "/trace", "/console", "/actuator", "/actuator/env",
            "/actuator/health", "/_debug", "/elmah.axd", "/trace.axd",
            "/__debug__", "/api/debug", "/graphiql", "/altair",
        ]
        for path in debug_paths:
            try:
                resp = await client.get(urljoin(url, path))
                if resp.status_code == 200 and len(resp.text) > 50:
                    indicators = ["debug", "stack trace", "traceback", "actuator", "graphiql"]
                    if any(ind in resp.text.lower() for ind in indicators):
                        self.add_vulnerability(Vulnerability(
                            title=f"Debug Endpoint Exposed ({path})",
                            description=f"Debug interface at {path} is publicly accessible.",
                            severity=Severity.HIGH, cvss_score=7.5,
                            owasp_category=self.owasp_category, url=urljoin(url, path),
                            evidence=f"HTTP 200 with debug content",
                            remediation="Disable debug endpoints in production.",
                            cwe_id="CWE-489",
                        ))
            except httpx.RequestError:
                pass

    async def _check_default_creds(self, client: httpx.AsyncClient, url: str) -> None:
        creds = [("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                 ("root", "root"), ("test", "test"), ("admin", "")]
        login_paths = ["/login", "/admin/login", "/admin", "/signin", "/wp-login.php"]

        for path in login_paths:
            login_url = urljoin(url, path)
            try:
                resp = await client.get(login_url)
                if resp.status_code != 200:
                    continue
                if "password" not in resp.text.lower():
                    continue
                for user, pwd in creds:
                    try:
                        r = await client.post(login_url, data={"username": user, "password": pwd}, follow_redirects=True)
                        fail_indicators = ["invalid", "incorrect", "failed", "error", "wrong"]
                        if not any(ind in r.text.lower() for ind in fail_indicators):
                            if "dashboard" in r.text.lower() or "welcome" in r.text.lower() or r.status_code in (302, 303):
                                self.add_vulnerability(Vulnerability(
                                    title=f"Default Credentials ({user}:{pwd})",
                                    description=f"Login at {login_url} accepts default credentials.",
                                    severity=Severity.CRITICAL, cvss_score=9.8,
                                    owasp_category=self.owasp_category, url=login_url,
                                    evidence=f"Credentials: {user}:{pwd}",
                                    remediation="Change default credentials. Enforce strong password policies.",
                                    cwe_id="CWE-798",
                                ))
                                return
                    except httpx.RequestError:
                        pass
            except httpx.RequestError:
                pass
