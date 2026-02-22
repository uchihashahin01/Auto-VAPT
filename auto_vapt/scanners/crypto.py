"""A02:2021 — Cryptographic Failures Scanner."""

from __future__ import annotations

import ssl
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, Severity, Vulnerability
from auto_vapt.scanners.base import BaseScanner, register_scanner

log = get_logger(__name__)

WEAK_TLS_VERSIONS = {
    ssl.TLSVersion.TLSv1: "TLS 1.0",
    ssl.TLSVersion.TLSv1_1: "TLS 1.1",
}


@register_scanner
class CryptoScanner(BaseScanner):
    """Scans for TLS/SSL weaknesses, missing HSTS, and insecure cookies."""

    scanner_id = "crypto"
    scanner_name = "Cryptographic Failures Scanner (A02)"
    owasp_category = OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        parsed = urlparse(target_url)
        http_client = kwargs.get("http_client") or httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(10.0), follow_redirects=False,
        )
        try:
            await self._check_https(http_client, target_url)
            await self._check_hsts(target_url)
            if parsed.scheme == "https":
                await self._check_tls(parsed.hostname or "", parsed.port or 443)
                await self._check_cert(parsed.hostname or "", parsed.port or 443)
            await self._check_cookies(target_url)
        finally:
            if "http_client" not in kwargs:
                await http_client.aclose()

    async def _check_https(self, client: httpx.AsyncClient, url: str) -> None:
        if not urlparse(url).scheme == "http":
            return
        try:
            resp = await client.get(url)
            if resp.status_code in (301, 302, 307, 308):
                loc = resp.headers.get("location", "")
                if loc.startswith("https://"):
                    return
            self.add_vulnerability(Vulnerability(
                title="No HTTPS Enforcement",
                description=f"Site at {url} served over HTTP without HTTPS redirect.",
                severity=Severity.HIGH, cvss_score=7.4,
                owasp_category=self.owasp_category, url=url,
                evidence=f"HTTP {resp.status_code} — no HTTPS redirect",
                remediation="Redirect all HTTP to HTTPS. Use Let's Encrypt for free TLS certs.",
                cwe_id="CWE-319",
            ))
        except httpx.RequestError:
            pass

    async def _check_hsts(self, url: str) -> None:
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as c:
                resp = await c.get(url)
            hsts = resp.headers.get("strict-transport-security", "")
            if not hsts:
                self.add_vulnerability(Vulnerability(
                    title="Missing HSTS Header",
                    description="Strict-Transport-Security header missing — vulnerable to downgrade attacks.",
                    severity=Severity.HIGH, cvss_score=7.4,
                    owasp_category=self.owasp_category, url=url,
                    evidence="HSTS header not present",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
                    cwe_id="CWE-523",
                ))
        except httpx.RequestError:
            pass

    async def _check_tls(self, hostname: str, port: int) -> None:
        import asyncio
        for tls_ver, name in WEAK_TLS_VERSIONS.items():
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.maximum_version = tls_ver
                ctx.minimum_version = tls_ver
                loop = asyncio.get_event_loop()
                sock = await loop.run_in_executor(None, lambda: socket.create_connection((hostname, port), timeout=5))
                try:
                    ss = await loop.run_in_executor(None, lambda: ctx.wrap_socket(sock, server_hostname=hostname))
                    ss.close()
                    self.add_vulnerability(Vulnerability(
                        title=f"Weak TLS Version ({name})",
                        description=f"Server supports deprecated {name}.",
                        severity=Severity.HIGH, cvss_score=7.5,
                        owasp_category=self.owasp_category, url=f"https://{hostname}:{port}",
                        evidence=f"{name} connection succeeded",
                        remediation=f"Disable {name}. Only allow TLS 1.2+.",
                        cwe_id="CWE-326",
                    ))
                except ssl.SSLError:
                    pass
                finally:
                    sock.close()
            except (socket.error, OSError, ssl.SSLError):
                pass

    async def _check_cert(self, hostname: str, port: int) -> None:
        import asyncio, time
        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()
            sock = await loop.run_in_executor(None, lambda: socket.create_connection((hostname, port), timeout=5))
            try:
                ss = await loop.run_in_executor(None, lambda: ctx.wrap_socket(sock, server_hostname=hostname))
                cert = ss.getpeercert()
                ss.close()
                if cert:
                    exp = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
                    days = (exp - time.time()) / 86400
                    if days < 0:
                        self.add_vulnerability(Vulnerability(
                            title="Expired TLS Certificate",
                            description="The TLS certificate has expired.",
                            severity=Severity.CRITICAL, cvss_score=9.1,
                            owasp_category=self.owasp_category,
                            url=f"https://{hostname}", evidence=f"Expired {abs(int(days))} days ago",
                            remediation="Renew the TLS certificate immediately.", cwe_id="CWE-295",
                        ))
                    elif days < 30:
                        self.add_vulnerability(Vulnerability(
                            title="TLS Certificate Expiring Soon",
                            description=f"Certificate expires in {int(days)} days.",
                            severity=Severity.LOW, cvss_score=2.0,
                            owasp_category=self.owasp_category,
                            url=f"https://{hostname}", evidence=f"Expires in {int(days)} days",
                            remediation="Renew the certificate.", cwe_id="CWE-295",
                        ))
            except ssl.SSLCertVerificationError as e:
                self.add_vulnerability(Vulnerability(
                    title="Invalid TLS Certificate",
                    description=f"Certificate validation failed: {e}",
                    severity=Severity.HIGH, cvss_score=7.4,
                    owasp_category=self.owasp_category, url=f"https://{hostname}",
                    evidence=str(e), remediation="Use a trusted CA-signed certificate.", cwe_id="CWE-295",
                ))
            finally:
                sock.close()
        except (socket.error, OSError):
            self.add_error(f"Cannot connect to {hostname}:{port}")

    async def _check_cookies(self, url: str) -> None:
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as c:
                resp = await c.get(url)
            for hdr in resp.headers.get_list("set-cookie"):
                h = hdr.lower()
                name = hdr.split("=")[0].strip()
                issues = []
                if "secure" not in h:
                    issues.append("Missing Secure flag")
                if "httponly" not in h:
                    issues.append("Missing HttpOnly flag")
                if "samesite" not in h:
                    issues.append("Missing SameSite attribute")
                if issues:
                    self.add_vulnerability(Vulnerability(
                        title=f"Insecure Cookie ({name})",
                        description=f"Cookie '{name}': {'; '.join(issues)}",
                        severity=Severity.MEDIUM, cvss_score=4.7,
                        owasp_category=self.owasp_category, url=url,
                        evidence=f"Set-Cookie: {hdr[:200]}",
                        remediation="Set Secure, HttpOnly, SameSite=Strict on all cookies.",
                        cwe_id="CWE-614",
                    ))
        except httpx.RequestError:
            pass
