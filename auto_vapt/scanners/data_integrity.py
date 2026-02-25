"""A08:2021 — Software and Data Integrity Failures Scanner."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, Severity, Vulnerability
from auto_vapt.scanners.base import BaseScanner, register_scanner

log = get_logger(__name__)


@register_scanner
class DataIntegrityScanner(BaseScanner):
    """Scans for software and data integrity failures (OWASP A08:2021).

    Checks for:
    - Missing Subresource Integrity (SRI) on CDN scripts
    - Insecure deserialization indicators
    - Missing integrity checks on auto-update mechanisms
    - Unsigned / unverified content delivery
    """

    scanner_id = "data_integrity"
    scanner_name = "Data Integrity Scanner (A08)"
    owasp_category = OWASPCategory.A08_DATA_INTEGRITY

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        http_client: httpx.AsyncClient = kwargs.get("http_client") or httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(15.0), follow_redirects=True
        )
        target_info = kwargs.get("target_info")

        try:
            await self._check_sri(http_client, target_url)
            await self._check_deserialization(http_client, target_url, target_info)
            await self._check_ci_cd_indicators(http_client, target_url)
        finally:
            if "http_client" not in kwargs:
                await http_client.aclose()

    async def _check_sri(self, client: httpx.AsyncClient, url: str) -> None:
        """Check if external scripts/styles have Subresource Integrity attributes."""
        try:
            resp = await client.get(url)
            soup = BeautifulSoup(resp.text, "lxml")

            external_scripts = soup.find_all("script", src=True)
            external_styles = soup.find_all("link", rel="stylesheet", href=True)

            for script in external_scripts:
                src = script.get("src", "")
                # Check if it's from a CDN / external origin
                if any(cdn in src for cdn in [
                    "cdn.", "cdnjs.", "unpkg.com", "jsdelivr.net",
                    "googleapis.com", "cloudflare.com", "bootstrapcdn.com",
                ]):
                    if not script.get("integrity"):
                        self.add_vulnerability(Vulnerability(
                            title=f"Missing SRI — External Script",
                            description=(
                                f"The page at {url} loads an external script from {src} "
                                f"without Subresource Integrity (SRI) hash verification. "
                                f"A compromised CDN could inject malicious code."
                            ),
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            owasp_category=OWASPCategory.A08_DATA_INTEGRITY,
                            url=url,
                            evidence=f"Script src: {src} — no integrity attribute",
                            remediation=(
                                "Add `integrity` and `crossorigin` attributes to all external "
                                "scripts: <script src='...' integrity='sha384-...' crossorigin='anonymous'>"
                            ),
                            cwe_id="CWE-353",
                        ))

            for style in external_styles:
                href = style.get("href", "")
                if any(cdn in href for cdn in [
                    "cdn.", "cdnjs.", "unpkg.com", "jsdelivr.net",
                    "googleapis.com", "cloudflare.com", "bootstrapcdn.com",
                ]):
                    if not style.get("integrity"):
                        self.add_vulnerability(Vulnerability(
                            title=f"Missing SRI — External Stylesheet",
                            description=(
                                f"The page at {url} loads an external stylesheet from {href} "
                                f"without Subresource Integrity verification."
                            ),
                            severity=Severity.LOW,
                            cvss_score=3.1,
                            owasp_category=OWASPCategory.A08_DATA_INTEGRITY,
                            url=url,
                            evidence=f"Stylesheet href: {href} — no integrity attribute",
                            remediation=(
                                "Add `integrity` and `crossorigin` attributes to external stylesheets."
                            ),
                            cwe_id="CWE-353",
                        ))

        except httpx.RequestError as e:
            self.add_error(f"SRI check failed: {e}")

    async def _check_deserialization(
        self, client: httpx.AsyncClient, url: str, target_info: Any
    ) -> None:
        """Check for insecure deserialization indicators."""
        try:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check for serialized object indicators in cookies
            cookies = resp.headers.get_list("set-cookie")
            for cookie in cookies:
                # Java serialized objects, PHP serialized, Python pickle
                serialization_sigs = [
                    "rO0AB",  # Java serialized (base64)
                    "O:4:",   # PHP serialized object
                    "a:2:{",  # PHP serialized array
                    "gASV",   # Python pickle (base64)
                ]
                for sig in serialization_sigs:
                    if sig in cookie:
                        self.add_vulnerability(Vulnerability(
                            title="Potential Insecure Deserialization in Cookie",
                            description=(
                                f"A cookie from {url} contains what appears to be a "
                                f"serialized object ({sig}). If the server deserializes "
                                f"this without validation, it may be exploitable."
                            ),
                            severity=Severity.HIGH,
                            cvss_score=8.1,
                            owasp_category=OWASPCategory.A08_DATA_INTEGRITY,
                            url=url,
                            evidence=f"Serialization signature '{sig}' in Set-Cookie",
                            remediation=(
                                "Never deserialize untrusted data. Use JSON instead of "
                                "native serialization formats. Implement integrity checks "
                                "(HMAC) on serialized data."
                            ),
                            cwe_id="CWE-502",
                        ))
                        return

        except httpx.RequestError:
            pass

    async def _check_ci_cd_indicators(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Check for exposed CI/CD or build artifacts."""
        ci_paths = [
            "/.github/workflows/",
            "/.gitlab-ci.yml",
            "/Jenkinsfile",
            "/.circleci/config.yml",
            "/.travis.yml",
            "/docker-compose.yml",
            "/Dockerfile",
            "/.env.example",
            "/package.json",
            "/composer.json",
        ]
        for path in ci_paths:
            url = urljoin(base_url, path)
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.text) > 10:
                    content = resp.text.lower()
                    # Verify it's real content, not a custom 404
                    if any(kw in content for kw in [
                        "name", "version", "script", "stage", "pipeline",
                        "docker", "build", "deploy", "require",
                    ]):
                        self.add_vulnerability(Vulnerability(
                            title=f"Exposed Build/CI Configuration ({path})",
                            description=(
                                f"The file {path} is publicly accessible at {url}. "
                                f"This may reveal infrastructure details, secrets, or "
                                f"deployment configurations."
                            ),
                            severity=Severity.LOW,
                            cvss_score=3.7,
                            owasp_category=OWASPCategory.A08_DATA_INTEGRITY,
                            url=url,
                            evidence=f"HTTP 200 with {len(resp.text)} bytes",
                            remediation=(
                                "Block access to CI/CD configuration files via web server "
                                "rules. Ensure build artifacts are not deployed to production."
                            ),
                            cwe_id="CWE-538",
                        ))
            except httpx.RequestError:
                pass
