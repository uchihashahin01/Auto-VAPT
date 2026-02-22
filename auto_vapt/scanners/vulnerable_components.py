"""A06:2021 — Vulnerable and Outdated Components Scanner (SCA)."""

from __future__ import annotations

import re
from typing import Any

import httpx
from bs4 import BeautifulSoup

from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, Severity, Vulnerability
from auto_vapt.scanners.base import BaseScanner, register_scanner

log = get_logger(__name__)

# Known vulnerable library patterns (version regex + CVE info)
KNOWN_VULNS: list[dict[str, Any]] = [
    {"lib": "jQuery", "pattern": r"jquery[/-](\d+\.\d+\.\d+)", "below": "3.5.0",
     "cve": "CVE-2020-11022", "desc": "XSS via HTML injection in jQuery < 3.5.0",
     "severity": Severity.MEDIUM, "cvss": 6.1},
    {"lib": "jQuery", "pattern": r"jquery[/-](\d+\.\d+\.\d+)", "below": "3.0.0",
     "cve": "CVE-2015-9251", "desc": "XSS in jQuery < 3.0.0 via cross-domain ajax",
     "severity": Severity.MEDIUM, "cvss": 6.1},
    {"lib": "Bootstrap", "pattern": r"bootstrap[/-](\d+\.\d+\.\d+)", "below": "3.4.1",
     "cve": "CVE-2019-8331", "desc": "XSS in Bootstrap < 3.4.1 tooltip/popover",
     "severity": Severity.MEDIUM, "cvss": 6.1},
    {"lib": "Angular", "pattern": r"angular[/-](\d+\.\d+\.\d+)", "below": "1.6.9",
     "cve": "CVE-2019-10768", "desc": "Prototype pollution in Angular < 1.6.9",
     "severity": Severity.HIGH, "cvss": 7.5},
    {"lib": "Lodash", "pattern": r"lodash[/-](\d+\.\d+\.\d+)", "below": "4.17.21",
     "cve": "CVE-2021-23337", "desc": "Command injection in Lodash < 4.17.21",
     "severity": Severity.HIGH, "cvss": 7.2},
    {"lib": "Moment.js", "pattern": r"moment[/-](\d+\.\d+\.\d+)", "below": "2.29.4",
     "cve": "CVE-2022-31129", "desc": "ReDoS in Moment.js < 2.29.4",
     "severity": Severity.HIGH, "cvss": 7.5},
    {"lib": "Vue.js", "pattern": r"vue[/-](\d+\.\d+\.\d+)", "below": "2.5.0",
     "cve": "N/A", "desc": "XSS via template injection in old Vue.js",
     "severity": Severity.MEDIUM, "cvss": 6.1},
]


def _version_lt(version: str, threshold: str) -> bool:
    """Compare semver strings. Returns True if version < threshold."""
    try:
        v_parts = [int(x) for x in version.split(".")[:3]]
        t_parts = [int(x) for x in threshold.split(".")[:3]]
        while len(v_parts) < 3:
            v_parts.append(0)
        while len(t_parts) < 3:
            t_parts.append(0)
        return v_parts < t_parts
    except (ValueError, IndexError):
        return False


@register_scanner
class VulnerableComponentsScanner(BaseScanner):
    """Scans for vulnerable and outdated JavaScript libraries and server software."""

    scanner_id = "vulnerable_components"
    scanner_name = "Vulnerable Components Scanner (A06)"
    owasp_category = OWASPCategory.A06_VULNERABLE_COMPONENTS

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        http_client = kwargs.get("http_client") or httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(15.0), follow_redirects=True,
        )
        try:
            await self._check_js_libraries(http_client, target_url)
            await self._check_server_version(http_client, target_url)
            await self._check_generator_meta(http_client, target_url)
        finally:
            if "http_client" not in kwargs:
                await http_client.aclose()

    async def _check_js_libraries(self, client: httpx.AsyncClient, url: str) -> None:
        """Detect JS library versions from HTML source and linked scripts."""
        try:
            resp = await client.get(url)
            content = resp.text

            # Also fetch linked JS files
            soup = BeautifulSoup(content, "lxml")
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    from urllib.parse import urljoin
                    src = urljoin(url, src)
                elif not src.startswith("http"):
                    from urllib.parse import urljoin
                    src = urljoin(url, src)
                try:
                    js_resp = await client.get(src)
                    content += "\n" + js_resp.text[:5000]  # First 5KB
                except httpx.RequestError:
                    # Try version from filename
                    content += f"\n{src}"

            # Check against known vulnerable patterns
            for vuln in KNOWN_VULNS:
                matches = re.findall(vuln["pattern"], content, re.IGNORECASE)
                for version in matches:
                    if _version_lt(version, vuln["below"]):
                        self.add_vulnerability(Vulnerability(
                            title=f"Vulnerable {vuln['lib']} ({version})",
                            description=f"{vuln['desc']}. Detected version: {version}.",
                            severity=vuln["severity"], cvss_score=vuln["cvss"],
                            owasp_category=self.owasp_category, url=url,
                            evidence=f"{vuln['lib']} v{version} < {vuln['below']}",
                            remediation=f"Update {vuln['lib']} to the latest version.",
                            cve_ids=[vuln["cve"]] if vuln["cve"] != "N/A" else [],
                            cwe_id="CWE-1104",
                        ))
                        break
        except httpx.RequestError as e:
            self.add_error(f"JS library check failed: {e}")

    async def _check_server_version(self, client: httpx.AsyncClient, url: str) -> None:
        """Check server software version for known vulnerabilities."""
        try:
            resp = await client.get(url)
            server = resp.headers.get("server", "")
            if not server:
                return

            # Check for specific old versions
            apache_match = re.search(r"Apache/(\d+\.\d+\.\d+)", server)
            nginx_match = re.search(r"nginx/(\d+\.\d+\.\d+)", server)
            iis_match = re.search(r"Microsoft-IIS/(\d+\.\d+)", server)

            if apache_match:
                ver = apache_match.group(1)
                if _version_lt(ver, "2.4.52"):
                    self.add_vulnerability(Vulnerability(
                        title=f"Outdated Apache ({ver})",
                        description=f"Apache {ver} may have known vulnerabilities.",
                        severity=Severity.MEDIUM, cvss_score=5.3,
                        owasp_category=self.owasp_category, url=url,
                        evidence=f"Server: {server}",
                        remediation="Update Apache to the latest stable version.",
                        cwe_id="CWE-1104",
                    ))
            elif nginx_match:
                ver = nginx_match.group(1)
                if _version_lt(ver, "1.24.0"):
                    self.add_vulnerability(Vulnerability(
                        title=f"Outdated nginx ({ver})",
                        description=f"nginx {ver} may have known vulnerabilities.",
                        severity=Severity.MEDIUM, cvss_score=5.3,
                        owasp_category=self.owasp_category, url=url,
                        evidence=f"Server: {server}",
                        remediation="Update nginx to the latest stable version.",
                        cwe_id="CWE-1104",
                    ))
        except httpx.RequestError:
            pass

    async def _check_generator_meta(self, client: httpx.AsyncClient, url: str) -> None:
        """Check meta generator tag for CMS version."""
        try:
            resp = await client.get(url)
            soup = BeautifulSoup(resp.text, "lxml")
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen and gen.get("content"):
                content = gen["content"]
                # WordPress version check
                wp_match = re.search(r"WordPress\s+(\d+\.\d+\.?\d*)", content)
                if wp_match:
                    ver = wp_match.group(1)
                    self.add_vulnerability(Vulnerability(
                        title=f"WordPress Version Disclosure ({ver})",
                        description=f"WordPress {ver} version exposed via meta generator tag.",
                        severity=Severity.LOW, cvss_score=3.1,
                        owasp_category=self.owasp_category, url=url,
                        evidence=f"<meta name='generator' content='{content}'>",
                        remediation="Remove the generator meta tag. Keep WordPress updated.",
                        cwe_id="CWE-200",
                    ))
        except httpx.RequestError:
            pass
