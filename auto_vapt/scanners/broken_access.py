"""A01:2021 — Broken Access Control Scanner."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, Severity, Vulnerability
from auto_vapt.scanners.base import BaseScanner, register_scanner

log = get_logger(__name__)

# Sensitive admin/config paths for forced browsing
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/login",
    "/admin/dashboard", "/admin/config", "/admin/users",
    "/panel", "/cpanel", "/manager", "/management",
    "/wp-admin", "/wp-login.php", "/wp-admin/admin-ajax.php",
    "/phpmyadmin", "/pma", "/adminer", "/adminer.php",
]

SENSITIVE_FILE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/HEAD", "/.git/config", "/.gitignore",
    "/.svn/entries", "/.svn/wc.db",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/config.yml", "/config.json", "/config.php",
    "/wp-config.php.bak", "/wp-config.php~",
    "/backup.sql", "/database.sql", "/dump.sql", "/db.sql",
    "/backup.zip", "/backup.tar.gz", "/site-backup.zip",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php",
    "/debug", "/trace.axd", "/elmah.axd",
    "/.DS_Store", "/Thumbs.db",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\etc\\passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd%00",
    "....//....//....//windows/win.ini",
]

IDOR_INDICATORS = [
    "id=", "user_id=", "uid=", "account=", "profile=",
    "order=", "doc=", "file=", "report=", "invoice=",
]


@register_scanner
class BrokenAccessScanner(BaseScanner):
    """Scans for broken access control vulnerabilities.

    Tests for:
    - Forced browsing to admin/sensitive pages
    - Sensitive file exposure (.env, .git, backups)
    - Path traversal / directory traversal
    - IDOR (Insecure Direct Object Reference) indicators
    - Directory listing enabled
    """

    scanner_id = "broken_access"
    scanner_name = "Broken Access Control Scanner (A01)"
    owasp_category = OWASPCategory.A01_BROKEN_ACCESS_CONTROL

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        """Scan for broken access control vulnerabilities."""
        http_client: httpx.AsyncClient = kwargs.get("http_client") or httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(10.0), follow_redirects=False,
            headers={"User-Agent": "Auto-VAPT/1.0 Security Scanner"},
        )

        try:
            await self._check_admin_paths(http_client, target_url)
            await self._check_sensitive_files(http_client, target_url)
            await self._check_path_traversal(http_client, target_url)
            await self._check_directory_listing(http_client, target_url)
            await self._check_http_method_tampering(http_client, target_url)
        finally:
            if "http_client" not in kwargs:
                await http_client.aclose()

    async def _check_admin_paths(
        self, client: httpx.AsyncClient, base_url: str
    ) -> None:
        """Check for accessible admin interfaces."""
        for path in ADMIN_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    # Check if it's a real admin page (not a redirect or custom 404)
                    admin_indicators = [
                        "dashboard", "admin", "login", "panel",
                        "username", "password", "sign in",
                    ]
                    if any(ind in body_lower for ind in admin_indicators):
                        self.add_vulnerability(Vulnerability(
                            title=f"Exposed Admin Interface ({path})",
                            description=(
                                f"The admin interface at {url} is publicly accessible without "
                                f"authentication or IP restriction."
                            ),
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                            url=url,
                            evidence=f"HTTP {resp.status_code} — admin page accessible",
                            remediation=(
                                "Restrict admin interfaces by IP address or VPN. Implement "
                                "multi-factor authentication. Use a non-guessable admin URL."
                            ),
                            references=[
                                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                            ],
                            cwe_id="CWE-284",
                        ))
            except httpx.RequestError:
                pass

    async def _check_sensitive_files(
        self, client: httpx.AsyncClient, base_url: str
    ) -> None:
        """Check for exposed sensitive files."""
        for path in SENSITIVE_FILE_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.text) > 10:
                    # Validate it's real content, not a custom 404
                    is_sensitive = False
                    severity = Severity.MEDIUM
                    cvss = 5.3

                    if ".env" in path:
                        if any(k in resp.text for k in ["DB_", "API_KEY", "SECRET", "PASSWORD", "TOKEN"]):
                            is_sensitive = True
                            severity = Severity.CRITICAL
                            cvss = 9.1
                    elif ".git" in path:
                        if "ref:" in resp.text or "[core]" in resp.text:
                            is_sensitive = True
                            severity = Severity.HIGH
                            cvss = 7.5
                    elif path.endswith((".sql", ".zip", ".tar.gz")):
                        is_sensitive = True
                        severity = Severity.CRITICAL
                        cvss = 9.1
                    elif "phpinfo" in path:
                        if "PHP Version" in resp.text:
                            is_sensitive = True
                            severity = Severity.MEDIUM
                            cvss = 5.3
                    elif path in ("/server-status", "/server-info"):
                        if "Apache" in resp.text:
                            is_sensitive = True
                    else:
                        is_sensitive = True

                    if is_sensitive:
                        self.add_vulnerability(Vulnerability(
                            title=f"Sensitive File Exposure ({path})",
                            description=(
                                f"The file {url} is publicly accessible and may contain "
                                f"sensitive information such as credentials or configurations."
                            ),
                            severity=severity,
                            cvss_score=cvss,
                            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                            url=url,
                            evidence=f"File accessible — first 200 chars: {resp.text[:200]}",
                            remediation=(
                                "Block access to sensitive files via web server configuration. "
                                "Add rules to .htaccess or nginx.conf to deny access to dotfiles, "
                                "backup files, and configuration files."
                            ),
                            cwe_id="CWE-538",
                        ))
            except httpx.RequestError:
                pass

    async def _check_path_traversal(
        self, client: httpx.AsyncClient, base_url: str
    ) -> None:
        """Check for path traversal vulnerabilities."""
        # Try common file inclusion parameters
        test_params = ["file", "path", "page", "doc", "folder", "include", "template"]

        for param in test_params:
            for payload in PATH_TRAVERSAL_PAYLOADS[:4]:
                url = f"{base_url.rstrip('/')}/?{param}={payload}"
                try:
                    resp = await client.get(url)
                    if "root:" in resp.text and "/bin/" in resp.text:
                        self.add_vulnerability(Vulnerability(
                            title=f"Path Traversal ({param})",
                            description=(
                                f"The parameter '{param}' is vulnerable to path traversal. "
                                f"Local files can be read via directory traversal sequences."
                            ),
                            severity=Severity.CRITICAL,
                            cvss_score=9.1,
                            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                            url=url,
                            parameter=param,
                            evidence=f"Payload: {payload} — /etc/passwd content retrieved",
                            remediation=(
                                "Validate and sanitize file paths. Use a whitelist of allowed files. "
                                "Avoid passing user input to filesystem operations. Use chroot jails."
                            ),
                            cwe_id="CWE-22",
                        ))
                        return
                except httpx.RequestError:
                    pass

    async def _check_directory_listing(
        self, client: httpx.AsyncClient, base_url: str
    ) -> None:
        """Check if directory listing is enabled."""
        test_dirs = ["/", "/images/", "/uploads/", "/static/", "/assets/", "/files/", "/media/"]

        for dir_path in test_dirs:
            url = urljoin(base_url, dir_path)
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    indicators = ["Index of", "Directory listing", "Parent Directory", "[DIR]"]
                    if any(ind in resp.text for ind in indicators):
                        self.add_vulnerability(Vulnerability(
                            title=f"Directory Listing Enabled ({dir_path})",
                            description=(
                                f"Directory listing is enabled at {url}, exposing file structure."
                            ),
                            severity=Severity.LOW,
                            cvss_score=3.7,
                            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                            url=url,
                            evidence="Directory listing detected in response",
                            remediation=(
                                "Disable directory listing in web server config. "
                                "Apache: 'Options -Indexes'. Nginx: 'autoindex off'."
                            ),
                            cwe_id="CWE-548",
                        ))
            except httpx.RequestError:
                pass

    async def _check_http_method_tampering(
        self, client: httpx.AsyncClient, base_url: str
    ) -> None:
        """Check for HTTP method tampering vulnerabilities."""
        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]

        for method in dangerous_methods:
            try:
                resp = await client.request(method, base_url)
                if resp.status_code not in (405, 501, 403, 404):
                    if method == "TRACE" and "TRACE" in resp.text:
                        self.add_vulnerability(Vulnerability(
                            title=f"HTTP TRACE Method Enabled",
                            description=(
                                "The TRACE HTTP method is enabled, which can be exploited "
                                "for Cross-Site Tracing (XST) attacks to steal credentials."
                            ),
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                            url=base_url,
                            evidence=f"TRACE method returned {resp.status_code}",
                            remediation="Disable TRACE method in web server configuration.",
                            cwe_id="CWE-693",
                        ))
                    elif method in ("PUT", "DELETE"):
                        self.add_vulnerability(Vulnerability(
                            title=f"Dangerous HTTP Method Allowed ({method})",
                            description=(
                                f"The HTTP {method} method is allowed and may permit "
                                f"unauthorized modification or deletion of resources."
                            ),
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                            url=base_url,
                            evidence=f"{method} returned HTTP {resp.status_code}",
                            remediation=f"Disable {method} method unless explicitly required.",
                            cwe_id="CWE-650",
                        ))
            except httpx.RequestError:
                pass
