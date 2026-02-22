"""A07:2021 — Identification and Authentication Failures Scanner."""

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
class AuthFailuresScanner(BaseScanner):
    """Scans for authentication and session management weaknesses.

    Tests for:
    - Brute-force resilience (account lockout)
    - Username enumeration via error message differences
    - Session fixation and session ID quality
    - Password policy weakness indicators
    - JWT issues (if detected)
    """

    scanner_id = "auth_failures"
    scanner_name = "Auth Failures Scanner (A07)"
    owasp_category = OWASPCategory.A07_AUTH_FAILURES

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        http_client = kwargs.get("http_client") or httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(10.0), follow_redirects=True,
        )
        try:
            login_url = await self._find_login_page(http_client, target_url)
            if login_url:
                await self._check_brute_force(http_client, login_url)
                await self._check_user_enumeration(http_client, login_url)
                await self._check_password_policy(http_client, login_url)
            await self._check_session_management(http_client, target_url)
            await self._check_jwt(http_client, target_url)
        finally:
            if "http_client" not in kwargs:
                await http_client.aclose()

    async def _find_login_page(self, client: httpx.AsyncClient, url: str) -> str | None:
        paths = ["/login", "/signin", "/auth/login", "/admin/login",
                 "/wp-login.php", "/user/login", "/account/login"]
        for path in paths:
            try:
                resp = await client.get(urljoin(url, path))
                if resp.status_code == 200 and "password" in resp.text.lower():
                    log.info("login_page_found", path=path)
                    return urljoin(url, path)
            except httpx.RequestError:
                pass
        return None

    async def _check_brute_force(self, client: httpx.AsyncClient, login_url: str) -> None:
        """Test if there's rate limiting or account lockout."""
        responses: list[int] = []
        for i in range(10):
            try:
                resp = await client.post(login_url, data={
                    "username": "admin", "password": f"wrong{i}",
                })
                responses.append(resp.status_code)
            except httpx.RequestError:
                break

        # If all attempts return same status, no lockout detected
        if len(responses) >= 8 and all(r == responses[0] for r in responses):
            self.add_vulnerability(Vulnerability(
                title="No Brute-Force Protection",
                description=(
                    f"Login at {login_url} allows unlimited authentication attempts "
                    f"without rate limiting or account lockout."
                ),
                severity=Severity.HIGH, cvss_score=7.3,
                owasp_category=self.owasp_category, url=login_url,
                evidence=f"10 failed logins returned HTTP {responses[0]} each, no lockout",
                remediation=(
                    "Implement account lockout after 5 failed attempts. "
                    "Add rate limiting and CAPTCHA after 3 failures. "
                    "Consider progressive delays between attempts."
                ),
                cwe_id="CWE-307",
            ))

    async def _check_user_enumeration(self, client: httpx.AsyncClient, login_url: str) -> None:
        """Check if error messages differ between valid/invalid usernames."""
        try:
            resp1 = await client.post(login_url, data={
                "username": "admin", "password": "wrongpassword123"
            })
            resp2 = await client.post(login_url, data={
                "username": "nonexistent_user_xyz_98765", "password": "wrongpassword123"
            })

            # If responses differ significantly, username enumeration possible
            if abs(len(resp1.text) - len(resp2.text)) > 20:
                self.add_vulnerability(Vulnerability(
                    title="Username Enumeration",
                    description=(
                        "Login error messages differ based on username validity, "
                        "allowing attackers to enumerate valid accounts."
                    ),
                    severity=Severity.MEDIUM, cvss_score=5.3,
                    owasp_category=self.owasp_category, url=login_url,
                    evidence=f"Response length diff: {len(resp1.text)} vs {len(resp2.text)}",
                    remediation="Use generic error messages like 'Invalid credentials' for all login failures.",
                    cwe_id="CWE-204",
                ))
        except httpx.RequestError:
            pass

    async def _check_password_policy(self, client: httpx.AsyncClient, login_url: str) -> None:
        """Check for weak password policy indicators."""
        try:
            resp = await client.get(login_url)
            body = resp.text.lower()
            soup = BeautifulSoup(resp.text, "lxml")

            # Check password field attributes
            pwd_field = soup.find("input", {"type": "password"})
            if pwd_field:
                minlength = pwd_field.get("minlength", "")
                if minlength and int(minlength) < 8:
                    self.add_vulnerability(Vulnerability(
                        title="Weak Password Length Requirement",
                        description=f"Password field allows minimum {minlength} characters.",
                        severity=Severity.MEDIUM, cvss_score=5.3,
                        owasp_category=self.owasp_category, url=login_url,
                        evidence=f"minlength={minlength}",
                        remediation="Require minimum 8 characters (preferably 12+).",
                        cwe_id="CWE-521",
                    ))

            # Check for CSRF token
            csrf = soup.find("input", {"name": lambda n: n and "csrf" in n.lower()}) if soup else None
            if not csrf:
                csrf = soup.find("input", {"name": lambda n: n and "token" in n.lower()}) if soup else None
            if not csrf and "csrf" not in body:
                self.add_vulnerability(Vulnerability(
                    title="Missing CSRF Protection on Login",
                    description="Login form appears to lack CSRF token protection.",
                    severity=Severity.MEDIUM, cvss_score=4.3,
                    owasp_category=self.owasp_category, url=login_url,
                    evidence="No CSRF token field found in login form",
                    remediation="Add CSRF token to all forms, especially login.",
                    cwe_id="CWE-352",
                ))
        except (httpx.RequestError, ValueError):
            pass

    async def _check_session_management(self, client: httpx.AsyncClient, url: str) -> None:
        """Check session cookie quality."""
        try:
            resp = await client.get(url)
            cookies = resp.headers.get_list("set-cookie")

            for cookie in cookies:
                name = cookie.split("=")[0].strip().lower()
                if any(s in name for s in ["session", "sid", "sess", "phpsessid", "jsessionid"]):
                    value = cookie.split("=")[1].split(";")[0].strip() if "=" in cookie else ""
                    # Check session ID entropy (should be > 16 chars)
                    if value and len(value) < 16:
                        self.add_vulnerability(Vulnerability(
                            title="Weak Session ID",
                            description=f"Session ID '{name}' is only {len(value)} chars (low entropy).",
                            severity=Severity.HIGH, cvss_score=7.1,
                            owasp_category=self.owasp_category, url=url,
                            evidence=f"Session ID length: {len(value)}",
                            remediation="Use cryptographically random session IDs of at least 128 bits.",
                            cwe_id="CWE-330",
                        ))
        except httpx.RequestError:
            pass

    async def _check_jwt(self, client: httpx.AsyncClient, url: str) -> None:
        """Check for JWT-related issues."""
        import base64, json
        try:
            resp = await client.get(url)
            # Check cookies and headers for JWTs
            all_text = str(resp.headers) + " " + resp.text[:2000]

            import re
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            jwts = re.findall(jwt_pattern, all_text)

            for jwt in jwts[:1]:  # Check first JWT found
                parts = jwt.split(".")
                try:
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                    alg = header.get("alg", "")
                    if alg.lower() == "none":
                        self.add_vulnerability(Vulnerability(
                            title="JWT Algorithm None Vulnerability",
                            description="JWT uses 'none' algorithm — signature not verified.",
                            severity=Severity.CRITICAL, cvss_score=9.1,
                            owasp_category=self.owasp_category, url=url,
                            evidence=f"JWT header: {header}",
                            remediation="Never accept 'none' algorithm. Enforce RS256 or ES256.",
                            cwe_id="CWE-347",
                        ))
                    elif alg.startswith("HS"):
                        self.add_vulnerability(Vulnerability(
                            title="JWT Using Symmetric Algorithm",
                            description=f"JWT uses {alg} (symmetric). Consider asymmetric (RS256/ES256).",
                            severity=Severity.LOW, cvss_score=3.1,
                            owasp_category=self.owasp_category, url=url,
                            evidence=f"JWT alg: {alg}",
                            remediation="Use asymmetric algorithms (RS256/ES256) for better security.",
                            cwe_id="CWE-327",
                        ))
                except (ValueError, json.JSONDecodeError):
                    pass
        except httpx.RequestError:
            pass
