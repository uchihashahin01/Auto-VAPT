"""A04:2021 — Insecure Design Scanner."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, Severity, Vulnerability
from auto_vapt.scanners.base import BaseScanner, register_scanner

log = get_logger(__name__)

# Common patterns indicating insecure design
RATE_LIMIT_PATHS = ["/api/login", "/login", "/api/auth", "/api/register", "/register"]
BUSINESS_LOGIC_PARAMS = ["price", "amount", "quantity", "discount", "total", "balance"]


@register_scanner
class InsecureDesignScanner(BaseScanner):
    """Scans for insecure design patterns (OWASP A04:2021).

    Checks for:
    - Missing rate limiting on sensitive endpoints
    - Business logic flaws (negative values, parameter tampering)
    - Missing CAPTCHA on auth endpoints
    - Unrestricted resource consumption
    """

    scanner_id = "insecure_design"
    scanner_name = "Insecure Design Scanner (A04)"
    owasp_category = OWASPCategory.A04_INSECURE_DESIGN

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        http_client: httpx.AsyncClient = kwargs.get("http_client") or httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(15.0), follow_redirects=True
        )
        target_info = kwargs.get("target_info")

        try:
            await self._check_rate_limiting(http_client, target_url)
            await self._check_business_logic(http_client, target_url, target_info)
            await self._check_captcha(http_client, target_url)
            await self._check_error_handling(http_client, target_url)
        finally:
            if "http_client" not in kwargs:
                await http_client.aclose()

    async def _check_rate_limiting(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Check if sensitive endpoints have rate limiting."""
        for path in RATE_LIMIT_PATHS:
            url = urljoin(base_url, path)
            try:
                responses = []
                for _ in range(10):
                    resp = await client.post(
                        url, data={"username": "test", "password": "test"}, follow_redirects=False
                    )
                    responses.append(resp.status_code)

                # If none returned 429 (Too Many Requests), no rate limiting
                if 429 not in responses and all(r != 404 for r in responses[:1]):
                    # Only report if the endpoint exists
                    if responses[0] != 404:
                        self.add_vulnerability(Vulnerability(
                            title=f"Missing Rate Limiting ({path})",
                            description=(
                                f"The endpoint {url} does not implement rate limiting. "
                                f"10 rapid requests all succeeded without throttling. "
                                f"This allows brute-force and credential stuffing attacks."
                            ),
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                            url=url,
                            evidence=f"10 requests — status codes: {responses[:5]}",
                            remediation=(
                                "Implement rate limiting (e.g., 5 attempts per minute) on "
                                "authentication endpoints. Use exponential backoff and account "
                                "lockout after repeated failures."
                            ),
                            cwe_id="CWE-770",
                        ))
                        return  # Report once
            except httpx.RequestError:
                pass

    async def _check_business_logic(
        self, client: httpx.AsyncClient, base_url: str, target_info: Any
    ) -> None:
        """Check for business logic flaws via parameter tampering."""
        forms = []
        if target_info and hasattr(target_info, "discovered_forms"):
            forms = target_info.discovered_forms or []

        for form in forms:
            for inp in form.get("inputs", []):
                if inp.get("name", "").lower() in BUSINESS_LOGIC_PARAMS:
                    action = urljoin(base_url, form.get("action", ""))
                    # Try negative value
                    data = {i["name"]: i.get("value", "1") for i in form["inputs"]}
                    data[inp["name"]] = "-1"
                    try:
                        resp = await client.post(action, data=data)
                        if resp.status_code == 200 and "error" not in resp.text.lower():
                            self.add_vulnerability(Vulnerability(
                                title=f"Business Logic Flaw — Negative Value ({inp['name']})",
                                description=(
                                    f"The parameter '{inp['name']}' at {action} accepts "
                                    f"negative values without server-side validation."
                                ),
                                severity=Severity.HIGH,
                                cvss_score=7.5,
                                owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                                url=action,
                                parameter=inp["name"],
                                evidence=f"Submitted {inp['name']}=-1, got HTTP 200",
                                remediation=(
                                    "Implement server-side validation for all business-critical "
                                    "parameters. Never trust client-side input for pricing, "
                                    "quantities, or financial calculations."
                                ),
                                cwe_id="CWE-20",
                            ))
                    except httpx.RequestError:
                        pass

    async def _check_captcha(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Check for CAPTCHA on auth endpoints."""
        for path in ["/login", "/register", "/signup"]:
            url = urljoin(base_url, path)
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    has_form = "<form" in body
                    has_captcha = any(
                        c in body for c in ["captcha", "recaptcha", "hcaptcha", "turnstile"]
                    )
                    if has_form and not has_captcha:
                        self.add_vulnerability(Vulnerability(
                            title=f"Missing CAPTCHA ({path})",
                            description=(
                                f"The form at {url} does not implement CAPTCHA verification, "
                                f"making it vulnerable to automated attacks."
                            ),
                            severity=Severity.LOW,
                            cvss_score=3.7,
                            owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                            url=url,
                            remediation=(
                                "Add CAPTCHA (reCAPTCHA, hCaptcha, or Cloudflare Turnstile) "
                                "to authentication and registration forms."
                            ),
                            cwe_id="CWE-804",
                        ))
                        return
            except httpx.RequestError:
                pass

    async def _check_error_handling(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Check if application exposes detailed error information."""
        error_triggers = [
            "/nonexistent-page-12345",
            "/?id=1'",
            "/api/v1/undefined",
        ]
        for path in error_triggers:
            url = urljoin(base_url, path)
            try:
                resp = await client.get(url)
                body = resp.text.lower()
                stack_indicators = [
                    "traceback", "stack trace", "exception", "at line",
                    "file \"", "debug", "internal server error",
                ]
                for indicator in stack_indicators:
                    if indicator in body and resp.status_code >= 400:
                        self.add_vulnerability(Vulnerability(
                            title="Verbose Error Messages",
                            description=(
                                f"The application at {url} exposes detailed error information "
                                f"including stack traces or debug output."
                            ),
                            severity=Severity.LOW,
                            cvss_score=3.1,
                            owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                            url=url,
                            evidence=f"Indicator: '{indicator}' found in error response",
                            remediation=(
                                "Configure custom error pages. Never expose stack traces, "
                                "debug information, or internal paths in production."
                            ),
                            cwe_id="CWE-209",
                        ))
                        return
            except httpx.RequestError:
                pass
