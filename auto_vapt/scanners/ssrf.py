"""A10:2021 — Server-Side Request Forgery (SSRF) Scanner."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import httpx

from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, Severity, Vulnerability
from auto_vapt.scanners.base import BaseScanner, register_scanner

log = get_logger(__name__)

# SSRF test payloads — these target internal/metadata services
SSRF_PAYLOADS = [
    ("http://127.0.0.1/", "localhost"),
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
    ("http://[::1]/", "IPv6 localhost"),
    ("http://0.0.0.0/", "zero IP"),
    ("http://localhost:22/", "internal SSH"),
    ("http://localhost:3306/", "internal MySQL"),
]

# Parameters commonly vulnerable to SSRF
SSRF_PARAM_NAMES = [
    "url", "uri", "link", "src", "source", "href", "redirect",
    "next", "return", "callback", "fetch", "proxy", "page",
    "load", "target", "dest", "destination", "domain", "host",
    "site", "feed", "img", "image", "path", "file",
]

SSRF_INDICATORS = [
    "root:", "uid=", "instance-id", "ami-id", "hostname",
    "availability-zone", "local-ipv4", "public-ipv4",
    "computeMetadata", "microsoft", "project-id",
]


@register_scanner
class SSRFScanner(BaseScanner):
    """Scans for Server-Side Request Forgery vulnerabilities (OWASP A10:2021).

    Checks for:
    - URL parameters that fetch remote resources
    - Redirect/callback parameters pointing to internal IPs
    - Cloud metadata endpoint access
    """

    scanner_id = "ssrf"
    scanner_name = "SSRF Scanner (A10)"
    owasp_category = OWASPCategory.A10_SSRF

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        http_client: httpx.AsyncClient = kwargs.get("http_client") or httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(10.0), follow_redirects=False
        )
        target_info = kwargs.get("target_info")

        try:
            # Test URL parameters for SSRF
            await self._test_url_params(http_client, target_url)

            # Test crawled URLs
            if target_info and target_info.crawled_urls:
                for crawled_url in target_info.crawled_urls[:20]:
                    await self._test_url_params(http_client, crawled_url)

            # Test forms with URL-like inputs
            if target_info and target_info.discovered_forms:
                for form in target_info.discovered_forms:
                    await self._test_form_ssrf(http_client, target_url, form)

            # Check for open redirect (related to SSRF)
            await self._check_open_redirect(http_client, target_url, target_info)

        finally:
            if "http_client" not in kwargs:
                await http_client.aclose()

    async def _test_url_params(self, client: httpx.AsyncClient, url: str) -> None:
        """Test URL query parameters for SSRF."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params:
            if param_name.lower() not in SSRF_PARAM_NAMES:
                continue

            for payload, label in SSRF_PAYLOADS[:4]:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload

                try:
                    resp = await client.get(base, params=test_params)

                    # Check for SSRF indicators in response
                    for indicator in SSRF_INDICATORS:
                        if indicator in resp.text:
                            self.add_vulnerability(Vulnerability(
                                title=f"SSRF — {label} ({param_name})",
                                description=(
                                    f"The parameter '{param_name}' at {url} is vulnerable "
                                    f"to Server-Side Request Forgery. The server fetched "
                                    f"the internal resource: {payload}"
                                ),
                                severity=Severity.CRITICAL,
                                cvss_score=9.1,
                                owasp_category=OWASPCategory.A10_SSRF,
                                url=url,
                                parameter=param_name,
                                evidence=f"Payload: {payload} | Indicator: {indicator}",
                                remediation=(
                                    "Validate and sanitize all URLs before fetching. "
                                    "Use allowlists for permitted domains. Block requests "
                                    "to internal IP ranges (127.0.0.0/8, 169.254.0.0/16, "
                                    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). "
                                    "Disable cloud metadata endpoint access from applications."
                                ),
                                cwe_id="CWE-918",
                            ))
                            return

                    # Check if the response differs significantly (blind SSRF)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        # Get baseline
                        baseline_params = {k: v[0] for k, v in params.items()}
                        baseline_params[param_name] = "http://invalid.invalid/"
                        try:
                            baseline = await client.get(base, params=baseline_params)
                            if abs(len(resp.text) - len(baseline.text)) > 500:
                                self.add_vulnerability(Vulnerability(
                                    title=f"Potential Blind SSRF ({param_name})",
                                    description=(
                                        f"The parameter '{param_name}' shows different "
                                        f"response sizes when given internal vs. invalid URLs, "
                                        f"suggesting the server fetches the provided URL."
                                    ),
                                    severity=Severity.HIGH,
                                    cvss_score=7.5,
                                    owasp_category=OWASPCategory.A10_SSRF,
                                    url=url,
                                    parameter=param_name,
                                    evidence=(
                                        f"Internal URL response: {len(resp.text)} bytes, "
                                        f"Invalid URL response: {len(baseline.text)} bytes"
                                    ),
                                    remediation=(
                                        "Validate URLs server-side. Use an allowlist approach "
                                        "for permitted fetch destinations."
                                    ),
                                    cwe_id="CWE-918",
                                ))
                                return
                        except httpx.RequestError:
                            pass

                except httpx.RequestError:
                    pass

    async def _test_form_ssrf(
        self, client: httpx.AsyncClient, base_url: str, form: dict
    ) -> None:
        """Test form inputs named like URL parameters for SSRF."""
        action = urljoin(base_url, form.get("action", ""))
        for inp in form.get("inputs", []):
            name = inp.get("name", "").lower()
            if name not in SSRF_PARAM_NAMES:
                continue

            for payload, label in SSRF_PAYLOADS[:3]:
                data = {i["name"]: i.get("value", "test") for i in form["inputs"]}
                data[inp["name"]] = payload

                try:
                    method = form.get("method", "GET").upper()
                    if method == "POST":
                        resp = await client.post(action, data=data)
                    else:
                        resp = await client.get(action, params=data)

                    for indicator in SSRF_INDICATORS:
                        if indicator in resp.text:
                            self.add_vulnerability(Vulnerability(
                                title=f"SSRF via Form — {label} ({inp['name']})",
                                description=(
                                    f"The form input '{inp['name']}' at {action} is "
                                    f"vulnerable to SSRF. Internal resource access detected."
                                ),
                                severity=Severity.CRITICAL,
                                cvss_score=9.1,
                                owasp_category=OWASPCategory.A10_SSRF,
                                url=action,
                                parameter=inp["name"],
                                evidence=f"Payload: {payload} | Indicator: {indicator}",
                                remediation=(
                                    "Never allow user-supplied URLs to be fetched without "
                                    "strict validation. Use URL allowlists and block "
                                    "internal IP ranges."
                                ),
                                cwe_id="CWE-918",
                            ))
                            return
                except httpx.RequestError:
                    pass

    async def _check_open_redirect(
        self, client: httpx.AsyncClient, base_url: str, target_info: Any
    ) -> None:
        """Check for open redirect vulnerabilities (often chained with SSRF)."""
        redirect_params = ["redirect", "next", "url", "return", "returnTo", "goto", "continue"]
        evil_url = "https://evil.example.com/"

        urls_to_test = [base_url]
        if target_info and target_info.crawled_urls:
            urls_to_test.extend(target_info.crawled_urls[:10])

        for url in urls_to_test:
            parsed = urlparse(url)
            for param in redirect_params:
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={evil_url}"
                try:
                    resp = await client.get(test_url, follow_redirects=False)
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        if "evil.example.com" in location:
                            self.add_vulnerability(Vulnerability(
                                title=f"Open Redirect ({param})",
                                description=(
                                    f"The parameter '{param}' at {url} allows redirecting "
                                    f"to an arbitrary external domain. This can be used for "
                                    f"phishing or chained with SSRF."
                                ),
                                severity=Severity.MEDIUM,
                                cvss_score=5.4,
                                owasp_category=OWASPCategory.A10_SSRF,
                                url=url,
                                parameter=param,
                                evidence=f"Redirected to: {location}",
                                remediation=(
                                    "Validate redirect targets against an allowlist of "
                                    "permitted domains. Use relative URLs for internal "
                                    "redirects. Never blindly redirect to user-supplied URLs."
                                ),
                                cwe_id="CWE-601",
                            ))
                            return
                except httpx.RequestError:
                    pass
