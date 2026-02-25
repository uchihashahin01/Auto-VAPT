"""OWASP ZAP Integration Scanner — leverages ZAP's active scanner via API."""

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from auto_vapt.logger import get_logger
from auto_vapt.models import OWASPCategory, Severity, Vulnerability
from auto_vapt.scanners.base import BaseScanner, register_scanner

log = get_logger(__name__)

ZAP_API_URL = os.environ.get("ZAP_API_URL", "http://localhost:8080")

# Map ZAP risk levels to our severity model
ZAP_RISK_MAP = {
    "Informational": Severity.INFO,
    "Low": Severity.LOW,
    "Medium": Severity.MEDIUM,
    "High": Severity.HIGH,
    "Critical": Severity.CRITICAL,
}

ZAP_RISK_CVSS = {
    "Informational": 0.0,
    "Low": 3.1,
    "Medium": 5.3,
    "High": 7.5,
    "Critical": 9.8,
}

# Map ZAP CWE IDs to OWASP categories (best-effort)
CWE_OWASP_MAP = {
    "89": OWASPCategory.A03_INJECTION,
    "79": OWASPCategory.A03_INJECTION,
    "78": OWASPCategory.A03_INJECTION,
    "90": OWASPCategory.A03_INJECTION,
    "91": OWASPCategory.A03_INJECTION,
    "22": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "284": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "285": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "287": OWASPCategory.A07_AUTH_FAILURES,
    "326": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "327": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "328": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "16": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "525": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "614": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "829": OWASPCategory.A06_VULNERABLE_COMPONENTS,
    "918": OWASPCategory.A10_SSRF,
    "352": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
}


@register_scanner
class ZAPScanner(BaseScanner):
    """Integrates OWASP ZAP active scanner for enterprise-grade vulnerability detection.

    Requires ZAP daemon running (e.g. via docker-compose).
    Set ZAP_API_URL environment variable (default: http://localhost:8080).
    """

    scanner_id = "zap"
    scanner_name = "OWASP ZAP Scanner"
    owasp_category = OWASPCategory.A03_INJECTION  # ZAP covers multiple categories

    async def scan(self, target_url: str, **kwargs: Any) -> None:
        """Run ZAP spider + active scan and collect alerts."""
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
                # Check ZAP is available
                if not await self._check_zap(client):
                    self.add_error("ZAP daemon not available — skipping ZAP scan")
                    log.warning("zap_unavailable", url=ZAP_API_URL)
                    return

                # Step 1: Spider the target
                log.info("zap_spidering", target=target_url)
                spider_id = await self._start_spider(client, target_url)
                if spider_id is not None:
                    await self._wait_for_spider(client, spider_id)

                # Step 2: Active scan
                log.info("zap_active_scan", target=target_url)
                scan_id = await self._start_active_scan(client, target_url)
                if scan_id is not None:
                    await self._wait_for_active_scan(client, scan_id)

                # Step 3: Collect alerts
                alerts = await self._get_alerts(client, target_url)
                log.info("zap_alerts_found", count=len(alerts))

                for alert in alerts:
                    self._process_alert(alert)

        except httpx.RequestError as e:
            self.add_error(f"ZAP connection failed: {e}")
            log.error("zap_connection_failed", error=str(e))

    async def _check_zap(self, client: httpx.AsyncClient) -> bool:
        """Check if ZAP daemon is reachable."""
        try:
            resp = await client.get(f"{ZAP_API_URL}/JSON/core/view/version/")
            return resp.status_code == 200
        except httpx.RequestError:
            return False

    async def _start_spider(self, client: httpx.AsyncClient, target: str) -> str | None:
        """Start ZAP spider on target."""
        try:
            resp = await client.get(
                f"{ZAP_API_URL}/JSON/spider/action/scan/",
                params={"url": target, "maxChildren": "10", "recurse": "true"},
            )
            data = resp.json()
            return data.get("scan")
        except Exception as e:
            self.add_error(f"ZAP spider start failed: {e}")
            return None

    async def _wait_for_spider(self, client: httpx.AsyncClient, spider_id: str) -> None:
        """Wait for ZAP spider to complete."""
        for _ in range(120):  # Max 2 minutes
            try:
                resp = await client.get(
                    f"{ZAP_API_URL}/JSON/spider/view/status/",
                    params={"scanId": spider_id},
                )
                status = resp.json().get("status", "0")
                if int(status) >= 100:
                    return
            except Exception:
                pass
            await asyncio.sleep(1)

    async def _start_active_scan(self, client: httpx.AsyncClient, target: str) -> str | None:
        """Start ZAP active scan."""
        try:
            resp = await client.get(
                f"{ZAP_API_URL}/JSON/ascan/action/scan/",
                params={"url": target, "recurse": "true", "inScopeOnly": "false"},
            )
            data = resp.json()
            return data.get("scan")
        except Exception as e:
            self.add_error(f"ZAP active scan start failed: {e}")
            return None

    async def _wait_for_active_scan(self, client: httpx.AsyncClient, scan_id: str) -> None:
        """Wait for ZAP active scan to complete."""
        for _ in range(600):  # Max 10 minutes
            try:
                resp = await client.get(
                    f"{ZAP_API_URL}/JSON/ascan/view/status/",
                    params={"scanId": scan_id},
                )
                status = resp.json().get("status", "0")
                if int(status) >= 100:
                    return
            except Exception:
                pass
            await asyncio.sleep(2)

    async def _get_alerts(self, client: httpx.AsyncClient, target: str) -> list[dict]:
        """Get all ZAP alerts for the target."""
        try:
            resp = await client.get(
                f"{ZAP_API_URL}/JSON/alert/view/alerts/",
                params={"baseurl": target, "start": "0", "count": "500"},
            )
            return resp.json().get("alerts", [])
        except Exception as e:
            self.add_error(f"Failed to retrieve ZAP alerts: {e}")
            return []

    def _process_alert(self, alert: dict) -> None:
        """Convert a ZAP alert to a Vulnerability model."""
        risk = alert.get("risk", "Informational")
        cwe_id = str(alert.get("cweid", ""))
        owasp = CWE_OWASP_MAP.get(cwe_id, OWASPCategory.A05_SECURITY_MISCONFIGURATION)

        self.add_vulnerability(Vulnerability(
            title=f"[ZAP] {alert.get('alert', 'Unknown')}",
            description=alert.get("description", "No description provided by ZAP."),
            severity=ZAP_RISK_MAP.get(risk, Severity.INFO),
            cvss_score=ZAP_RISK_CVSS.get(risk, 0.0),
            owasp_category=owasp,
            url=alert.get("url", ""),
            parameter=alert.get("param", ""),
            evidence=alert.get("evidence", ""),
            remediation=alert.get("solution", ""),
            references=[alert.get("reference", "")],
            cwe_id=f"CWE-{cwe_id}" if cwe_id and cwe_id != "0" else "",
        ))
