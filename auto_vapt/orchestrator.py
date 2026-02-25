"""Scan orchestrator — coordinates all scanners and aggregates results."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from auto_vapt.config import ScanConfig
from auto_vapt.logger import get_logger
from auto_vapt.models import ScanReport, ScanStatus, TargetInfo
from auto_vapt.rate_limiter import RateLimitedTransport
from auto_vapt.scanners.base import get_registered_scanners
from auto_vapt.scanners.profiler import profile_target
from auto_vapt.crawler import WebCrawler

log = get_logger(__name__)
console = Console()


class ScanOrchestrator:
    """Orchestrates the full scan lifecycle.

    Flow: Target Profiling → Scanner Execution → Result Aggregation → Report Generation
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.report = ScanReport(
            target=TargetInfo(url=config.target.url),
            scan_profile=config.profile,
            config_used=config.model_dump(),
        )

    async def run(self) -> ScanReport:
        """Execute the full scan pipeline."""
        start = time.time()
        self.report.status = ScanStatus.PROFILING

        console.print("\n[bold cyan]▶ Phase 1: Target Profiling[/]")
        target_info = await self._profile_target()
        self.report.target = target_info

        console.print(f"  [green]✓[/] IP: {target_info.ip_address}")
        console.print(f"  [green]✓[/] Server: {target_info.server or 'Unknown'}")
        console.print(f"  [green]✓[/] Technologies: {', '.join(target_info.technologies) or 'None detected'}")
        console.print(f"  [green]✓[/] HTTP Methods: {', '.join(target_info.http_methods) or 'Unknown'}")

        console.print("\n[bold cyan]▶ Phase 2: Web Crawling[/]")
        await self._crawl_target(target_info)

        console.print(f"  [green]✓[/] Pages discovered: {len(target_info.crawled_urls)}")
        console.print(f"  [green]✓[/] Forms found: {len(target_info.discovered_forms)}")
        console.print(f"  [green]✓[/] Parameters: {len(target_info.discovered_parameters)}")
        console.print(f"  [green]✓[/] JS endpoints: {len(target_info.js_endpoints)}")

        console.print("\n[bold cyan]▶ Phase 3: Vulnerability Scanning[/]")
        self.report.status = ScanStatus.SCANNING
        await self._run_scanners(target_info)

        console.print("\n[bold cyan]▶ Phase 4: Report Generation[/]")
        self.report.status = ScanStatus.REPORTING
        await self._generate_reports()

        self.report.status = ScanStatus.COMPLETED
        self.report.completed_at = datetime.now(timezone.utc)
        self.report.total_duration_seconds = round(time.time() - start, 2)

        console.print(f"\n  [green]✓[/] Scan completed in {self.report.total_duration_seconds:.1f}s")
        console.print(f"  [green]✓[/] Total vulnerabilities: {len(self.report.all_vulnerabilities)}")

        return self.report

    async def _crawl_target(self, target_info: TargetInfo) -> None:
        """Crawl the target to discover pages, forms, and parameters."""
        try:
            crawler = WebCrawler(
                max_depth=self.config.max_depth,
                max_pages=self.config.max_pages if hasattr(self.config, 'max_pages') else 100,
                rate_limit=0.1,
                verify_ssl=self.config.verify_ssl,
                user_agent=self.config.user_agent,
            )
            result = await crawler.crawl(self.config.target.url)

            # Merge crawl data into TargetInfo
            target_info.crawled_urls = sorted(result.discovered_urls)
            target_info.discovered_forms = [
                {"url": f.url, "action": f.action, "method": f.method, "inputs": f.inputs}
                for f in result.forms
            ]
            target_info.discovered_parameters = sorted(result.parameters)
            target_info.js_endpoints = sorted(result.js_endpoints)
            target_info.discovered_emails = sorted(result.emails)
            target_info.html_comments = result.comments[:20]  # Limit

        except Exception as e:
            log.error("crawling_failed", error=str(e))
            console.print(f"  [yellow]⚠ Crawling partial failure: {e}[/]")

    async def _profile_target(self) -> TargetInfo:
        """Profile the target to gather intelligence."""
        try:
            return await profile_target(
                self.config.target.url,
                verify_ssl=self.config.verify_ssl,
            )
        except Exception as e:
            log.error("profiling_failed", error=str(e))
            console.print(f"  [yellow]⚠ Profiling partial failure: {e}[/]")
            return TargetInfo(url=self.config.target.url)

    async def _run_scanners(self, target_info: TargetInfo) -> None:
        """Run all enabled scanners with concurrency control."""
        registry = get_registered_scanners()
        enabled_scanners = []

        for scanner_id, scanner_cls in registry.items():
            scanner_config = self.config.scanners.get(scanner_id)
            if scanner_config and scanner_config.enabled:
                enabled_scanners.append((scanner_id, scanner_cls, scanner_config))
            elif scanner_id in self.config.scanners:
                log.info("scanner_disabled", scanner=scanner_id)

        if not enabled_scanners:
            console.print("  [yellow]⚠ No scanners enabled[/]")
            return

        # Shared HTTP client for all scanners
        transport = RateLimitedTransport(rate=float(self.config.rate_limit))
        headers = {"User-Agent": self.config.user_agent}
        auth = None

        # Build auth from config
        auth_config = self.config.target.auth
        if auth_config and auth_config.type != "none":
            if auth_config.type == "bearer" and auth_config.token:
                headers["Authorization"] = f"Bearer {auth_config.token}"
            elif auth_config.type == "cookie" and auth_config.cookie:
                headers["Cookie"] = auth_config.cookie
            elif auth_config.type == "basic" and auth_config.username:
                auth = httpx.BasicAuth(auth_config.username, auth_config.password)
            elif auth_config.type == "form" and auth_config.login_url:
                # Perform form login to obtain session cookie
                async with httpx.AsyncClient(
                    verify=self.config.verify_ssl, follow_redirects=True
                ) as login_client:
                    resp = await login_client.post(
                        auth_config.login_url,
                        data={"username": auth_config.username, "password": auth_config.password},
                    )
                    cookies = resp.cookies
                    if cookies:
                        headers["Cookie"] = "; ".join(
                            f"{k}={v}" for k, v in cookies.items()
                        )
            # Merge any custom auth headers
            if auth_config.headers:
                headers.update(auth_config.headers)

            console.print(f"  [green]✓[/] Authenticated scanning ({auth_config.type})")

        async with httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=httpx.Timeout(15.0),
            follow_redirects=self.config.follow_redirects,
            headers=headers,
            auth=auth,
            transport=transport,
        ) as http_client:
            semaphore = asyncio.Semaphore(self.config.max_concurrent_scanners)

            async def run_scanner(scanner_id: str, scanner_cls: type, config: object) -> None:
                async with semaphore:
                    scanner = scanner_cls(config)
                    result = await scanner.execute(
                        self.config.target.url,
                        http_client=http_client,
                        target_info=target_info,
                    )
                    self.report.results.append(result)

                    vuln_count = len(result.vulnerabilities)
                    status = f"[green]✓[/] {vuln_count} finding(s)" if vuln_count else "[dim]✓ Clean[/]"
                    console.print(f"  {status} — {scanner.scanner_name} ({result.duration_seconds:.1f}s)")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Scanning...", total=len(enabled_scanners))
                tasks = []

                for scanner_id, scanner_cls, scanner_config in enabled_scanners:
                    tasks.append(run_scanner(scanner_id, scanner_cls, scanner_config))

                # Run with global timeout
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=self.config.global_timeout,
                    )
                except asyncio.TimeoutError:
                    console.print("  [yellow]⚠ Global timeout reached[/]")

    async def _generate_reports(self) -> None:
        """Generate reports in configured formats."""
        output_dir = Path(self.config.report.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        for fmt in self.config.report.formats:
            try:
                if fmt == "json":
                    await self._write_json_report(output_dir)
                elif fmt == "html":
                    await self._write_html_report(output_dir)
                elif fmt == "pdf":
                    await self._write_pdf_report(output_dir)
                elif fmt == "sarif":
                    await self._write_sarif_report(output_dir)
                console.print(f"  [green]✓[/] {fmt.upper()} report generated")
            except Exception as e:
                console.print(f"  [red]✗[/] {fmt.upper()} report failed: {e}")
                log.error("report_generation_failed", format=fmt, error=str(e))

    async def _write_json_report(self, output_dir: Path) -> None:
        """Write JSON report."""
        import json
        report_path = output_dir / f"autovapt-report-{self.report.id[:8]}.json"
        data = self.report.model_dump(mode="json")
        with open(report_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    async def _write_html_report(self, output_dir: Path) -> None:
        """Write HTML report using Jinja2 template."""
        from auto_vapt.reporting.generator import generate_html_report
        report_path = output_dir / f"autovapt-report-{self.report.id[:8]}.html"
        html = generate_html_report(self.report)
        with open(report_path, "w") as f:
            f.write(html)

    async def _write_pdf_report(self, output_dir: Path) -> None:
        """Write PDF report using WeasyPrint."""
        from auto_vapt.reporting.generator import generate_pdf_report
        report_path = output_dir / f"autovapt-report-{self.report.id[:8]}.pdf"
        generate_pdf_report(self.report, report_path)

    async def _write_sarif_report(self, output_dir: Path) -> None:
        """Write SARIF report for code scanning integration."""
        import json
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "Auto-VAPT",
                    "version": "1.0.0",
                    "rules": [],
                }},
                "results": [],
            }],
        }

        for vuln in self.report.all_vulnerabilities:
            sarif["runs"][0]["results"].append({
                "ruleId": vuln.cwe_id or vuln.id,
                "level": "error" if vuln.severity.value in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": vuln.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": vuln.url}}}],
            })

        report_path = output_dir / f"autovapt-report-{self.report.id[:8]}.sarif"
        with open(report_path, "w") as f:
            json.dump(sarif, f, indent=2)
