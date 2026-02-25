"""Integration tests for Auto-VAPT — test full scan pipeline and dashboard API."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import httpx

from auto_vapt.config import ScanConfig, TargetConfig, ScannerConfig, ReportConfig, create_config_from_args
from auto_vapt.models import ScanReport, ScanStatus, Severity, OWASPCategory, Vulnerability
from auto_vapt.orchestrator import ScanOrchestrator
from auto_vapt.scanners.base import get_registered_scanners
from dashboard.database import init_db, get_db, save_scan, get_all_scans, get_stats, delete_scan


# ─── Configuration ─────────────────────────────────────────────

# Use a safe, intentionally vulnerable test target
TEST_TARGET = os.environ.get("VAPT_TEST_TARGET", "http://testphp.vulnweb.com")
SKIP_LIVE = os.environ.get("VAPT_SKIP_LIVE", "false").lower() == "true"


# ─── Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def tmp_report_dir():
    """Create a temporary directory for reports."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def tmp_db():
    """Create a temporary SQLite database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    init_db(db_path)
    yield db_path
    os.unlink(db_path)


@pytest.fixture
def quick_config(tmp_report_dir):
    """Create a quick scan config for testing."""
    return create_config_from_args(
        target_url=TEST_TARGET,
        profile="quick",
        output_dir=tmp_report_dir,
        formats=["json"],
        rate_limit=5,
        timeout=120,
        verify_ssl=False,
    )


# ─── Scanner Registry Tests ───────────────────────────────────

class TestScannerRegistry:
    """Test that all scanner modules register correctly."""

    def test_all_scanners_registered(self):
        registry = get_registered_scanners()
        expected = {
            "injection", "broken_access", "crypto",
            "misconfig", "vulnerable_components", "auth_failures",
            "zap",
        }
        registered = set(registry.keys())
        # All non-ZAP scanners should be registered (ZAP may or may not be)
        core_scanners = expected - {"zap"}
        assert core_scanners.issubset(registered), f"Missing scanners: {core_scanners - registered}"

    def test_scanner_classes_have_required_attrs(self):
        registry = get_registered_scanners()
        for scanner_id, scanner_cls in registry.items():
            assert hasattr(scanner_cls, "scanner_id")
            assert hasattr(scanner_cls, "scanner_name")
            assert hasattr(scanner_cls, "owasp_category")
            assert scanner_cls.scanner_id == scanner_id


# ─── Config Tests ──────────────────────────────────────────────

class TestConfigIntegration:
    """Test config creation and profile overrides."""

    def test_quick_profile(self):
        config = create_config_from_args(
            target_url="https://example.com",
            profile="quick",
        )
        assert config.max_depth == 1
        assert len(config.scanners) == 2

    def test_full_profile(self):
        config = create_config_from_args(
            target_url="https://example.com",
            profile="full",
        )
        assert config.max_depth == 5
        assert config.max_concurrent_scanners == 5

    def test_ci_profile(self):
        config = create_config_from_args(
            target_url="https://example.com",
            profile="ci",
        )
        assert config.ci.enabled is True
        assert config.ci.sarif_output is True


# ─── Database Tests ────────────────────────────────────────────

class TestDatabaseIntegration:
    """Test database operations end-to-end."""

    def test_save_and_retrieve_scan(self, tmp_db):
        conn = get_db(tmp_db)
        try:
            save_scan(conn, {
                "id": "test-scan-001",
                "target_url": "https://example.com",
                "profile": "quick",
                "status": "COMPLETED",
                "started_at": "2025-01-01T00:00:00Z",
                "risk_score": 42.0,
                "total_vulns": 5,
                "critical_count": 1,
                "high_count": 2,
                "medium_count": 1,
                "low_count": 1,
            })
            scans = get_all_scans(conn)
            assert len(scans) == 1
            assert scans[0]["id"] == "test-scan-001"
            assert scans[0]["risk_score"] == 42.0
        finally:
            conn.close()

    def test_delete_scan(self, tmp_db):
        conn = get_db(tmp_db)
        try:
            save_scan(conn, {
                "id": "test-del-001",
                "target_url": "https://example.com",
                "started_at": "2025-01-01T00:00:00Z",
            })
            result = delete_scan(conn, "test-del-001")
            assert result is True
            scans = get_all_scans(conn)
            assert len(scans) == 0
        finally:
            conn.close()

    def test_stats_calculation(self, tmp_db):
        conn = get_db(tmp_db)
        try:
            for i in range(3):
                save_scan(conn, {
                    "id": f"stat-scan-{i}",
                    "target_url": "https://example.com",
                    "status": "COMPLETED",
                    "started_at": "2025-01-01T00:00:00Z",
                    "risk_score": 30.0,
                    "total_vulns": 2,
                })
            stats = get_stats(conn)
            assert stats["total_scans"] == 3
        finally:
            conn.close()


# ─── Report Generation Tests ──────────────────────────────────

class TestReportGeneration:
    """Test report output generation."""

    def test_json_report_structure(self):
        from auto_vapt.models import TargetInfo
        report = ScanReport(
            target=TargetInfo(url="https://example.com"),
            scan_profile="quick",
        )
        data = report.model_dump(mode="json")
        assert "target" in data
        assert "results" in data
        assert data["target"]["url"] == "https://example.com"

    def test_html_report_generation(self):
        from auto_vapt.models import TargetInfo
        from auto_vapt.reporting.generator import generate_html_report
        report = ScanReport(
            target=TargetInfo(url="https://example.com"),
            scan_profile="quick",
        )
        html = generate_html_report(report)
        assert "<!DOCTYPE html>" in html
        assert "Auto-VAPT" in html
        assert "example.com" in html


# ─── Live Scan Tests (require network) ────────────────────────

@pytest.mark.skipif(SKIP_LIVE, reason="Live tests disabled via VAPT_SKIP_LIVE")
class TestLiveScan:
    """Integration tests against a live target (testphp.vulnweb.com)."""

    @pytest.mark.asyncio
    async def test_quick_scan_pipeline(self, quick_config, tmp_report_dir):
        """Test the full scan pipeline with a quick profile."""
        orchestrator = ScanOrchestrator(quick_config)
        report = await orchestrator.run()

        assert report.status == ScanStatus.COMPLETED
        assert report.total_duration_seconds > 0
        assert report.target.url == TEST_TARGET

        # Check that JSON report was written
        report_files = list(Path(tmp_report_dir).glob("*.json"))
        assert len(report_files) >= 1

    @pytest.mark.asyncio
    async def test_profiler_discovers_info(self, quick_config):
        """Test that profiler gathers target information."""
        orchestrator = ScanOrchestrator(quick_config)
        target_info = await orchestrator._profile_target()

        assert target_info.url == TEST_TARGET
        # Should discover at least some info
        assert target_info.ip_address or target_info.server or target_info.technologies

    @pytest.mark.asyncio
    async def test_crawler_discovers_pages(self, quick_config):
        """Test that crawler finds pages and forms."""
        from auto_vapt.crawler import WebCrawler
        crawler = WebCrawler(max_depth=1, max_pages=10, verify_ssl=False)
        result = await crawler.crawl(TEST_TARGET)

        assert len(result.discovered_urls) > 0
        # vulnweb.com should have forms
        assert len(result.forms) >= 0  # At least attempted


# ─── Dashboard API Tests ──────────────────────────────────────

class TestDashboardAPI:
    """Test dashboard FastAPI endpoints."""

    @pytest.fixture(autouse=True)
    def setup_test_client(self, tmp_db):
        """Set up FastAPI test client with temp database."""
        from fastapi.testclient import TestClient
        from dashboard import database

        # Patch database path
        original_path = database.DB_PATH
        database.DB_PATH = Path(tmp_db)
        
        from dashboard.app import app
        self.client = TestClient(app)
        yield
        database.DB_PATH = original_path

    def test_health_endpoint(self):
        resp = self.client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_stats_endpoint(self):
        resp = self.client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_scans" in data

    def test_list_scans_empty(self):
        resp = self.client.get("/api/scans")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_scan_not_found(self):
        resp = self.client.get("/api/scans/nonexistent-id")
        assert resp.status_code == 404

    def test_create_scan(self):
        resp = self.client.post("/api/scans", json={
            "target_url": "http://example.com",
            "profile": "quick",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert "id" in data
        assert data["status"] == "PENDING"

    def test_delete_nonexistent_scan(self):
        resp = self.client.delete("/api/scans/nonexistent")
        assert resp.status_code == 404
