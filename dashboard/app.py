"""FastAPI backend for Auto-VAPT Dashboard."""

from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from dashboard.database import (
    init_db, get_db, save_scan, save_vulnerabilities,
    update_scan_status, get_all_scans, get_scan, get_scan_vulns,
    delete_scan, get_stats,
)

# ─── WebSocket Connection Manager ────────────────────────────────────

class ConnectionManager:
    """Manage WebSocket connections for live scan progress."""

    def __init__(self) -> None:
        self.active: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str) -> None:
        await websocket.accept()
        if scan_id not in self.active:
            self.active[scan_id] = []
        self.active[scan_id].append(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: str) -> None:
        if scan_id in self.active:
            self.active[scan_id] = [w for w in self.active[scan_id] if w != websocket]
            if not self.active[scan_id]:
                del self.active[scan_id]

    async def broadcast(self, scan_id: str, message: dict[str, Any]) -> None:
        if scan_id in self.active:
            dead: list[WebSocket] = []
            for ws in self.active[scan_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.disconnect(ws, scan_id)


manager = ConnectionManager()

# ─── Request/Response Models ─────────────────────────────────────────

class ScanRequest(BaseModel):
    target_url: str
    profile: str = Field(default="default")
    rate_limit: int = Field(default=10, ge=1, le=100)
    timeout: int = Field(default=1800, ge=60, le=7200)
    verify_ssl: bool = True


class ScanResponse(BaseModel):
    id: str
    target_url: str
    profile: str
    status: str
    started_at: str
    completed_at: str | None = None
    duration_seconds: float = 0
    risk_score: float = 0
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    pass_fail: bool = True


# ─── App Lifecycle ───────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Auto-VAPT Dashboard",
    description="CI/CD Integrated Vulnerability Assessment Scanner — Dashboard API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── API Routes ──────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "auto-vapt-dashboard"}


@app.get("/api/stats")
async def stats():
    """Get aggregate dashboard statistics."""
    conn = get_db()
    try:
        return get_stats(conn)
    finally:
        conn.close()


@app.get("/api/scans")
async def list_scans(limit: int = 50):
    """List all scans, most recent first."""
    conn = get_db()
    try:
        scans = get_all_scans(conn, limit)
        for s in scans:
            s["pass_fail"] = bool(s.get("pass_fail", 1))
        return scans
    finally:
        conn.close()


@app.get("/api/scans/{scan_id}")
async def get_scan_detail(scan_id: str):
    """Get scan details with vulnerabilities."""
    conn = get_db()
    try:
        scan = get_scan(conn, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan["pass_fail"] = bool(scan.get("pass_fail", 1))
        scan["target_info"] = json.loads(scan.get("target_info", "{}"))
        scan["vulnerabilities"] = get_scan_vulns(conn, scan_id)
        return scan
    finally:
        conn.close()


@app.post("/api/scans", status_code=201)
async def start_scan(req: ScanRequest):
    """Start a new vulnerability scan."""
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db()
    try:
        save_scan(conn, {
            "id": scan_id,
            "target_url": req.target_url,
            "profile": req.profile,
            "status": "PENDING",
            "started_at": now,
        })
    finally:
        conn.close()

    # Run scan in background
    asyncio.create_task(_run_scan_async(scan_id, req))

    return {"id": scan_id, "status": "PENDING", "target_url": req.target_url}


@app.delete("/api/scans/{scan_id}")
async def remove_scan(scan_id: str):
    """Delete a scan and its results."""
    conn = get_db()
    try:
        if not delete_scan(conn, scan_id):
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"deleted": True}
    finally:
        conn.close()


# ─── WebSocket ───────────────────────────────────────────────────────

@app.websocket("/ws/scans/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for live scan progress updates."""
    await manager.connect(websocket, scan_id)
    try:
        while True:
            # Keep connection alive, client can send ping
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)


# ─── Background Scan Runner ─────────────────────────────────────────

async def _run_scan_async(scan_id: str, req: ScanRequest) -> None:
    """Run a scan in the background and broadcast progress via WebSocket."""
    from auto_vapt.config import create_config_from_args
    from auto_vapt.orchestrator import ScanOrchestrator
    from auto_vapt.models import ScanStatus

    conn = get_db()

    try:
        # Update status to PROFILING
        update_scan_status(conn, scan_id, "PROFILING")
        await manager.broadcast(scan_id, {
            "type": "status", "status": "PROFILING",
            "message": "Profiling target...",
        })

        config = create_config_from_args(
            target_url=req.target_url,
            profile=req.profile,
            rate_limit=req.rate_limit,
            timeout=req.timeout,
            verify_ssl=req.verify_ssl,
        )

        orchestrator = ScanOrchestrator(config)

        # Override orchestrator to broadcast progress
        original_run_scanners = orchestrator._run_scanners

        async def patched_run_scanners(target_info):
            update_scan_status(conn, scan_id, "SCANNING")
            await manager.broadcast(scan_id, {
                "type": "status", "status": "SCANNING",
                "message": "Running vulnerability scanners...",
            })
            await original_run_scanners(target_info)

            # Broadcast each result as it comes in
            for result in orchestrator.report.results:
                await manager.broadcast(scan_id, {
                    "type": "scanner_complete",
                    "scanner": result.scanner_name,
                    "vulns_found": len(result.vulnerabilities),
                    "duration": result.duration_seconds,
                })

        orchestrator._run_scanners = patched_run_scanners

        report = await orchestrator.run()

        # Save results to database
        summary = report.severity_summary
        update_scan_status(
            conn, scan_id, "COMPLETED",
            completed_at=datetime.now(timezone.utc).isoformat(),
            duration_seconds=report.total_duration_seconds,
            risk_score=report.risk_score,
            total_vulns=len(report.all_vulnerabilities),
            critical_count=summary.get("CRITICAL", 0),
            high_count=summary.get("HIGH", 0),
            medium_count=summary.get("MEDIUM", 0),
            low_count=summary.get("LOW", 0),
            info_count=summary.get("INFO", 0),
            pass_fail=report.pass_fail,
        )

        # Save vulnerabilities
        vuln_dicts = [v.model_dump(mode="json") for v in report.all_vulnerabilities]
        save_vulnerabilities(conn, scan_id, vuln_dicts)

        await manager.broadcast(scan_id, {
            "type": "completed",
            "status": "COMPLETED",
            "risk_score": report.risk_score,
            "total_vulns": len(report.all_vulnerabilities),
            "duration": report.total_duration_seconds,
            "summary": summary,
        })

    except Exception as e:
        update_scan_status(conn, scan_id, "FAILED")
        await manager.broadcast(scan_id, {
            "type": "error", "status": "FAILED", "message": str(e),
        })
    finally:
        conn.close()


# ─── Serve Frontend ──────────────────────────────────────────────────

import os
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend", "dist")

if os.path.exists(FRONTEND_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")

    @app.get("/{path:path}")
    async def serve_frontend(path: str):
        file_path = os.path.join(FRONTEND_DIR, path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
