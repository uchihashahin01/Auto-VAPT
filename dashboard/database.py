"""SQLite database layer for storing scan history and results."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).parent / "autovapt.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT 'default',
    status TEXT NOT NULL DEFAULT 'PENDING',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    duration_seconds REAL DEFAULT 0,
    risk_score REAL DEFAULT 0,
    total_vulns INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    pass_fail INTEGER DEFAULT 1,
    target_info TEXT DEFAULT '{}',
    config_used TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL DEFAULT 0,
    owasp_category TEXT NOT NULL,
    url TEXT DEFAULT '',
    parameter TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    cwe_id TEXT DEFAULT '',
    cve_ids TEXT DEFAULT '[]',
    scanner TEXT DEFAULT '',
    false_positive INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
"""


def get_db(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Get a database connection with WAL mode and foreign keys enabled."""
    path = db_path or DB_PATH
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str | Path | None = None) -> None:
    """Initialize the database schema."""
    conn = get_db(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def save_scan(conn: sqlite3.Connection, scan_data: dict[str, Any]) -> None:
    """Save a scan record to the database."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO scans (id, target_url, profile, status, started_at,
           completed_at, duration_seconds, risk_score, total_vulns,
           critical_count, high_count, medium_count, low_count, info_count,
           pass_fail, target_info, config_used, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_data["id"],
            scan_data["target_url"],
            scan_data.get("profile", "default"),
            scan_data.get("status", "PENDING"),
            scan_data.get("started_at", now),
            scan_data.get("completed_at"),
            scan_data.get("duration_seconds", 0),
            scan_data.get("risk_score", 0),
            scan_data.get("total_vulns", 0),
            scan_data.get("critical_count", 0),
            scan_data.get("high_count", 0),
            scan_data.get("medium_count", 0),
            scan_data.get("low_count", 0),
            scan_data.get("info_count", 0),
            1 if scan_data.get("pass_fail", True) else 0,
            json.dumps(scan_data.get("target_info", {})),
            json.dumps(scan_data.get("config_used", {})),
            now,
        ),
    )
    conn.commit()


def save_vulnerabilities(
    conn: sqlite3.Connection, scan_id: str, vulns: list[dict[str, Any]]
) -> None:
    """Save vulnerabilities for a scan."""
    now = datetime.now(timezone.utc).isoformat()
    for v in vulns:
        conn.execute(
            """INSERT OR REPLACE INTO vulnerabilities
               (id, scan_id, title, description, severity, cvss_score,
                owasp_category, url, parameter, evidence, remediation,
                cwe_id, cve_ids, scanner, false_positive, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                v.get("id", ""),
                scan_id,
                v["title"],
                v["description"],
                v["severity"],
                v.get("cvss_score", 0),
                v["owasp_category"],
                v.get("url", ""),
                v.get("parameter", ""),
                v.get("evidence", ""),
                v.get("remediation", ""),
                v.get("cwe_id", ""),
                json.dumps(v.get("cve_ids", [])),
                v.get("scanner", ""),
                1 if v.get("false_positive", False) else 0,
                now,
            ),
        )
    conn.commit()


def update_scan_status(
    conn: sqlite3.Connection, scan_id: str, status: str, **kwargs: Any
) -> None:
    """Update scan status and optional fields."""
    fields = ["status = ?"]
    values: list[Any] = [status]

    for key in ("completed_at", "duration_seconds", "risk_score", "total_vulns",
                "critical_count", "high_count", "medium_count", "low_count",
                "info_count", "pass_fail"):
        if key in kwargs:
            val = kwargs[key]
            if key == "pass_fail":
                val = 1 if val else 0
            fields.append(f"{key} = ?")
            values.append(val)

    values.append(scan_id)
    conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit()


def get_all_scans(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    """Get all scans ordered by most recent first."""
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_scan(conn: sqlite3.Connection, scan_id: str) -> dict[str, Any] | None:
    """Get a single scan by ID."""
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def get_scan_vulns(conn: sqlite3.Connection, scan_id: str) -> list[dict[str, Any]]:
    """Get all vulnerabilities for a scan."""
    rows = conn.execute(
        "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY cvss_score DESC",
        (scan_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["cve_ids"] = json.loads(d.get("cve_ids", "[]"))
        d["false_positive"] = bool(d.get("false_positive", 0))
        result.append(d)
    return result


def delete_scan(conn: sqlite3.Connection, scan_id: str) -> bool:
    """Delete a scan and its vulnerabilities."""
    cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    return cursor.rowcount > 0


def get_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    """Get aggregate statistics across all scans."""
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    completed = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE status = 'COMPLETED'"
    ).fetchone()[0]
    total_vulns = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

    severity_dist = {}
    for row in conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity"
    ).fetchall():
        severity_dist[row["severity"]] = row["cnt"]

    owasp_dist = {}
    for row in conn.execute(
        "SELECT owasp_category, COUNT(*) as cnt FROM vulnerabilities GROUP BY owasp_category"
    ).fetchall():
        owasp_dist[row["owasp_category"]] = row["cnt"]

    avg_risk = conn.execute(
        "SELECT AVG(risk_score) FROM scans WHERE status = 'COMPLETED'"
    ).fetchone()[0] or 0

    recent = conn.execute(
        "SELECT target_url, risk_score, total_vulns, started_at FROM scans ORDER BY created_at DESC LIMIT 10"
    ).fetchall()

    return {
        "total_scans": total,
        "completed_scans": completed,
        "total_vulnerabilities": total_vulns,
        "severity_distribution": severity_dist,
        "owasp_distribution": owasp_dist,
        "average_risk_score": round(avg_risk, 1),
        "recent_scans": [dict(r) for r in recent],
    }
