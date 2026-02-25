"""Notification system — Slack, email, and generic webhook alerts."""

from __future__ import annotations

import asyncio
import json
import smtplib
import ssl
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import httpx

from auto_vapt.logger import get_logger
from auto_vapt.models import ScanReport

log = get_logger(__name__)


@dataclass
class NotificationConfig:
    """Configuration for notifications."""

    slack_webhook_url: str = ""
    email_smtp_host: str = ""
    email_smtp_port: int = 587
    email_from: str = ""
    email_to: list[str] = field(default_factory=list)
    email_username: str = ""
    email_password: str = ""
    email_use_tls: bool = True
    webhook_url: str = ""
    webhook_headers: dict[str, str] = field(default_factory=dict)
    notify_on: list[str] = field(default_factory=lambda: ["completed", "failed"])


def _build_summary(report: ScanReport) -> dict[str, Any]:
    """Build a notification summary payload from a scan report."""
    summary = report.severity_summary
    return {
        "scan_id": report.id[:8],
        "target": report.target.url,
        "profile": report.scan_profile,
        "status": report.status.value,
        "risk_score": report.risk_score,
        "total_vulns": len(report.all_vulnerabilities),
        "critical": summary.get("CRITICAL", 0),
        "high": summary.get("HIGH", 0),
        "medium": summary.get("MEDIUM", 0),
        "low": summary.get("LOW", 0),
        "info": summary.get("INFO", 0),
        "pass_fail": report.pass_fail,
        "duration": report.total_duration_seconds,
    }


async def send_slack_notification(
    webhook_url: str, report: ScanReport
) -> bool:
    """Send a Slack notification with scan results."""
    s = _build_summary(report)
    gate = ":white_check_mark: PASS" if s["pass_fail"] else ":x: FAIL"
    color = "#22c55e" if s["pass_fail"] else "#ef4444"

    payload = {
        "attachments": [
            {
                "color": color,
                "fallback": f"Auto-VAPT Scan {s['status']} — {s['target']}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🛡️ Auto-VAPT Scan {s['status']}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Target:*\n{s['target']}"},
                            {"type": "mrkdwn", "text": f"*Profile:*\n{s['profile']}"},
                            {"type": "mrkdwn", "text": f"*Risk Score:*\n{s['risk_score']:.0f}/100"},
                            {"type": "mrkdwn", "text": f"*Security Gate:*\n{gate}"},
                            {
                                "type": "mrkdwn",
                                "text": (
                                    f"*Findings:*\n"
                                    f":red_circle: {s['critical']} Critical · "
                                    f":orange_circle: {s['high']} High · "
                                    f":yellow_circle: {s['medium']} Medium · "
                                    f":blue_circle: {s['low']} Low"
                                ),
                            },
                            {"type": "mrkdwn", "text": f"*Duration:*\n{s['duration']:.1f}s"},
                        ],
                    },
                ],
            }
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
        log.info("slack_notification_sent", target=s["target"])
        return True
    except Exception as e:
        log.error("slack_notification_failed", error=str(e))
        return False


def send_email_notification(config: NotificationConfig, report: ScanReport) -> bool:
    """Send an email notification with scan results."""
    s = _build_summary(report)
    gate = "PASS ✓" if s["pass_fail"] else "FAIL ✗"

    subject = f"Auto-VAPT Scan {s['status']} — {s['target']} [{gate}]"

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:20px">
    <div style="max-width:600px;margin:0 auto;background:white;border-radius:8px;overflow:hidden">
        <div style="background:{'#22c55e' if s['pass_fail'] else '#ef4444'};color:white;padding:20px">
            <h1 style="margin:0">🛡️ Auto-VAPT Scan {s['status']}</h1>
            <p style="margin:5px 0 0">{s['target']}</p>
        </div>
        <div style="padding:20px">
            <table style="width:100%;border-collapse:collapse">
                <tr><td style="padding:8px;font-weight:bold">Risk Score</td><td style="padding:8px">{s['risk_score']:.0f}/100</td></tr>
                <tr><td style="padding:8px;font-weight:bold">Security Gate</td><td style="padding:8px">{gate}</td></tr>
                <tr><td style="padding:8px;font-weight:bold">Critical</td><td style="padding:8px;color:#ef4444">{s['critical']}</td></tr>
                <tr><td style="padding:8px;font-weight:bold">High</td><td style="padding:8px;color:#f97316">{s['high']}</td></tr>
                <tr><td style="padding:8px;font-weight:bold">Medium</td><td style="padding:8px;color:#eab308">{s['medium']}</td></tr>
                <tr><td style="padding:8px;font-weight:bold">Low</td><td style="padding:8px;color:#3b82f6">{s['low']}</td></tr>
                <tr><td style="padding:8px;font-weight:bold">Duration</td><td style="padding:8px">{s['duration']:.1f}s</td></tr>
                <tr><td style="padding:8px;font-weight:bold">Scan ID</td><td style="padding:8px">{s['scan_id']}</td></tr>
            </table>
        </div>
        <div style="padding:10px 20px;background:#f9f9f9;font-size:12px;color:#888">
            Generated by Auto-VAPT Security Scanner
        </div>
    </div>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = config.email_from
    msg["To"] = ", ".join(config.email_to)
    msg.attach(MIMEText(html, "html"))

    try:
        context = ssl.create_default_context()
        if config.email_use_tls:
            with smtplib.SMTP(config.email_smtp_host, config.email_smtp_port) as server:
                server.starttls(context=context)
                if config.email_username:
                    server.login(config.email_username, config.email_password)
                server.sendmail(config.email_from, config.email_to, msg.as_string())
        else:
            with smtplib.SMTP(config.email_smtp_host, config.email_smtp_port) as server:
                if config.email_username:
                    server.login(config.email_username, config.email_password)
                server.sendmail(config.email_from, config.email_to, msg.as_string())
        log.info("email_notification_sent", to=config.email_to)
        return True
    except Exception as e:
        log.error("email_notification_failed", error=str(e))
        return False


async def send_webhook_notification(
    url: str, report: ScanReport, headers: dict[str, str] | None = None
) -> bool:
    """Send a generic webhook notification with scan results JSON."""
    payload = _build_summary(report)

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                url,
                json=payload,
                headers=headers or {"Content-Type": "application/json"},
            )
            resp.raise_for_status()
        log.info("webhook_notification_sent", url=url)
        return True
    except Exception as e:
        log.error("webhook_notification_failed", error=str(e))
        return False


async def notify(config: NotificationConfig, report: ScanReport) -> dict[str, bool]:
    """Send all configured notifications for a scan report.

    Returns:
        Dict mapping channel name to success status.
    """
    results: dict[str, bool] = {}

    if config.slack_webhook_url:
        results["slack"] = await send_slack_notification(
            config.slack_webhook_url, report
        )

    if config.email_smtp_host and config.email_to:
        results["email"] = send_email_notification(config, report)

    if config.webhook_url:
        results["webhook"] = await send_webhook_notification(
            config.webhook_url, report, config.webhook_headers
        )

    return results
