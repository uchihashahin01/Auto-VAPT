"""HTML report generator with professional styling."""

from __future__ import annotations

from datetime import datetime

from auto_vapt.models import ScanReport, Severity


def generate_html_report(report: ScanReport) -> str:
    """Generate a professional HTML vulnerability assessment report."""
    vulns = report.all_vulnerabilities
    summary = report.severity_summary

    vuln_rows = ""
    for i, v in enumerate(vulns, 1):
        color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
                 "LOW": "#2563eb", "INFO": "#6b7280"}.get(v.severity.value, "#6b7280")
        vuln_rows += f"""
        <tr>
            <td>{i}</td>
            <td><span class="badge" style="background:{color}">{v.severity.value}</span></td>
            <td>{v.cvss_score:.1f}</td>
            <td>{v.title}</td>
            <td>{v.owasp_category.value}</td>
            <td><code>{v.cwe_id}</code></td>
        </tr>"""

    vuln_details = ""
    for i, v in enumerate(vulns, 1):
        color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
                 "LOW": "#2563eb", "INFO": "#6b7280"}.get(v.severity.value, "#6b7280")
        vuln_details += f"""
        <div class="vuln-card" id="vuln-{v.id}">
            <div class="vuln-header" style="border-left: 4px solid {color}">
                <span class="badge" style="background:{color}">{v.severity.value}</span>
                <span class="cvss">CVSS {v.cvss_score:.1f}</span>
                <h3>{v.title}</h3>
            </div>
            <div class="vuln-body">
                <p><strong>OWASP:</strong> {v.owasp_category.value}</p>
                <p><strong>CWE:</strong> {v.cwe_id}</p>
                <p><strong>URL:</strong> <code>{v.url}</code></p>
                {"<p><strong>Parameter:</strong> <code>" + v.parameter + "</code></p>" if v.parameter else ""}
                <h4>Description</h4>
                <p>{v.description}</p>
                {"<h4>Evidence</h4><pre>" + v.evidence + "</pre>" if v.evidence else ""}
                <h4>Remediation</h4>
                <div class="remediation">{v.remediation}</div>
            </div>
        </div>"""

    target = report.target
    gate = "PASS ✓" if report.pass_fail else "FAIL ✗"
    gate_class = "pass" if report.pass_fail else "fail"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auto-VAPT Report — {target.url}</title>
<style>
:root {{
    --bg: #0a0a0f; --surface: #12121a; --border: #1e1e2e;
    --text: #e4e4e7; --muted: #71717a; --accent: #6366f1;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
}}
.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
header {{
    background: linear-gradient(135deg, #1e1b4b, #312e81, #1e1b4b);
    padding: 3rem 2rem; text-align: center; border-bottom: 1px solid var(--border);
}}
header h1 {{ font-size: 2.5rem; color: #c7d2fe; letter-spacing: -0.02em; }}
header p {{ color: #818cf8; margin-top: 0.5rem; font-size: 1.1rem; }}
.meta-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem; margin: 2rem 0;
}}
.meta-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.5rem;
}}
.meta-card h4 {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
.meta-card .value {{ font-size: 1.5rem; font-weight: 700; margin-top: 0.5rem; }}
.severity-grid {{
    display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin: 2rem 0;
}}
.sev-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.5rem; text-align: center;
}}
.sev-card .count {{ font-size: 2rem; font-weight: 800; }}
.sev-card .label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--muted); }}
.badge {{
    display: inline-block; padding: 2px 10px; border-radius: 6px;
    color: white; font-size: 0.75rem; font-weight: 700;
}}
table {{
    width: 100%; border-collapse: collapse; background: var(--surface);
    border-radius: 12px; overflow: hidden; margin: 2rem 0;
}}
th {{ background: #1e1b4b; color: #c7d2fe; padding: 12px 16px; text-align: left; font-size: 0.8rem; text-transform: uppercase; }}
td {{ padding: 12px 16px; border-bottom: 1px solid var(--border); }}
tr:hover {{ background: rgba(99, 102, 241, 0.05); }}
.vuln-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; margin: 1.5rem 0; overflow: hidden;
}}
.vuln-header {{
    padding: 1rem 1.5rem; display: flex; align-items: center; gap: 1rem;
    background: rgba(255,255,255,0.02);
}}
.vuln-header h3 {{ flex: 1; }}
.cvss {{
    background: rgba(99, 102, 241, 0.15); color: #a5b4fc;
    padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600;
}}
.vuln-body {{ padding: 1.5rem; }}
.vuln-body h4 {{ color: var(--accent); margin: 1rem 0 0.5rem; }}
pre {{
    background: #1a1a2e; padding: 1rem; border-radius: 8px;
    overflow-x: auto; font-size: 0.85rem; color: #a5b4fc;
}}
code {{ background: rgba(99, 102, 241, 0.1); padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; }}
.remediation {{
    background: rgba(34, 197, 94, 0.08); border-left: 3px solid #22c55e;
    padding: 1rem; border-radius: 0 8px 8px 0;
}}
.gate {{ font-size: 1.5rem; font-weight: 800; }}
.gate.pass {{ color: #22c55e; }}
.gate.fail {{ color: #dc2626; }}
section {{ margin: 3rem 0; }}
section > h2 {{
    font-size: 1.5rem; color: #c7d2fe; margin-bottom: 1rem;
    padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);
}}
footer {{ text-align: center; padding: 2rem; color: var(--muted); font-size: 0.85rem; }}
@media (max-width: 768px) {{
    .severity-grid {{ grid-template-columns: repeat(3, 1fr); }}
    .meta-grid {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>

<header>
    <h1>🛡️ Auto-VAPT Security Report</h1>
    <p>Automated Vulnerability Assessment & Penetration Testing</p>
</header>

<div class="container">

<section>
<h2>Executive Summary</h2>
<div class="meta-grid">
    <div class="meta-card">
        <h4>Target</h4>
        <div class="value" style="font-size:1rem;word-break:break-all">{target.url}</div>
    </div>
    <div class="meta-card">
        <h4>Risk Score</h4>
        <div class="value" style="color:{'#dc2626' if report.risk_score > 50 else '#ca8a04' if report.risk_score > 20 else '#22c55e'}">{report.risk_score:.0f}/100</div>
    </div>
    <div class="meta-card">
        <h4>Security Gate</h4>
        <div class="gate {gate_class}">{gate}</div>
    </div>
    <div class="meta-card">
        <h4>Scan Duration</h4>
        <div class="value">{report.total_duration_seconds:.1f}s</div>
    </div>
</div>

<div class="severity-grid">
    <div class="sev-card"><div class="count" style="color:#dc2626">{summary.get('CRITICAL',0)}</div><div class="label">Critical</div></div>
    <div class="sev-card"><div class="count" style="color:#ea580c">{summary.get('HIGH',0)}</div><div class="label">High</div></div>
    <div class="sev-card"><div class="count" style="color:#ca8a04">{summary.get('MEDIUM',0)}</div><div class="label">Medium</div></div>
    <div class="sev-card"><div class="count" style="color:#2563eb">{summary.get('LOW',0)}</div><div class="label">Low</div></div>
    <div class="sev-card"><div class="count" style="color:#6b7280">{summary.get('INFO',0)}</div><div class="label">Info</div></div>
</div>
</section>

<section>
<h2>Target Information</h2>
<div class="meta-grid">
    <div class="meta-card"><h4>IP Address</h4><div class="value" style="font-size:1rem">{target.ip_address or 'N/A'}</div></div>
    <div class="meta-card"><h4>Server</h4><div class="value" style="font-size:1rem">{target.server or 'N/A'}</div></div>
    <div class="meta-card"><h4>Technologies</h4><div class="value" style="font-size:1rem">{', '.join(target.technologies) or 'N/A'}</div></div>
    <div class="meta-card"><h4>Scan Profile</h4><div class="value" style="font-size:1rem">{report.scan_profile}</div></div>
</div>
</section>

<section>
<h2>Vulnerability Summary</h2>
<table>
<thead><tr><th>#</th><th>Severity</th><th>CVSS</th><th>Title</th><th>OWASP</th><th>CWE</th></tr></thead>
<tbody>{vuln_rows if vuln_rows else '<tr><td colspan="6" style="text-align:center;color:var(--muted)">No vulnerabilities found ✓</td></tr>'}</tbody>
</table>
</section>

<section>
<h2>Detailed Findings</h2>
{vuln_details if vuln_details else '<p style="color:var(--muted)">No vulnerabilities to report.</p>'}
</section>

</div>

<footer>
    Generated by Auto-VAPT v1.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Scan ID: {report.id[:8]}
</footer>

</body>
</html>"""
