<div align="center">

# 🛡️ Auto-VAPT

### CI/CD Integrated Vulnerability Assessment & Penetration Testing Pipeline

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](.github/workflows/ci.yml)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010-orange.svg)](https://owasp.org/Top10/)

**Automated security scanning pipeline that detects OWASP Top 10 vulnerabilities in web applications, integrates directly into CI/CD workflows, and generates compliance-ready reports — with a real-time web dashboard for scan management.**

</div>

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    CLI / CI Entry Point                    │
│              auto-vapt scan <target> [options]             │
└──────────────┬───────────────────────────────┬───────────┘
               │                               │
    ┌──────────▼──────────┐         ┌──────────▼──────────┐
    │   Config Loader     │         │   Target Profiler    │
    │   (YAML + Pydantic) │         │   (Nmap, Headers)    │
    └──────────┬──────────┘         └──────────┬──────────┘
               │                               │
    ┌──────────▼───────────────────────────────▼──────────┐
    │              Scan Orchestrator (Async)               │
    │         Concurrent execution + rate limiting         │
    └──┬──────┬──────┬──────┬──────┬──────┬───────────────┘
       │      │      │      │      │      │
    ┌──▼─┐ ┌──▼─┐ ┌──▼─┐ ┌──▼─┐ ┌──▼─┐ ┌──▼─┐
    │A01 │ │A02 │ │A03 │ │A05 │ │A06 │ │A07 │
    │BAC │ │Cry │ │Inj │ │Mis │ │SCA │ │Aut │
    └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘ └──┬─┘
       └──────┴──────┴──────┴──────┴──────┘
                         │
    ┌────────────────────▼────────────────────────────────┐
    │              Reporting Engine                        │
    │        HTML (Dark UI) │ JSON │ SARIF                 │
    └────────────────────────┬────────────────────────────┘
                             │
    ┌────────────────────────▼────────────────────────────┐
    │           Web Dashboard (FastAPI + React)            │
    │   Scan Management │ Live Progress │ Trend Charts     │
    └─────────────────────────────────────────────────────┘
```

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **10 OWASP Scanner Modules** | Full OWASP Top 10 coverage: Injection (SQLi/XSS/CMDi + Blind SQLi), Broken Access Control, Crypto Failures, Insecure Design, Misconfig, Vulnerable Components (OSV API), Auth Failures, Data Integrity, Logging Failures, SSRF |
| 🕷️ **OWASP ZAP Integration** | Optional integration with OWASP ZAP for deep active scanning via ZAP API |
| 🖥️ **Interactive Web Dashboard** | React dark-themed UI with sidebar navigation, animated charts (donut, gauge, sparklines), scan comparison, real-time WebSocket progress, and vulnerability drill-down |
| 🚀 **CI/CD Integration** | GitHub Actions + GitLab CI templates with security gates |
| 📊 **Professional Reports** | HTML dark-themed report, JSON, PDF (WeasyPrint), SARIF for code scanning |
| 🎯 **Target Profiling** | Technology fingerprinting, port scanning, HTTP method enumeration |
| ⚡ **Async Engine** | Concurrent scanner execution with token-bucket rate limiting |
| 🔐 **Authenticated Scanning** | Bearer, cookie, basic, and form-based authentication support |
| 🔌 **Plugin System** | Load custom scanner modules from a directory at runtime |
| 📈 **Scan Diffing** | Compare two scans to track new, resolved, and unchanged vulnerabilities |
| 🔔 **Notifications** | Slack webhook, email (SMTP), and generic webhook alerts on scan completion |
| 🔧 **Configurable** | YAML configs, scan profiles (quick/default/full/api/ci) |
| 🐳 **Docker Ready** | Multi-stage build with security tools pre-installed |
| 💾 **Scan History** | SQLite-backed scan persistence with aggregate statistics |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/uchihashahin01/Auto-VAPT.git
cd Auto-VAPT

# Install with Poetry
pip install poetry
poetry install

# Install frontend dependencies
cd dashboard/frontend && npm install && npm run build && cd ../..

# Or with Docker
docker compose build
```

### Quick Launch

```bash
# Start both backend and frontend with one command
./start.sh

# Dashboard → http://localhost:5173
# API       → http://localhost:8888/api/health
```

### CLI Usage

```bash
# Quick scan
auto-vapt scan https://target.com -p quick

# Full scan with all modules + PDF report
auto-vapt scan https://target.com -p full -f html json pdf

# CI/CD mode (exits non-zero on HIGH+ findings)
auto-vapt scan https://target.com --ci --format sarif

# Authenticated scanning (with bearer token in config)
auto-vapt scan https://target.com -c configs/auth-config.yaml

# Load custom scanner plugins
auto-vapt scan https://target.com --plugins ./my-plugins/

# Compare two scans (diff)
auto-vapt diff reports/scan-old.json reports/scan-new.json

# Using a config file
auto-vapt scan https://target.com -c configs/default.yaml

# Check config validity
auto-vapt config-check configs/default.yaml

# List available profiles
auto-vapt profiles
```

### 🖥️ Web Dashboard

The dashboard runs as a **single process** — the FastAPI backend serves both the API and the React frontend.

#### Step 1: Start the Dashboard

```bash
# Make sure you're in the project directory and virtual environment is active
cd Auto-VAPT
source .venv/bin/activate

# Start the dashboard (backend + frontend served together)
python -m uvicorn dashboard.app:app --host 0.0.0.0 --port 8888
```

> **Note:** You must activate the virtual environment (`source .venv/bin/activate`) before starting the dashboard, otherwise Python cannot find the required dependencies.

#### Step 2: Open in Browser

Go to **http://localhost:8888** — you'll see the dashboard with stats cards, severity charts, and scan history.

#### Step 3: Start a Scan from the Dashboard

1. Click the **⚡ New Scan** button (top right)
2. Enter the **Target URL** (e.g. `http://testphp.vulnweb.com`)
3. Select a **Scan Profile**:
   - `quick` — 2 scanners, fast results (~10s)
   - `default` — All 6 scanners, standard depth (~60s)
   - `full` — All scanners, deep crawl (~2 min)
4. Adjust **Rate Limit** and **Timeout** if needed
5. Click **🚀 Start Scan**
6. Watch the **live progress bar** — real-time WebSocket updates show scanner status
7. When complete, click the scan row to see **full vulnerability details**

#### Dashboard Features

| View | What It Shows |
|------|--------------|
| **Dashboard** | Aggregate stats, severity bar chart, OWASP category distribution, recent scans |
| **Scans** | Complete scan history table with risk scores, severity counts (C/H/M/L), pass/fail gate |
| **Scan Detail** | Expandable vulnerability cards — click any finding to see evidence, remediation, CVSS score |
| **New Scan Modal** | Start scans with profile selection, rate limit, and timeout configuration |
| **Live Progress** | Real-time scanning progress via WebSocket as each scanner module completes |

### Docker Usage

```bash
# Run scan via Docker
docker compose run auto-vapt scan https://target.com -p quick

# With OWASP ZAP integration
docker compose up -d zap
docker compose run auto-vapt scan https://target.com -p full
```

## 📋 Scan Profiles

| Profile | Depth | Timeout | Scanners | Use Case |
|---------|-------|---------|----------|----------|
| `quick` | 1 | 10m | 2 | Fast CI checks |
| `default` | 3 | 30m | 10 | Standard assessments |
| `full` | 5 | 30m | 10 | Deep penetration testing |
| `api` | 3 | 30m | 3 | API security testing |
| `ci` | 2 | 15m | 10 | CI/CD pipeline integration |

## 🔍 OWASP Coverage

| # | Category | Scanner Module | Tests |
|---|----------|---------------|-------|
| A01 | Broken Access Control | `broken_access.py` | Admin path discovery, sensitive files, path traversal, directory listing |
| A02 | Cryptographic Failures | `crypto.py` | TLS/SSL analysis, HSTS, certificate validation, cookie security |
| A03 | Injection | `injection.py` | SQL injection (error + blind), XSS (reflected), command injection |
| A04 | Insecure Design | `insecure_design.py` | Business logic flaws, insecure defaults, missing rate limits |
| A05 | Security Misconfiguration | `misconfig.py` | Security headers, CORS, debug endpoints, default credentials |
| A06 | Vulnerable Components | `vulnerable_components.py` | JS library CVE checking, server version analysis, NVD/OSV lookup |
| A07 | Auth Failures | `auth_failures.py` | Brute-force, username enumeration, session management, JWT |
| A08 | Data Integrity Failures | `data_integrity.py` | SRI checks, insecure deserialization, unsigned updates |
| A09 | Logging & Monitoring Failures | `logging_failures.py` | Missing security headers, error disclosure, log injection |
| A10 | SSRF | `ssrf.py` | Server-side request forgery, internal service probing |

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  vapt:
    uses: ./.github/workflows/vapt-scan.yml
    with:
      target_url: "https://staging.yourapp.com"
      scan_profile: "ci"
```

### GitLab CI

```yaml
include:
  - local: 'ci-templates/gitlab-ci.yml'

vapt_scan:
  extends: .vapt-scan
  variables:
    TARGET_URL: "https://staging.yourapp.com"
```

## 📊 Report Formats

- **HTML** — Professional dark-themed interactive report with executive summary, severity breakdown, and remediation steps
- **PDF** — Printable PDF report via WeasyPrint (install with `poetry install -E pdf`)
- **JSON** — Machine-readable for integration with other tools
- **SARIF** — Static Analysis Results Interchange Format for GitHub Code Scanning

## ⚙️ Configuration

```yaml
# configs/default.yaml
profile: default
target:
  url: "https://example.com"
  exclude:
    - "*/logout*"
    - "*/static/*"

scanners:
  injection:
    enabled: true
    timeout: 300
    threads: 5
  broken_access:
    enabled: true
    timeout: 300

report:
  output_dir: "./reports"
  formats: [html, json]
  include_remediation: true

ci:
  enabled: false
  fail_on: HIGH
  max_allowed:
    CRITICAL: 0
    HIGH: 0
    MEDIUM: 10
```

## 🧪 Development

```bash
# Run tests
poetry run pytest tests/ -v

# Lint
poetry run ruff check auto_vapt/

# Type check
poetry run mypy auto_vapt/ --ignore-missing-imports

# Run dashboard in dev mode
cd dashboard/frontend && npm run dev   # Frontend at :5173
python -m uvicorn dashboard.app:app --reload --port 8888  # Backend at :8888
```

## 📁 Project Structure

```
Auto-VAPT/
├── auto_vapt/                       # Core scanner package
│   ├── __init__.py
│   ├── cli.py                       # Click CLI interface
│   ├── config.py                    # Pydantic config system
│   ├── models.py                    # Data models (Vulnerability, ScanReport)
│   ├── logger.py                    # Structured logging (structlog)
│   ├── orchestrator.py              # Async scan orchestrator
│   ├── ci.py                        # CI/CD integration helpers
│   ├── crawler.py                   # Web crawler / spider
│   ├── diff.py                      # Scan comparison / diffing
│   ├── notifications.py             # Slack, email & webhook alerts
│   ├── plugins.py                   # Plugin loader for custom scanners
│   ├── rate_limiter.py              # Token-bucket rate limiter
│   ├── scanners/
│   │   ├── base.py                  # BaseScanner + plugin registry
│   │   ├── profiler.py              # Target intelligence gathering
│   │   ├── injection.py             # A03: SQLi (error + blind), XSS, CMDi
│   │   ├── broken_access.py         # A01: Access control testing
│   │   ├── crypto.py                # A02: TLS/SSL, HSTS, cookies
│   │   ├── insecure_design.py       # A04: Insecure design patterns
│   │   ├── misconfig.py             # A05: Headers, CORS, debug
│   │   ├── vulnerable_components.py # A06: SCA + NVD/OSV CVE lookup
│   │   ├── auth_failures.py         # A07: Auth & session
│   │   ├── data_integrity.py        # A08: Data integrity failures
│   │   ├── logging_failures.py      # A09: Logging & monitoring
│   │   ├── ssrf.py                  # A10: Server-side request forgery
│   │   └── zap_scanner.py           # OWASP ZAP API integration
│   └── reporting/
│       └── generator.py             # HTML + PDF report generator
├── dashboard/                       # Web Dashboard
│   ├── app.py                       # FastAPI backend (REST + WebSocket)
│   ├── database.py                  # SQLite persistence layer
│   └── frontend/                    # React + Vite frontend
│       ├── src/
│       │   ├── App.jsx              # Main dashboard component
│       │   ├── api.js               # API service module
│       │   └── index.css            # Dark theme CSS
│       ├── index.html
│       └── package.json
├── configs/
│   └── default.yaml                 # Default scan config
├── ci-templates/
│   └── gitlab-ci.yml                # GitLab CI template
├── tests/
│   ├── test_models.py               # Unit tests
│   ├── test_integration.py          # Integration tests
│   └── test_crawler_live.py         # Live crawler tests
├── .github/workflows/
│   ├── ci.yml                       # Project CI
│   └── vapt-scan.yml                # Reusable scan workflow
├── start.sh                         # Launch backend + frontend together
├── Dockerfile                       # Multi-stage Docker build
├── docker-compose.yml               # Docker Compose setup
├── pyproject.toml                   # Poetry config
└── README.md
```

## 🛣️ Roadmap

- [x] Web Crawler / Spider for full-site discovery
- [x] OWASP ZAP API integration
- [x] PDF report generation
- [x] Rate limiter implementation
- [x] Authenticated scanning support
- [x] More OWASP modules (A04, A08, A09, A10)
- [x] NVD/OSV CVE API integration
- [x] Blind SQLi detection
- [x] Plugin system for custom scanners
- [x] Scan diffing / comparison
- [x] Notifications (Slack, email, webhooks)
- [x] Dashboard UI revamp (animated charts, compare view)
- [ ] Multi-target campaign mode
- [ ] REST API authentication for dashboard
- [ ] Historical trend analysis

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This tool is designed for **authorized security testing only**. Always obtain proper authorization before scanning any systems. Unauthorized scanning may violate laws and regulations. The authors are not responsible for misuse.
