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
| 🔍 **6 OWASP Scanner Modules** | Injection (SQLi/XSS/CMDi), Broken Access Control, Crypto Failures, Misconfig, Vulnerable Components, Auth Failures |
| 🖥️ **Web Dashboard** | React dark-themed UI with scan management, real-time WebSocket progress, and vulnerability drill-down |
| 🚀 **CI/CD Integration** | GitHub Actions + GitLab CI templates with security gates |
| 📊 **Professional Reports** | HTML dark-themed report, JSON, SARIF for code scanning |
| 🎯 **Target Profiling** | Technology fingerprinting, port scanning, HTTP method enumeration |
| ⚡ **Async Engine** | Concurrent scanner execution with rate limiting |
| 🔧 **Configurable** | YAML configs, scan profiles (quick/default/full/api/ci) |
| 🐳 **Docker Ready** | Multi-stage build with security tools pre-installed |
| 🔌 **Plugin Architecture** | Extensible scanner registry with decorator-based registration |
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

### CLI Usage

```bash
# Quick scan
auto-vapt scan https://target.com -p quick

# Full scan with all modules
auto-vapt scan https://target.com -p full -f html json

# CI/CD mode (exits non-zero on HIGH+ findings)
auto-vapt scan https://target.com --ci --format sarif

# Using a config file
auto-vapt scan https://target.com -c configs/default.yaml

# Check config validity
auto-vapt config-check configs/default.yaml

# List available profiles
auto-vapt profiles
```

### 🖥️ Web Dashboard

```bash
# Start the dashboard server
python -m uvicorn dashboard.app:app --port 8888

# Open in browser
# http://localhost:8888
```

The dashboard provides:
- **Dashboard view** — Aggregate stats, severity distribution chart, OWASP category breakdown
- **Scans view** — Full scan history with risk scores, severity counts, and pass/fail gates
- **Scan Detail** — Expandable vulnerability cards with evidence, remediation, and CVSS scores
- **New Scan** — Start scans from the browser with profile and rate limit configuration
- **Live Progress** — Real-time WebSocket updates as scanners execute

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
| `default` | 3 | 30m | 6 | Standard assessments |
| `full` | 5 | 30m | 6 | Deep penetration testing |
| `api` | 3 | 30m | 3 | API security testing |
| `ci` | 2 | 15m | 6 | CI/CD pipeline integration |

## 🔍 OWASP Coverage

| # | Category | Scanner Module | Tests |
|---|----------|---------------|-------|
| A01 | Broken Access Control | `broken_access.py` | Admin path discovery, sensitive files, path traversal, directory listing |
| A02 | Cryptographic Failures | `crypto.py` | TLS/SSL analysis, HSTS, certificate validation, cookie security |
| A03 | Injection | `injection.py` | SQL injection, XSS (reflected), command injection |
| A05 | Security Misconfiguration | `misconfig.py` | Security headers, CORS, debug endpoints, default credentials |
| A06 | Vulnerable Components | `vulnerable_components.py` | JS library CVE checking, server version analysis |
| A07 | Auth Failures | `auth_failures.py` | Brute-force, username enumeration, session management, JWT |

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
│   ├── scanners/
│   │   ├── base.py                  # BaseScanner + plugin registry
│   │   ├── profiler.py              # Target intelligence gathering
│   │   ├── injection.py             # A03: SQLi, XSS, CMDi
│   │   ├── broken_access.py         # A01: Access control testing
│   │   ├── crypto.py                # A02: TLS/SSL, HSTS, cookies
│   │   ├── misconfig.py             # A05: Headers, CORS, debug
│   │   ├── vulnerable_components.py # A06: SCA
│   │   └── auth_failures.py         # A07: Auth & session
│   └── reporting/
│       └── generator.py             # HTML report generator
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
│   └── test_models.py               # Unit tests
├── .github/workflows/
│   ├── ci.yml                       # Project CI
│   └── vapt-scan.yml                # Reusable scan workflow
├── Dockerfile                       # Multi-stage Docker build
├── docker-compose.yml               # Docker Compose setup
├── pyproject.toml                   # Poetry config
└── README.md
```

## 🛣️ Roadmap

- [ ] Web Crawler / Spider for full-site discovery
- [ ] OWASP ZAP API integration
- [ ] PDF report generation
- [ ] Rate limiter implementation
- [ ] Authenticated scanning support
- [ ] More OWASP modules (A04, A08, A09, A10)
- [ ] NVD/OSV CVE API integration
- [ ] Blind SQLi detection

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This tool is designed for **authorized security testing only**. Always obtain proper authorization before scanning any systems. Unauthorized scanning may violate laws and regulations. The authors are not responsible for misuse.
