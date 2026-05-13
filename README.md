# VULNSCAN

Modular Flask-based vulnerability assessment engine with safe evidence-based checks, risk scoring, compliance mapping, and PDF/JSON reporting.

## Safety Notice

Only scan systems you own or have permission to test.

## Project Structure

```text
vuln-scanner/
├── app.py
├── scanner/
│   ├── ports.py
│   ├── http_checks.py
│   ├── tls_checks.py
│   ├── dns_checks.py
│   ├── web_app_checks.py
│   ├── api_checks.py
│   └── evidence.py
├── intelligence/
│   ├── risk_engine.py
│   ├── nvd_client.py
│   ├── kev_parser.py
│   └── vuln_mapper.py
├── reporting/
│   ├── pdf_report.py
│   └── json_export.py
└── storage/
    └── db.py
```

## Install

```bash
git clone https://github.com/Abdul-Kadir11/vuln_scanner.git
cd vuln_scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run Flask API

```bash
python3 app.py
```

Server default: `http://127.0.0.1:5000`

Dashboard: `GET /`

## API Usage

### Scan target

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "internet_exposed": true,
    "generate_pdf": true,
    "generate_json": true,
    "use_nvd_lookup": false
  }'
```

Optional auth context for authenticated/passive scans:

```json
{
  "auth_context": {
    "bearer_token": "TOKEN",
    "headers": {"X-Api-Key": "KEY"},
    "cookies": {"sessionid": "VALUE"},
    "basic_auth": {"username": "user", "password": "pass"},
    "verify_tls": true
  }
}
```

Distributed multi-target scanning:

```bash
curl -X POST http://127.0.0.1:5000/api/scan/distributed \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["example.com", "iana.org"],
    "workers": 2,
    "generate_pdf": false,
    "generate_json": false
  }'
```

### Response shape

```json
{
  "target": "example.com",
  "findings": [],
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "scan_metadata": {
    "open_ports": [],
    "http_checked_url": null,
    "dns_records": {},
    "tls_expiry_days": null,
    "web_app": {},
    "api_docs": []
  },
  "json_report_path": "report/report_example.com.json",
  "pdf_report_path": "report/report_example.com.pdf",
  "scan_id": 1
}
```

## Scanner Coverage

- TCP connect scan on ports `21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080`
- HTTP security header checks:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
- TLS checks:
  - certificate validity and expiry
  - hostname match
  - self-signed detection
- DNS checks:
  - `A` and `MX` resolution
  - missing `SPF` and `DMARC` detection
- Passive web app checks:
  - server banner exposure
  - cookie flag review (`Secure`, `HttpOnly`)
  - directory listing signal
  - `robots.txt` / `.well-known/security.txt` availability
- Passive API checks:
  - OpenAPI/Swagger discovery (`/openapi.json`, `/swagger.json`, `/v3/api-docs`)
  - permissive CORS policy signals
  - differential analyzer (baseline request -> modified request -> response comparison)
- Deep web scanning:
  - depth-limited same-origin crawling
  - safe path discovery checks for exposed sensitive endpoints/files

## Enrichment Pipeline

`service -> version -> CVEs -> KEV flag -> boosted risk`

- Service/version collected during scan
- CVEs mapped via local signatures and optional NVD lookup
- KEV flag applied from CISA KEV feed
- Risk score boosted automatically when `known_exploited=true`
- Exploit validation is supported in **safe non-invasive mode only** (fingerprint correlation, no active exploit payloads)

## Risk Engine

Risk score is normalized to `0-100` and uses:

- base CVSS
- `+25` if known exploited
- `+15` if internet-facing
- `+10` for critical ports

Severity levels: `Critical`, `High`, `Medium`, `Low`, `Info`.

## Reporting and Storage

- JSON exports: `reporting/json_export.py`
- PDF report generation: `reporting/pdf_report.py`
- SQLite scan persistence: `storage/db.py` (`storage/scans.db`)

## Legacy CLI

The original CLI scanner entrypoint (`vulnscan_cli.py`) remains in the repository for backward compatibility.