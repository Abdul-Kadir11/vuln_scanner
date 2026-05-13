# VULNSCAN

Unified vulnerability scanner with port/service checks, CVE mapping, recon, and plugin-based checks.

## Run

```bash
python3 vulnscan_cli.py
python3 vulnscan_cli.py --target example.com
```

## Advanced Tooling (Phase 1)

The scanner now integrates:

- `Sublist3r` (subdomain enumeration)
- `subfinder` (subdomain enumeration)
- `amass` (passive subdomain enumeration)
- `httpx` (live endpoint probing)
- `nuclei` (template-based vulnerability detection)

If a binary is missing, the scan continues and reports that tool as unavailable.

## CLI Toggles

Disable specific advanced tools:

```bash
python3 vulnscan_cli.py --target example.com --disable-tool amass --disable-tool nuclei
```

Disable recon enumeration tools (`Sublist3r`, `subfinder`, `amass`):

```bash
python3 vulnscan_cli.py --target example.com --no-recon
```