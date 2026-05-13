# VULNSCAN

Unified vulnerability scanner with port/service checks, CVE mapping, recon, and plugin-based checks.

## Install (Kali Linux)

```bash
git clone https://github.com/Abdul-Kadir11/vuln_scanner.git
cd vuln_scanner

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# external tooling used by recon/probing modules
sudo apt update
sudo apt install -y amass subfinder nuclei httpx-toolkit
pip install Sublist3r
```

## Run

```bash
python3 vulnscan_cli.py
python3 vulnscan_cli.py --target example.com
python3 vulnscan_cli.py --target example.com --theme default
```

`CRT` theme is now the default UI mode.

Disable boot animation if needed:

```bash
python3 vulnscan_cli.py --target example.com --no-boot
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