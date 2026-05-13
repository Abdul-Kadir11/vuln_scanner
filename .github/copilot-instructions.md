# Copilot Instructions for `vuln_scanner`

## Build, test, and lint commands

- **Run scanner (interactive):** `python vulnscan_cli.py`
- **Install dependencies:** `pip install -r requirements.txt`
- **Run all tests:** `pytest` (current `tests/` directory is empty, so this currently reports no tests)
- **Run one test:** `pytest tests/<file>.py::<test_name>`
- **Lint:** no project lint configuration/command is defined in this repo

## High-level architecture

- `vulnscan_cli.py` is the entrypoint and Rich-based UI; it collects a target, calls `core.controller.scan_target`, and renders results.
- `core/controller.py` is a thin orchestrator that delegates to `core.engine.run_scan`.
- `core/engine.py` does the core work:
  - probes a fixed `COMMON_PORTS` map via raw sockets (`scan_ports`)
  - dynamically discovers plugins from `plugins/<category>/` (`load_plugins`)
  - runs each plugin and returns a unified payload: `target`, `results`, `open_ports`, `services`
- Plugin implementations live under `plugins/network/` and `plugins/web/` and return finding dicts.
- Report/recon modules exist but are not wired into the current main scan path:
  - `report/formatter.py` and `report/html_report.py` can serialize outputs
  - `recon/nmap_scan.py` wraps `nmap` execution

## Key conventions in this codebase

- **Plugin discovery contract is module-level `Plugin`:** `core.engine.load_plugins()` only instantiates modules that expose a `Plugin` symbol (`hasattr(module, "Plugin")`). If you add or refactor plugins, preserve/export this symbol.
- **Current plugin files do not export `Plugin`:** classes are named like `FTPSecurityCheck`/`SSHSecurityCheck`; add `Plugin = <ClassName>` in each module (or adjust loader) before expecting discovery to return plugins.
- **Finding shape is dictionary-based:** plugins are expected to emit dictionaries with keys used across the codebase (`title`, `severity`, `cve`, `evidence`, `port`, `service`).
- **Input normalization is local to plugins:** most network plugins strip `http://`/`https://` from `target`; web plugin prepends `http://` if missing.
- **Plugin failures are converted to low-severity findings instead of being raised.**
- **Output filenames are target-derived:** report helpers sanitize target strings into filename-safe forms.

## MCP servers configured for this repo

- `.vscode/mcp.json` configures:
  - `github` via `@modelcontextprotocol/server-github` (expects `GITHUB_PERSONAL_ACCESS_TOKEN` in environment)
  - `playwright` via `@playwright/mcp@latest`
  - both servers are launched with `npx -y` for non-interactive startup
