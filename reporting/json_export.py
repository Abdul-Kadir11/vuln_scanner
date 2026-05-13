"""JSON export for scan results."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict


def export_scan_json(result: Dict[str, object], output_dir: str = "report") -> str:
    """Persist scan results as JSON and return file path."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    target = str(result.get("target", "target")).replace("://", "_").replace("/", "_")
    filename = Path(output_dir) / f"report_{target}.json"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **result,
    }
    filename.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(filename)

