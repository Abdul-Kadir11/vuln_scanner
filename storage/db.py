"""SQLite storage for scan artifacts."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable

DEFAULT_DB_PATH = "storage/scans.db"


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initialize scans table if it does not exist."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                created_at TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                findings_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_scan_result(result: Dict[str, object], db_path: str = DEFAULT_DB_PATH) -> int:
    """Persist a scan result and return row id."""
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (target, created_at, summary_json, findings_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                str(result.get("target", "")),
                datetime.now(timezone.utc).isoformat(),
                json.dumps(result.get("summary", {})),
                json.dumps(result.get("findings", [])),
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def list_recent_scans(limit: int = 20, db_path: str = DEFAULT_DB_PATH) -> Iterable[Dict[str, object]]:
    """Return recent scan metadata."""
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, target, created_at, summary_json
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "target": row["target"],
            "created_at": row["created_at"],
            "summary": json.loads(row["summary_json"]),
        }
        for row in rows
    ]

