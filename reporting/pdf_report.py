"""Minimal PDF report generation without external dependencies."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_simple_pdf(lines: List[str]) -> bytes:
    contents = ["BT", "/F1 10 Tf", "50 780 Td"]
    for idx, line in enumerate(lines):
        if idx > 0:
            contents.append("0 -14 Td")
        contents.append(f"({_escape_pdf_text(line)}) Tj")
    contents.append("ET")
    stream = "\n".join(contents).encode("latin-1", errors="replace")

    objects = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objects.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
    )
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
    objects.append(
        f"5 0 obj << /Length {len(stream)} >> stream\n".encode("ascii")
        + stream
        + b"\nendstream endobj\n"
    )

    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    body = bytearray(header)
    xref_offsets = [0]
    for obj in objects:
        xref_offsets.append(len(body))
        body.extend(obj)

    xref_start = len(body)
    body.extend(f"xref\n0 {len(xref_offsets)}\n".encode("ascii"))
    body.extend(b"0000000000 65535 f \n")
    for off in xref_offsets[1:]:
        body.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    body.extend(
        f"trailer << /Root 1 0 R /Size {len(xref_offsets)} >>\nstartxref\n{xref_start}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(body)


def generate_pdf_report(result: Dict[str, object], output_dir: str = "report") -> str:
    """Generate a simple PDF report and return its path."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    target = str(result.get("target", "target")).replace("://", "_").replace("/", "_")
    filename = Path(output_dir) / f"report_{target}.pdf"

    findings = result.get("findings", [])
    summary = result.get("summary", {})
    lines = [
        "Vulnerability Assessment Report",
        f"Target: {result.get('target', '-')}",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "Summary:",
        f"Critical: {summary.get('critical', 0)}  High: {summary.get('high', 0)}",
        f"Medium: {summary.get('medium', 0)}  Low: {summary.get('low', 0)}  Info: {summary.get('info', 0)}",
        "",
        "Findings:",
    ]
    for item in findings:
        lines.append(
            f"- [{item.get('severity', 'Info')}] {item.get('title', '-')}"
            f" (Risk: {item.get('risk_score', 0)})"
        )

    filename.write_bytes(_build_simple_pdf(lines))
    return str(filename)

