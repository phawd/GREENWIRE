#!/usr/bin/env python3
"""Review Markdown/PDF content for consistency with programmed defaults."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.configuration_manager import get_configuration_manager

REPORT_PATH = ROOT / "docs" / "REPO_CONSISTENCY_AUDIT.md"

PIN_PATTERN = re.compile(r"default\s+pin[^0-9]{0,16}([0-9]{4,12})", re.IGNORECASE)
NFC_DEFAULT_PATTERN = re.compile(r"\bnfc\b.*\bdefault\b|\bdefault\b.*\bnfc\b", re.IGNORECASE)
RFID_DEFAULT_PATTERN = re.compile(r"\brfid\b.*\bdefault\b|\bdefault\b.*\brfid\b", re.IGNORECASE)
TEST_KEY_PATTERN = re.compile(r"\btest\s+key(s)?\b", re.IGNORECASE)
PAN_DUP_PATTERN = re.compile(r"\bduplicate\b.*\bpan\b|\bpan\b.*\bduplicate\b", re.IGNORECASE)


def _iter_files(extensions: Iterable[str]) -> List[Path]:
    files: List[Path] = []
    for ext in extensions:
        files.extend(ROOT.rglob(f"*{ext}"))
    return sorted(
        path
        for path in files
        if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts
    )


def _read_pdf_text(path: Path) -> str:
    try:
        from pypdf import PdfReader  # type: ignore

        reader = PdfReader(str(path))
        chunks = []
        for page in reader.pages[:25]:
            text = page.extract_text() or ""
            chunks.append(text)
        return "\n".join(chunks)
    except Exception:
        return ""


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 5) -> List[str]:
    results: List[str] = []
    for line in text.splitlines():
        if pattern.search(line):
            results.append(line.strip())
            if len(results) >= limit:
                break
    return results


def build_audit() -> Dict[str, object]:
    cfg = get_configuration_manager().data()
    expected_pin = str(cfg.get("cards", {}).get("default_pin", "6666"))
    expected_nfc = bool(cfg.get("cards", {}).get("default_nfc_enabled", True))
    expected_rfid = bool(cfg.get("cards", {}).get("default_rfid_enabled", True))

    markdown_files = _iter_files([".md"])
    pdf_files = _iter_files([".pdf"])
    records: List[Dict[str, object]] = []
    mismatches: List[Dict[str, object]] = []

    for path in markdown_files + pdf_files:
        text = path.read_text(encoding="utf-8", errors="ignore") if path.suffix.lower() == ".md" else _read_pdf_text(path)
        record = {
            "path": str(path.relative_to(ROOT).as_posix()),
            "kind": "markdown" if path.suffix.lower() == ".md" else "pdf",
            "pin_hits": _line_hits(text, PIN_PATTERN),
            "nfc_hits": _line_hits(text, NFC_DEFAULT_PATTERN),
            "rfid_hits": _line_hits(text, RFID_DEFAULT_PATTERN),
            "test_key_hits": _line_hits(text, TEST_KEY_PATTERN),
            "pan_duplicate_hits": _line_hits(text, PAN_DUP_PATTERN),
        }
        records.append(record)

        for hit in record["pin_hits"]:
            match = PIN_PATTERN.search(hit)
            if match and match.group(1) != expected_pin:
                mismatches.append(
                    {
                        "path": record["path"],
                        "type": "default_pin",
                        "expected": expected_pin,
                        "found": match.group(1),
                        "line": hit,
                    }
                )

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "expected": {
            "default_pin": expected_pin,
            "default_nfc_enabled": expected_nfc,
            "default_rfid_enabled": expected_rfid,
            "test_keys_allowed_for_issuance": False,
            "auto_generated_pan_unique": True,
        },
        "markdown_count": len(markdown_files),
        "pdf_count": len(pdf_files),
        "records": records,
        "mismatches": mismatches,
    }


def render_markdown(audit: Dict[str, object]) -> str:
    expected = audit["expected"]
    lines = [
        "# Repo Consistency Audit",
        "",
        f"Generated: `{audit['generated_at']}`",
        "",
        "## Programmed Defaults",
        "",
        f"- default PIN: `{expected['default_pin']}`",
        f"- default NFC enabled: `{expected['default_nfc_enabled']}`",
        f"- default RFID enabled: `{expected['default_rfid_enabled']}`",
        f"- issuance test keys allowed: `{expected['test_keys_allowed_for_issuance']}`",
        f"- auto-generated PAN unique: `{expected['auto_generated_pan_unique']}`",
        "",
        "## Inventory",
        "",
        f"- Markdown files reviewed: `{audit['markdown_count']}`",
        f"- PDF files reviewed: `{audit['pdf_count']}`",
        "",
        "## Mismatches",
        "",
    ]

    mismatches: List[Dict[str, object]] = audit["mismatches"]  # type: ignore[assignment]
    if not mismatches:
        lines.append("- No explicit default PIN mismatches detected.")
    else:
        for mismatch in mismatches:
            lines.append(
                f"- `{mismatch['path']}`: expected `{mismatch['expected']}`, found `{mismatch['found']}` in `{mismatch['line']}`"
            )

    lines.extend(
        [
            "",
            "## Raw Summary (JSON)",
            "",
            "```json",
            json.dumps(
                {
                    "generated_at": audit["generated_at"],
                    "markdown_count": audit["markdown_count"],
                    "pdf_count": audit["pdf_count"],
                    "mismatch_count": len(mismatches),
                },
                indent=2,
            ),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    audit = build_audit()
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(render_markdown(audit), encoding="utf-8")
    print(f"[audit] markdown={audit['markdown_count']} pdf={audit['pdf_count']} mismatches={len(audit['mismatches'])}")
    print(f"[audit] report={REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
