"""Load deterministic EMV reference hex samples from the bundled emv directory."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path


_ROW_RE = re.compile(r"<tr>(.*?)</tr>", re.DOTALL | re.IGNORECASE)
_CELL_RE = re.compile(r"<td>(.*?)</td>", re.DOTALL | re.IGNORECASE)
_TAG_RE = re.compile(r"<.*?>", re.DOTALL)
_HEX_RE = re.compile(r"^[0-9A-F]+$")

_SCHEME_MAP = {
    "visa": "VISA",
    "mastercard": "MASTERCARD",
    "amex": "AMEX",
}


def _clean_cell(value: str) -> str:
    collapsed = _TAG_RE.sub("", value)
    return " ".join(collapsed.split()).strip()


@lru_cache(maxsize=1)
def load_reference_vectors(root: str | Path | None = None) -> dict[str, dict[str, str]]:
    repo_root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    source = repo_root / "emv" / "keys.html"
    if not source.exists():
        return {}

    text = source.read_text(encoding="utf-8", errors="ignore")
    vectors: dict[str, dict[str, str]] = {}

    for row_match in _ROW_RE.finditer(text):
        cells = [_clean_cell(cell) for cell in _CELL_RE.findall(row_match.group(1))]
        if len(cells) < 9:
            continue

        scheme_label = cells[0].upper()
        short_hex = cells[6].upper()
        status = cells[7].upper()
        if not _HEX_RE.match(short_hex):
            continue

        for scheme_key, expected_label in _SCHEME_MAP.items():
            if scheme_label != expected_label or scheme_key in vectors:
                continue
            vectors[scheme_key] = {
                "scheme": scheme_key,
                "rid": cells[3],
                "index": cells[2],
                "reference_hex": short_hex,
                "cryptogram_example": short_hex[:16],
                "status": status or "UNSPECIFIED",
                "source_file": str(source),
            }

    return vectors


def get_reference_cryptogram(scheme: str) -> dict[str, str] | None:
    return load_reference_vectors().get((scheme or "").strip().lower())
