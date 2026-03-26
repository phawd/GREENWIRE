from __future__ import annotations

"""Simple NFC/RFID vulnerability scanning helpers."""

from typing import List, Dict

from greenwire.core.nfc_iso import _BaseReaderWriter

DEFAULT_MIFARE_KEYS: List[bytes] = [
    bytes.fromhex("FFFFFFFFFFFF"),
    bytes.fromhex("000000000000"),
    bytes.fromhex("A0A1A2A3A4A5"),
    bytes.fromhex("B0B1B2B3B4B5"),
]


def _try_key(reader: _BaseReaderWriter, block: int, key: bytes) -> bool:
    try:
        return reader.authenticate(block, key)
    except Exception:
        return False


def scan_nfc_vulnerabilities(
    reader: _BaseReaderWriter,
) -> List[Dict[str, object]]:
    """Check a connected NFC tag for common weaknesses."""
    vulns: List[Dict[str, object]] = []

    found_keys = [
        k.hex()
        for k in DEFAULT_MIFARE_KEYS
        if _try_key(reader, 0, k)
    ]
    if found_keys:
        vulns.append({"type": "DEFAULT_KEY", "keys": found_keys})

    try:
        if reader.read_block(4):
            vulns.append({"type": "UNPROTECTED_BLOCK", "block": 4})
    except Exception:
        pass

    return vulns
