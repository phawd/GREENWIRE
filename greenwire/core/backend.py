import sqlite3
import hashlib
import logging
from pathlib import Path
from typing import Optional

from .emv_generator import generate_card
from .nfc_iso import AndroidReaderWriter

# Secret used for hashing; in real deployments this should come from
# a secure source such as an environment variable or secrets manager.
SECRET = "GREENWIRE_SECRET"


def init_backend(db_path: str | Path = "card_data.db") -> sqlite3.Connection:
    """Initialize the backend database and return a connection."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cards ("
        "verification_code TEXT PRIMARY KEY, pan_hash TEXT UNIQUE)"
    )
    return conn


def _pan_hash(pan: str) -> str:
    """Return a salted hash of the PAN for static validation."""
    return hashlib.sha256((pan + SECRET).encode()).hexdigest()


def issue_card(
    conn: sqlite3.Connection,
    issuer: str = "TEST BANK",
    iin: str = "400000",
    pan: Optional[str] = None,
) -> dict:
    """Generate a card, store validation data, and return it."""
    card = generate_card(issuer, iin)
    if pan is not None:
        card["pan"] = pan
    pan_hash = _pan_hash(card["pan"])
    verification_code = hashlib.sha256(
        (card["pan"] + card["expiry"] + SECRET).encode()
    ).hexdigest()[:16]
    if conn.execute(
        "SELECT 1 FROM cards WHERE pan_hash = ?", (pan_hash,)
    ).fetchone():
        raise ValueError("Duplicate card detected")
    conn.execute(
        "INSERT INTO cards (verification_code, pan_hash) VALUES (?, ?)",
        (verification_code, pan_hash),
    )
    conn.commit()
    card["verification_code"] = verification_code
    return card


def is_duplicate(conn: sqlite3.Connection, pan: str) -> bool:
    """Return True if the given PAN is already stored."""
    return (
        conn.execute(
            "SELECT 1 FROM cards WHERE pan_hash = ?",
            (_pan_hash(pan),),
        ).fetchone()
        is not None
    )


def issue_contactless_card(
    conn: sqlite3.Connection,
    reader: AndroidReaderWriter | None = None,
    issuer: str = "TEST BANK",
    iin: str = "400000",
) -> dict:
    """Issue a card and write minimal data via a contactless reader."""

    card = issue_card(conn, issuer, iin)
    device = reader or AndroidReaderWriter()
    try:
        if device.connect():
            device.write_block(1, card["pan"].encode())
            device.disconnect()
    except Exception as exc:  # noqa: BLE001
        logging.warning("Contactless write failed: %s", exc)
    return card
