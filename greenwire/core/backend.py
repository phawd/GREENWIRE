import sqlite3
import hashlib
from pathlib import Path
from typing import Optional

from .emv_generator import generate_card, generate_sle_sda_certificate

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


def generate_certifications(conn: sqlite3.Connection, count: int = 5) -> list[dict]:
    """Generate ``count`` sample cards and return them."""
    count = max(5, min(10, count))
    cards = []
    for _ in range(count):
        card = issue_card(conn)
        card["sle_sda_cert"] = generate_sle_sda_certificate(card["pan"])
        cards.append(card)
    return cards
