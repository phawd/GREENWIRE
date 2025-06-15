"""Utilities for NFC-based EMV processing using nfcpy."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional, Dict, List

import nfc


DEFAULT_CA_KEYS: Dict[str, Dict[str, str]] = {
    "A000000003_92": {
        "rid": "A000000003",
        "index": "92",
        "modulus": (
            "C1D2E3F4A5B6C7D8E9F0C1D2E3F4A5B6"
            "C7D8E9F0C1D2E3F4A5B6C7D8E9F0C1D2"
        ),
        "exponent": "03",
    },
    "A000000004_FF": {
        "rid": "A000000004",
        "index": "FF",
        "modulus": (
            "D1E2F3A4B5C6D7E8F9C0D1E2F3A4B5C6"
            "D7E8F9C0D1E2F3A4B5C6D7E8F9C0D1E2"
        ),
        "exponent": "03",
    },
}


@dataclass
class CAPublicKey:
    """Simple container for a certificate authority public key."""

    rid: str
    index: str
    modulus: str
    exponent: str


def load_ca_keys(path: str) -> Dict[str, Dict[str, str]]:
    """Load CA keys from ``path`` or return ``DEFAULT_CA_KEYS`` on failure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        result = {
            f"{entry['rid']}_{entry['index']}": entry for entry in data
        }
        return result
    except Exception as exc:  # noqa: BLE001
        logging.warning("Failed to load CA keys from %s: %s", path, exc)
        return DEFAULT_CA_KEYS


class NFCEMVProcessor:
    """Perform basic EMV transactions over NFC."""

    def __init__(self, device: str = "usb") -> None:
        self.device = device

    def _connect(self) -> nfc.clf.ContactlessFrontend:
        return nfc.ContactlessFrontend(self.device)

    def read_uid(self) -> Optional[str]:
        """Return the UID of the first discovered tag or ``None``."""
        with self._connect() as clf:
            tag = clf.connect(rdwr={"on-connect": lambda tag: False})
            return tag.identifier.hex() if hasattr(tag, "identifier") else None

    def read_block(self, block: int) -> bytes:
        """Read a block from a tag that supports the ``read`` command."""
        with self._connect() as clf:
            tag = clf.connect(rdwr={"on-connect": lambda tag: False})
            if hasattr(tag, "read"):
                data = tag.read(block)
                return bytes(data)
            raise RuntimeError("Tag does not support read operation")

    def write_block(self, block: int, data: bytes) -> None:
        """Write a block of data to a tag that supports the ``write`` command."""
        with self._connect() as clf:
            tag = clf.connect(rdwr={"on-connect": lambda tag: False})
            if hasattr(tag, "write"):
                tag.write(block, data)
            else:
                raise RuntimeError("Tag does not support write operation")

    def perform_emv_transaction(self, aid: str = "A0000000031010") -> Dict[str, bytes]:
        """Select ``aid`` and issue GET PROCESSING OPTIONS.

        Returns the raw responses for the SELECT and GPO commands.
        """
        with self._connect() as clf:
            tag = clf.connect(rdwr={"on-connect": lambda tag: False})
            if not hasattr(tag, "send_apdu"):
                raise RuntimeError("Tag does not support ISO-DEP")

            aid_bytes = bytes.fromhex(aid)
            select_resp = tag.send_apdu(0x00, 0xA4, 0x04, 0x00, aid_bytes)
            gpo_resp = tag.send_apdu(0x80, 0xA8, 0x00, 0x00, b"\x83\x00")
            return {"select": bytes(select_resp), "gpo": bytes(gpo_resp)}


class ContactlessEMVTerminal:
    """Perform contactless EMV transactions for multiple AIDs."""

    def __init__(
        self,
        aids: List[str],
        ca_keys: Optional[Dict[str, CAPublicKey]] = None,
        device: str = "usb",
    ) -> None:
        self.processor = NFCEMVProcessor(device)
        self.aids = aids
        self.ca_keys = ca_keys or {
            k: CAPublicKey(**v) for k, v in DEFAULT_CA_KEYS.items()
        }

    def get_ca_key(self, rid: str) -> Optional[CAPublicKey]:
        """Return the CA key associated with ``rid`` if available."""
        return self.ca_keys.get(rid)

    def run(self) -> List[Dict[str, bytes]]:
        """Execute SELECT and GPO for each configured AID."""
        results: List[Dict[str, bytes]] = []
        for aid in self.aids:
            try:
                logging.info("[NFC] Performing EMV transaction with AID %s", aid)
                res = self.processor.perform_emv_transaction(aid)
                results.append({"aid": aid, **res})
            except Exception as exc:  # noqa: BLE001
                logging.error("EMV transaction for %s failed: %s", aid, exc)
        return results

