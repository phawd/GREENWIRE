"""High-level interface for GREENWIRE HSM functionality.

This module centralises interactions with the local HSM emulator and the
HSM/ATM integration layer so that the classic CLI, the modern CLI, and the
menu-driven UI all share a consistent implementation.  It focuses on
realistic key storage, generation, and cryptographic helper operations that
mirror common payment HSM workflows (key management, MAC generation,
cryptogram processing, PIN services, etc.).
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:
    from Crypto.Cipher import DES3
except Exception:  # pragma: no cover - optional dependency for KCV
    DES3 = None

from hsm.thales_emulator import ThalesEmulator
from modules.hsm_atm_integration import HSMATMIntegration


@dataclass
class KeyRecord:
    """Metadata stored for each generated/imported key."""

    label: str
    key: str  # hex encoded
    length: int
    kcv: str
    created: str
    usage: Optional[str] = None
    integration_slot: Optional[str] = None

    def masked_key(self) -> str:
        """Return a truncated representation that hides most of the key."""

        if len(self.key) <= 12:
            return self.key
        return f"{self.key[:8]}…{self.key[-4:]}"


class HSMService:
    """Wrapper combining the Thales emulator and HSM/ATM integration layer."""

    DEFAULT_KEYSET: Iterable[Dict[str, Optional[str]]] = (
        {
            "label": "TMK",
            "length": 32,
            "usage": "Terminal Master Key",
            "integration_slot": None,
        },
        {
            "label": "ZMK",
            "length": 32,
            "usage": "Zone Master Key",
            "integration_slot": None,
        },
        {
            "label": "ZPK",
            "length": 16,
            "usage": "Zone PIN Key",
            "integration_slot": "pin_key",
        },
        {
            "label": "CVK",
            "length": 16,
            "usage": "Card Verification Key",
            "integration_slot": "cvv_key",
        },
        {
            "label": "IMK",
            "length": 16,
            "usage": "Issuer Master Key",
            "integration_slot": "mac_key",
        },
        {
            "label": "DEK",
            "length": 32,
            "usage": "Data Encryption Key",
            "integration_slot": "data_key",
        },
    )

    def __init__(self, store_path: Path | str = Path("data/hsm_keystore.json")) -> None:
        self.store_path = Path(store_path)
        self.store_path.parent.mkdir(parents=True, exist_ok=True)

        self._emulator = ThalesEmulator()
        self._integration = HSMATMIntegration()
        self._store: Dict[str, KeyRecord] = {}

        self._load_store()
        self._sync_store_with_emulator()

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _load_store(self) -> None:
        if not self.store_path.exists():
            return

        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}

        for label, payload in data.items():
            if not isinstance(payload, dict):
                continue

            key_hex = payload.get("key")
            if not key_hex:
                continue

            try:
                key_bytes = bytes.fromhex(key_hex)
            except ValueError:
                continue

            self._emulator.import_key(label, key_bytes)
            self._store[label] = KeyRecord(
                label=label,
                key=key_hex.upper(),
                length=len(key_bytes),
                kcv=payload.get("kcv", self._compute_kcv(key_bytes)),
                created=payload.get("created", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"),
                usage=payload.get("usage"),
                integration_slot=payload.get("integration_slot"),
            )

        self._sync_integration_keys()

    def _persist_store(self) -> None:
        serialised = {
            label: {
                "key": record.key,
                "length": record.length,
                "kcv": record.kcv,
                "created": record.created,
                "usage": record.usage,
                "integration_slot": record.integration_slot,
            }
            for label, record in self._store.items()
        }

        self.store_path.write_text(json.dumps(serialised, indent=2), encoding="utf-8")

    def _sync_store_with_emulator(self) -> None:
        for label in self._emulator.list_keys():
            if label in self._store:
                continue

            key_bytes = self._emulator.export_key(label)
            if not key_bytes:
                continue

            record = self._create_record(label, key_bytes)
            self._store[label] = record

        self._sync_integration_keys()
        self._persist_store()

    def _sync_integration_keys(self) -> None:
        for record in self._store.values():
            slot = record.integration_slot
            if not slot:
                continue

            try:
                self._integration.master_keys[slot] = bytes.fromhex(record.key)
            except Exception:
                # The integration layer tolerates mocked values even when crypto
                # libraries are unavailable, so failures can be ignored.
                continue

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def generate_key(
        self,
        label: str,
        length: int = 16,
        *,
        usage: Optional[str] = None,
        integration_slot: Optional[str] = None,
        overwrite: bool = False,
    ) -> KeyRecord:
        if not overwrite and label in self._store:
            raise ValueError(f"Key label '{label}' already exists. Use overwrite=True to replace it.")

        self._emulator.generate_key(label, length)
        key_bytes = self._emulator.export_key(label)
        if key_bytes is None:
            raise RuntimeError("Failed to retrieve generated key material from emulator")

        record = self._create_record(label, key_bytes, usage=usage, integration_slot=integration_slot)
        self._store[label] = record
        self._sync_integration_keys()
        self._persist_store()
        return record

    def generate_default_keyset(self, overwrite: bool = True) -> List[KeyRecord]:
        records: List[KeyRecord] = []
        for definition in self.DEFAULT_KEYSET:
            record = self.generate_key(
                definition["label"],
                definition["length"],
                usage=definition.get("usage"),
                integration_slot=definition.get("integration_slot"),
                overwrite=overwrite,
            )
            records.append(record)
        return records

    def list_keys(self) -> List[KeyRecord]:
        return sorted(self._store.values(), key=lambda rec: rec.label)

    def export_key(self, label: str, output_path: Optional[Path | str] = None) -> KeyRecord:
        if label not in self._store:
            key_bytes = self._emulator.export_key(label)
            if not key_bytes:
                raise KeyError(f"Key '{label}' not found")
            self._store[label] = self._create_record(label, key_bytes)
            self._persist_store()

        record = self._store[label]

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"label": record.label, "key": record.key, "kcv": record.kcv}
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        return record

    # ------------------------------------------------------------------
    # Cryptographic helpers
    # ------------------------------------------------------------------

    def generate_mac(self, key_label: str, data: bytes, algorithm: str = "des3") -> str:
        return self._emulator.generate_mac(key_label, data, algorithm=algorithm)

    def generate_arqc(self, master_key_label: str, pan: str, atc: int, data: bytes) -> str:
        return self._emulator.generate_arqc(master_key_label, pan, atc, data)

    def verify_arqc(
        self,
        key_label: str,
        arqc: bytes,
        data: bytes,
        *,
        pan: Optional[str] = None,
        atc: Optional[int] = None,
    ) -> bool:
        return self._emulator.verify_arqc(key_label, arqc, data, pan=pan, atc=atc)

    def generate_arpc(
        self,
        master_key_label: str,
        pan: str,
        atc: int,
        arqc: bytes,
        issuer_response: bytes = b"\x00\x00",
    ) -> str:
        return self._emulator.generate_arpc(master_key_label, pan, atc, arqc, issuer_response)

    def generate_pin_block(self, pin: str, pan: str, *, pin_format: str = "ISO-0") -> bytes:
        return self._emulator.generate_pin_block(pin, pan, format=pin_format)

    def verify_pin(self, entered_pin: str, stored_pin_hash: str) -> bool:
        return self._emulator.verify_pin(entered_pin, stored_pin_hash)

    def translate_pin(
        self,
        card_id: str,
        encrypted_pin_hex: str,
        source_key_id: str,
        dest_key_id: str,
    ) -> Dict[str, Optional[str]]:
        encrypted_pin = bytes.fromhex(encrypted_pin_hex)
        success, translated, message = self._integration.hsm_pin_translate(
            card_id, encrypted_pin, source_key_id, dest_key_id
        )

        return {
            "success": success,
            "message": message,
            "translated_pin_block": translated.hex().upper() if translated else None,
        }

    def generate_cvv(self, pan: str, expiry: str, service_code: str) -> str:
        return self._integration.generate_cvv(pan, expiry, service_code)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_kcv(key_bytes: bytes) -> str:
        try:
            if DES3 is None or len(key_bytes) not in (8, 16, 24):
                raise ValueError("DES3 unavailable")

            if len(key_bytes) == 8:
                des3_key = key_bytes * 3
            elif len(key_bytes) == 16:
                des3_key = key_bytes + key_bytes[:8]
            else:
                des3_key = key_bytes[:24]

            cipher = DES3.new(des3_key, DES3.MODE_ECB)
            return cipher.encrypt(b"\x00" * 8)[:3].hex().upper()
        except Exception:
            return hashlib.sha1(key_bytes).digest()[:3].hex().upper()

    def _create_record(
        self,
        label: str,
        key_bytes: bytes,
        *,
        usage: Optional[str] = None,
        integration_slot: Optional[str] = None,
    ) -> KeyRecord:
        key_hex = key_bytes.hex().upper()
        record = KeyRecord(
            label=label,
            key=key_hex,
            length=len(key_bytes),
            kcv=self._compute_kcv(key_bytes),
            created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            usage=usage,
            integration_slot=integration_slot,
        )
        return record


__all__ = ["HSMService", "KeyRecord"]
