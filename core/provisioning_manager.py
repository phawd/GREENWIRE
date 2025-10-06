"""Provisioning pipeline for secure GP/JCOP/MiFARE card material.

This module is responsible for loading the sensitive `input.json` file that
contains encrypted card personalization data, decrypting it for runtime use,
constructing provisioning bundles for different operational roles, and keeping
track of the active merchant/ATM/issuer configuration within the centralized
GREENWIRE configuration system.

All cryptographic primitives rely on the Python standard library to preserve
GREENWIRE's static distribution guarantee. The encrypted payloads are expected
to use a light-weight XOR stream derived from a passphrase and optional salt,
which is sufficient for controlled lab environments; production deployments can
extend :class:`ProvisioningManager` to integrate hardware security modules.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from hashlib import pbkdf2_hmac, sha256
from typing import Any, Dict, List, Optional

from .config import GreenwireConfig, get_config


class ProvisioningError(RuntimeError):
    """Raised when provisioning data cannot be loaded or decrypted."""


@dataclass
class ProvisioningBundle:
    """Structured payload returned by :class:`ProvisioningManager`."""

    role: str
    cards: List[Dict[str, Any]]
    hardware: Dict[str, Any]
    gp_jobs: List[Dict[str, Any]]
    jcop_jobs: List[Dict[str, Any]]
    mifare_jobs: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    cache_path: Optional[str] = None


class ProvisioningManager:
    """High-level coordinator for secure provisioning tasks."""

    def __init__(self, config: Optional[GreenwireConfig] = None) -> None:
        self.config = config or get_config()
        self._last_payload: Optional[Dict[str, Any]] = None
        self._last_metadata: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------
    def set_active_role(self, role: str) -> None:
        """Persistently set the active operational role."""

        if role not in self.config.roles.available_roles():
            raise ProvisioningError(f"Unknown role '{role}'.")

        self.config.roles.active_role = role
        settings_path = os.path.join(os.path.dirname(__file__), "..", "config", "settings.json")
        try:
            self.config.save_to_file(settings_path)
        except Exception:
            # As a safety fallback the process continues with in-memory updates.
            pass

    # ------------------------------------------------------------------
    # Input loading and decryption
    # ------------------------------------------------------------------
    def load_input(self, passphrase: Optional[str] = None) -> Dict[str, Any]:
        """Load and decrypt the secure `input.json` payload.

        Parameters
        ----------
        passphrase:
            Optional passphrase used for XOR-based encryption. When omitted, the
            manager falls back to the ``GREENWIRE_INPUT_PASSPHRASE`` environment
            variable or a zeroed key for plaintext payloads.
        """

        resolved_path = self._resolve_input_path()
        if not os.path.isfile(resolved_path):
            raise ProvisioningError(f"Provisioning input file not found: {resolved_path}")

        with open(resolved_path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)

        encryption = raw.get("encryption", {})
        payload_b64 = raw.get("payload")
        metadata = raw.get("metadata", {})
        if not payload_b64:
            raise ProvisioningError("Provisioning input missing base64 payload.")

        payload_bytes = base64.b64decode(payload_b64)
        encryption_type = encryption.get("type", "none").lower()

        decrypted_bytes = self._decrypt_payload(payload_bytes, encryption_type, encryption, passphrase)
        try:
            decrypted_json = json.loads(decrypted_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ProvisioningError("Decrypted payload is not valid UTF-8 JSON") from exc

        self._last_payload = decrypted_json
        self._last_metadata = {
            "encryption": encryption_type,
            "source": os.path.abspath(resolved_path),
            "loaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._persist_cache(decrypted_bytes)

        return decrypted_json

    # ------------------------------------------------------------------
    def build_role_bundle(self, role: Optional[str] = None, *, passphrase: Optional[str] = None) -> ProvisioningBundle:
        """Construct provisioning artefacts for a specific role."""

        role_name = role or self.config.roles.active_role
        if role_name not in self.config.roles.available_roles():
            raise ProvisioningError(f"Unknown role '{role_name}'.")

        payload = self._last_payload or self.load_input(passphrase=passphrase)
        cards = payload.get("cards", [])
        hardware_profile = self.config.roles.get_profile(role_name)

        gp_jobs: List[Dict[str, Any]] = []
        jcop_jobs: List[Dict[str, Any]] = []
        mifare_jobs: List[Dict[str, Any]] = []

        for card in cards:
            standards = card.get("standards", {})
            if gp := standards.get("globalplatform"):
                gp_jobs.append({"card_id": card.get("id"), **gp})
            if jcop := standards.get("jcop"):
                jcop_jobs.append({"card_id": card.get("id"), **jcop})
            if mifare := standards.get("mifare"):
                mifare_jobs.append({"card_id": card.get("id"), **mifare})

        metadata = {
            "role": role_name,
            "total_cards": len(cards),
            "gp_jobs": len(gp_jobs),
            "jcop_jobs": len(jcop_jobs),
            "mifare_jobs": len(mifare_jobs),
        }
        metadata.update(self._last_metadata)

        return ProvisioningBundle(
            role=role_name,
            cards=cards,
            hardware=hardware_profile,
            gp_jobs=gp_jobs,
            jcop_jobs=jcop_jobs,
            mifare_jobs=mifare_jobs,
            metadata=metadata,
            cache_path=self.config.provisioning.decrypted_cache,
        )

    # ------------------------------------------------------------------
    def bundle_summary(self, bundle: ProvisioningBundle) -> str:
        """Return a human-friendly summary for CLI/menu presentation."""

        lines = [
            f"Active role            : {bundle.role}",
            f"Hardware reader        : {bundle.hardware.get('hardware_reader', 'n/a')}",
            f"GlobalPlatform jobs    : {bundle.metadata.get('gp_jobs', 0)}",
            f"JCOP scripts           : {bundle.metadata.get('jcop_jobs', 0)}",
            f"MiFARE payloads        : {bundle.metadata.get('mifare_jobs', 0)}",
            f"Cards in payload       : {bundle.metadata.get('total_cards', 0)}",
            f"Input source           : {bundle.metadata.get('source', 'n/a')}",
            f"Loaded at              : {bundle.metadata.get('loaded_at', 'n/a')}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _resolve_input_path(self) -> str:
        candidate = self.config.provisioning.input_file
        if os.path.isabs(candidate):
            return candidate
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        return os.path.join(root, candidate)

    def _decrypt_payload(
        self,
        payload: bytes,
        encryption_type: str,
        encryption_params: Dict[str, Any],
        passphrase: Optional[str],
    ) -> bytes:
        if encryption_type == "none":
            return payload

        key_material = self._derive_key(passphrase, encryption_params)
        if not key_material:
            raise ProvisioningError("Unable to derive key for encrypted payload.")

        return bytes(b ^ key_material[i % len(key_material)] for i, b in enumerate(payload))

    def _derive_key(self, passphrase: Optional[str], encryption_params: Dict[str, Any]) -> Optional[bytes]:
        secret = passphrase or os.getenv("GREENWIRE_INPUT_PASSPHRASE", "")
        salt_b64 = encryption_params.get("salt")
        if encryption_params.get("type", "none").lower() == "xor" and salt_b64:
            salt = base64.b64decode(salt_b64)
            return pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 64)
        if secret:
            return sha256(secret.encode("utf-8")).digest()
        return None

    def _persist_cache(self, decrypted_bytes: bytes) -> None:
        cache_path = self.config.provisioning.decrypted_cache
        if not cache_path:
            return

        cache_dir = os.path.dirname(cache_path)
        if cache_dir and not os.path.isdir(cache_dir):
            os.makedirs(cache_dir, exist_ok=True)

        try:
            with open(cache_path, "wb") as handle:
                handle.write(decrypted_bytes)
            self.config.provisioning.last_loaded = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        except OSError:
            # Cache persistence is best-effort; ignore failures to keep runtime resilient.
            pass


__all__ = [
    "ProvisioningManager",
    "ProvisioningBundle",
    "ProvisioningError",
]
