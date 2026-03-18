"""Machine-bound sealing for card log records."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import secrets
from pathlib import Path
from typing import Any, Dict


_FORMAT = "gwlog-v1"


def _key_path() -> Path:
    override = os.getenv("GREENWIRE_OPERATOR_LOG_KEY")
    if override:
        return Path(override)
    return Path("data/operator_machine_key.bin")


def _load_device_secret() -> bytes:
    path = _key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_bytes()
    secret = secrets.token_bytes(32)
    path.write_bytes(secret)
    return secret


def _machine_fingerprint() -> bytes:
    identity = "|".join(
        [
            platform.node() or "unknown-node",
            platform.system() or "unknown-system",
            platform.release() or "unknown-release",
            platform.machine() or "unknown-machine",
        ]
    )
    return identity.encode("utf-8")


def _master_key() -> bytes:
    return hashlib.sha256(_load_device_secret() + _machine_fingerprint()).digest()


def _stream_xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(data, out[: len(data)]))


def seal_log_payload(payload: Dict[str, Any]) -> str:
    serialized = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    key = _master_key()
    nonce = secrets.token_bytes(16)
    ciphertext = _stream_xor(serialized, key, nonce)
    mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).hexdigest()
    return f"{_FORMAT}:{nonce.hex()}:{ciphertext.hex()}:{mac}"


def unseal_log_payload(blob: str) -> Dict[str, Any]:
    parts = blob.split(":")
    if len(parts) != 4 or parts[0] != _FORMAT:
        raise ValueError("Unsupported log blob format")
    _, nonce_hex, ciphertext_hex, mac_hex = parts
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    key = _master_key()
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac_hex):
        raise ValueError("Log blob integrity check failed")
    plaintext = _stream_xor(ciphertext, key, nonce)
    return json.loads(plaintext.decode("utf-8"))

