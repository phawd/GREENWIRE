"""Minimal Thales-like HSM emulator for local rehearsals.

This is intentionally small: it simulates key storage, key wrapping/unwrapping,
MAC generation and ARQC verification stubs. All operations are local and
non-secure — intended for testing and CI only.

Usage:
  from hsm.thales_emulator import ThalesEmulator
  h = ThalesEmulator()
  k = h.generate_key("ZMK", length=16)
  mac = h.generate_mac(k, b"payload")
"""
from __future__ import annotations

import os
from typing import Dict, Optional

try:
    from Crypto.Cipher import DES3
except Exception:  # pragma: no cover - runtime optional dependency
    DES3 = None


class ThalesEmulator:
    def __init__(self):
        # key storage: label -> key bytes
        self._keys: Dict[str, bytes] = {}

    def generate_key(self, label: str, length: int = 16) -> str:
        """Generate a symmetric key and store it under label. Returns label."""
        key = os.urandom(length)
        self._keys[label] = key
        return label

    def import_key(self, label: str, key_bytes: bytes) -> str:
        self._keys[label] = key_bytes
        return label

    def export_key(self, label: str) -> Optional[bytes]:
        return self._keys.get(label)

    def generate_mac(self, key_label: str, data: bytes, algorithm: str = "des3") -> str:
        key = self._keys.get(key_label)
        if key is None:
            raise KeyError("Unknown key label")
        # Implement ISO 9797 MAC (Retail MAC / ISO9797-1 MAC Algorithm 3 with DES-EDE)
        if algorithm.lower() not in ("des3", "3des", "iso9797"):
            raise ValueError("Unsupported algorithm; supported: des3/iso9797")

        if DES3 is None:
            raise RuntimeError("PyCryptodome is required for 3DES MAC (install pycryptodome)")

        # EMV/Thales often uses Retail MAC: DES3 in CBC mode with zero IV, and final (8-byte) chaining value.
        # Key length may be 8, 16, or 24 bytes. If 16 bytes, it is DES-EDE2 (K1,K2,K1).
        klen = len(key)
        if klen not in (8, 16, 24):
            raise ValueError("Invalid key length for DES3 MAC; expected 8/16/24 bytes")

        # Pad data per ISO9797-1 Method 2 (bit '1' followed by zeros) then encrypt with 3DES CBC (IV=0)
        # Build padding
        pad_len = 8 - (len(data) % 8) if (len(data) % 8) != 0 else 8
        padded = data + b"\x80" + b"\x00" * (pad_len - 1)

        # Use DES3 from PyCryptodome; DES3 expects a 16 or 24 byte key for EDE2/EDE3. If 8 bytes, expand to 16 (K,K,K)
        if klen == 8:
            des3_key = key * 3
        elif klen == 16:
            des3_key = key + key[:8]
        else:
            des3_key = key

        cipher = DES3.new(des3_key, DES3.MODE_CBC, iv=b"\x00" * 8)
        mac = cipher.encrypt(padded)[-8:]
        return mac.hex().upper()

    def _compute_3des_mac_from_key(self, key_bytes: bytes, data: bytes) -> bytes:
        """Compute 3DES Retail MAC directly from key bytes and data. Returns raw 8-byte MAC."""
        if DES3 is None:
            raise RuntimeError("PyCryptodome is required for 3DES MAC (install pycryptodome)")

        klen = len(key_bytes)
        if klen not in (8, 16, 24):
            raise ValueError("Invalid key length for DES3 MAC; expected 8/16/24 bytes")

        pad_len = 8 - (len(data) % 8) if (len(data) % 8) != 0 else 8
        padded = data + b"\x80" + b"\x00" * (pad_len - 1)

        if klen == 8:
            des3_key = key_bytes * 3
        elif klen == 16:
            des3_key = key_bytes + key_bytes[:8]
        else:
            des3_key = key_bytes

        cipher = DES3.new(des3_key, DES3.MODE_CBC, iv=b"\x00" * 8)
        mac = cipher.encrypt(padded)[-8:]
        return mac

    def derive_emv_session_key(self, master_key_label: str, pan: str, atc: int) -> bytes:
        """Derive a simple EMV session key from a stored master key, PAN and ATC.

        This implementation uses a simplified test KDF for deterministic testing.
        NOT PRODUCTION EMV COMPLIANT - uses SHA256 hash of master||pan||atc truncated to 16 bytes.
        For production, use proper EMV session key derivation algorithms.
        """
        master = self._keys.get(master_key_label)
        if master is None:
            raise KeyError("Unknown master key label")

        # Normalize PAN (digits only) and ATC (2 bytes)
        pan_digits = ''.join([c for c in pan if c.isdigit()])
        atc_bytes = atc.to_bytes(2, "big")

        # Simplified test KDF: SHA256(master || pan_digits || atc_bytes)[:16]
        import hashlib
        combined = master + pan_digits.encode('ascii') + atc_bytes
        key = hashlib.sha256(combined).digest()[:16]
        return key

    def generate_arqc(self, master_key_label: str, pan: str, atc: int, data: bytes) -> str:
        """Generate an ARQC-like cryptogram by deriving a session key and MACing the data.

        Args:
            master_key_label: label of the stored master key (bytes)
            pan: card PAN string
            atc: application transaction counter (int)
            data: transaction data bytes (as used for MAC)

        Returns:
            Uppercase hex string of 8-byte MAC (ARQC)
        """
        session_key = self.derive_emv_session_key(master_key_label, pan, atc)
        mac = self._compute_3des_mac_from_key(session_key, data)
        return mac.hex().upper()

    def generate_pin_block(self, pin: str, pan: str, format: str = "ISO-0") -> bytes:
        """Generate a PIN block.

        Currently supports ISO-0 (ISO 9564-1) format. Returns 8-byte PIN block.
        """
        # ISO-0 PIN block
        if format != "ISO-0":
            raise ValueError("Only ISO-0 PIN block format is supported in this emulator")

        if not pin.isdigit() or not (4 <= len(pin) <= 12):
            raise ValueError("PIN must be numeric and between 4 and 12 digits")

        # Build PIN field: 1 digit length nibble + PIN digits, padded with 0xF
        pin_len = len(pin)
        pin_nibbles = f"{pin_len:X}" + pin
        # pad to 16 nibbles
        pin_nibbles = pin_nibbles.ljust(16, 'F')
        pin_field = bytes.fromhex(pin_nibbles)

        # Build PAN field: take 12 rightmost digits excluding the check digit
        pan_digits = ''.join([c for c in pan if c.isdigit()])
        if len(pan_digits) < 13:
            pan12 = pan_digits.zfill(12)
        else:
            pan12 = pan_digits[-13:-1]
        pan_field_nibbles = pan12.rjust(16, '0')
        pan_field = bytes.fromhex(pan_field_nibbles)

        # XOR to produce PIN block
        pin_block = bytes(a ^ b for a, b in zip(pin_field, pan_field))
        return pin_block

    def generate_arpc(self, master_key_label: str, pan: str, atc: int, arqc: bytes, issuer_response: bytes = b"\x00\x00") -> str:
        """Generate a simple ARPC (Issuer Response Cryptogram) using the session key.

        This is a test-friendly ARPC: ARPC = MAC(session_key, ARQC || issuer_response)
        Returns uppercase hex string of 8-byte MAC.
        """
        session_key = self.derive_emv_session_key(master_key_label, pan, atc)
        payload = arqc + issuer_response
        mac = self._compute_3des_mac_from_key(session_key, payload)
        return mac.hex().upper()

    def verify_pin(self, entered_pin: str, stored_pin_hash: str) -> bool:
        """Verify PIN against a stored PIN hash inside the HSM.

        This simulates what an HSM would do for PIN verification by comparing
        a secure hash (SHA-256) of the presented PIN to the stored value.
        """
        import hashlib
        try:
            h = hashlib.sha256(entered_pin.encode()).hexdigest()
            return h == stored_pin_hash
        except Exception:
            return False

    def verify_arqc(self, key_label: str, arqc: bytes, data: bytes, pan: str = None, atc: int = None) -> bool:
        """Verify an ARQC-like MAC.

        This function first attempts to verify using the direct stored key (legacy
        behavior). If that fails (e.g., invalid DES3 key parity or degeneracy)
        it will return False. If pan and atc are provided, it will derive a
        session key and verify against that instead.
        """
        # If pan/atc provided, verify using derived session key
        if pan is not None and atc is not None:
            try:
                session_key = self.derive_emv_session_key(key_label, pan, atc)
                expected_mac = self._compute_3des_mac_from_key(session_key, data)
                return expected_mac.hex().upper() == arqc.hex().upper()
            except Exception:
                return False

        try:
            expected = self.generate_mac(key_label, data)
        except Exception:
            # Legacy verification may fail due to key parity/degeneracy issues.
            return False

        return expected == arqc.hex().upper()

    def list_keys(self) -> list[str]:
        return list(self._keys.keys())


_DEFAULT = None


def get_default_emulator() -> ThalesEmulator:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = ThalesEmulator()
    return _DEFAULT


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run a minimal Thales-like HSM emulator CLI")
    parser.add_argument("action", choices=["genkey", "list", "mac", "export"], help="Action")
    parser.add_argument("label", help="Key label")
    parser.add_argument("data", nargs="?", help="Hex data for MAC or import/export")
    args = parser.parse_args()

    emu = get_default_emulator()
    if args.action == "genkey":
        emu.generate_key(args.label)
        print(f"Generated key: {args.label}")
    elif args.action == "list":
        print("Keys:", emu.list_keys())
    elif args.action == "mac":
        if not args.data:
            print("Mac action requires data (hex)")
        else:
            data = bytes.fromhex(args.data)
            print(emu.generate_mac(args.label, data))
    elif args.action == "export":
        k = emu.export_key(args.label)
        if k is None:
            print("Key not found")
        else:
            print(k.hex())
