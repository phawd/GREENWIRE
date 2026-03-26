"""
GlobalPlatform SCP02 and SCP03 secure channel cryptographic primitives.

Implemented from the GlobalPlatform Card Specification v2.3 (public standard):
  - SCP02: Annex E (3DES-based session keys, cryptograms, C-MAC)
  - SCP03: Amendment D (AES-CMAC-based session keys and cryptograms)

No code derived from any existing implementation. All algorithms sourced
exclusively from the GlobalPlatform public specification documents.
"""

from __future__ import annotations

import os
import struct
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _TripleDES
    from cryptography.hazmat.primitives.ciphers import algorithms
    algorithms.TripleDES = _TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _des3_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """Single-block 3DES ECB encrypt (key must be 16 or 24 bytes)."""
    if len(key) == 16:
        key = key + key[:8]  # expand to 24-byte 3DES key
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def _des3_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) == 16:
        key = key + key[:8]
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def _des3_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) == 16:
        key = key + key[:8]
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def _aes_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key), backend=default_backend())
    c.update(data)
    return c.finalize()


def _iso7816_pad(data: bytes, block_size: int = 8) -> bytes:
    """ISO/IEC 7816-4 padding: append 0x80 then zero bytes to block boundary."""
    padded = data + b'\x80'
    remainder = len(padded) % block_size
    if remainder:
        padded += b'\x00' * (block_size - remainder)
    return padded


# ---------------------------------------------------------------------------
# SCP02 (GP spec §E.4 — 3DES)
# ---------------------------------------------------------------------------

class SCP02Session:
    """
    GlobalPlatform SCP02 secure channel session.

    Key derivation and cryptogram algorithms are defined in
    GlobalPlatform Card Specification v2.3, Annex E.
    """

    # Derivation constants (GP spec Table E-1)
    _DERIV_ENC = b'\x01\x82'
    _DERIV_MAC = b'\x01\x01'
    _DERIV_DEK = b'\x01\x81'
    _DERIV_RMAC = b'\x01\x02'

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) not in (16, 24):
            raise ValueError("SCP02 master key must be 16 or 24 bytes")
        self.master_key = master_key
        self.seq_counter: bytes = b''
        self.s_enc: bytes = b''
        self.s_mac: bytes = b''
        self.s_dek: bytes = b''
        self.s_rmac: bytes = b''
        self.mac_chaining_value: bytes = b'\x00' * 8

    # ------------------------------------------------------------------
    # Session key derivation  (GP spec §E.4.2)
    # ------------------------------------------------------------------

    def _derive_key(self, constant: bytes, seq: bytes) -> bytes:
        """Derive a 16-byte session key using a derivation constant + sequence counter."""
        # Derivation data: constant (2B) + 0x000000000000000000000000 + seq (2B) padded to 16B
        deriv_data = constant + b'\x00' * 12 + seq
        assert len(deriv_data) == 16
        return _des3_ecb_encrypt(self.master_key, deriv_data)

    def derive_session_keys(self, seq_counter: bytes) -> None:
        """Derive all four SCP02 session keys from the sequence counter."""
        if len(seq_counter) != 2:
            raise ValueError("Sequence counter must be 2 bytes")
        self.seq_counter = seq_counter
        self.s_enc  = self._derive_key(self._DERIV_ENC,  seq_counter)
        self.s_mac  = self._derive_key(self._DERIV_MAC,  seq_counter)
        self.s_dek  = self._derive_key(self._DERIV_DEK,  seq_counter)
        self.s_rmac = self._derive_key(self._DERIV_RMAC, seq_counter)

    # ------------------------------------------------------------------
    # Cryptogram computation  (GP spec §E.4.3 / §E.4.4)
    # ------------------------------------------------------------------

    def _full_3des_mac(self, key: bytes, data: bytes, iv: bytes = b'\x00' * 8) -> bytes:
        """Full 3DES MAC (ISO 9797-1 Algorithm 3) over padded data."""
        padded = _iso7816_pad(data, 8)
        # Single-DES CBC with left half of key, then final 3DES block
        left_key  = key[:8]
        right_key = key[8:16] if len(key) >= 16 else key[:8]
        # Encrypt all blocks with single DES except last
        result = iv
        for i in range(0, len(padded) - 8, 8):
            block = bytes(a ^ b for a, b in zip(padded[i:i+8], result))
            des_enc = Cipher(algorithms.TripleDES(left_key * 3), modes.ECB(), backend=default_backend())
            e = des_enc.encryptor()
            result = e.update(block) + e.finalize()
        # Final block: full 3DES
        last = bytes(a ^ b for a, b in zip(padded[-8:], result))
        return _des3_ecb_encrypt(key, last)

    def compute_card_cryptogram(self, host_challenge: bytes,
                                 card_challenge: bytes) -> bytes:
        """
        Verify the card cryptogram supplied in INITIALIZE UPDATE response.
        Returns the expected 8-byte cryptogram.
        data = host_challenge(8) || seq_counter(2) || card_challenge(6)
        """
        data = host_challenge + self.seq_counter + card_challenge
        return self._full_3des_mac(self.s_enc, data)

    def compute_host_cryptogram(self, host_challenge: bytes,
                                 card_challenge: bytes) -> bytes:
        """
        Compute the 8-byte host cryptogram for EXTERNAL AUTHENTICATE.
        data = seq_counter(2) || card_challenge(6) || host_challenge(8)
        """
        data = self.seq_counter + card_challenge + host_challenge
        return self._full_3des_mac(self.s_enc, data)

    def compute_c_mac(self, apdu_header: bytes, data: bytes) -> bytes:
        """
        Compute C-MAC over apdu_header || data using chaining value.
        Updates the MAC chaining value.
        """
        mac_input = self.mac_chaining_value + apdu_header + data
        mac = self._full_3des_mac(self.s_mac, mac_input, iv=b'\x00' * 8)
        self.mac_chaining_value = mac
        return mac

    def wrap_apdu(self, cla: int, ins: int, p1: int, p2: int,
                  data: bytes = b'') -> bytes:
        """Wrap a command APDU with SCP02 C-MAC security (i-level 01)."""
        secured_cla = cla | 0x04
        header = bytes([secured_cla, ins, p1, p2, len(data) + 8])
        mac = self.compute_c_mac(header[:4], data)
        lc = len(data) + 8
        return bytes([secured_cla, ins, p1, p2, lc]) + data + mac

    def encrypt_data(self, plaintext: bytes) -> bytes:
        """Encrypt data field with S-DEK (for key transport, STORE DATA)."""
        padded = _iso7816_pad(plaintext, 8)
        return _des3_cbc_encrypt(self.s_enc, b'\x00' * 8, padded)

    @staticmethod
    def generate_host_challenge() -> bytes:
        """Generate an 8-byte random host challenge."""
        return os.urandom(8)

    def build_initialize_update(self, host_challenge: bytes,
                                 key_version: int = 0) -> bytes:
        """Build the INITIALIZE UPDATE APDU command bytes."""
        return bytes([0x80, 0x50, key_version, 0x00, 0x08]) + host_challenge + b'\x00'

    def parse_initialize_update_response(self, response: bytes) -> dict:
        """
        Parse 28-byte INITIALIZE UPDATE response.
        Returns dict with: key_diversification, key_version, scp_id,
                           seq_counter, card_challenge, card_cryptogram
        """
        if len(response) < 28:
            raise ValueError(f"INITIALIZE UPDATE response too short: {len(response)} bytes")
        return {
            "key_diversification": response[0:10],
            "key_version":         response[10],
            "scp_id":              response[11],
            "seq_counter":         response[12:14],
            "card_challenge":      response[14:20],
            "card_cryptogram":     response[20:28],
        }

    def build_external_authenticate(self, host_cryptogram: bytes,
                                     security_level: int = 0x01) -> bytes:
        """
        Build EXTERNAL AUTHENTICATE APDU.
        security_level: 0x01=C-MAC, 0x03=C-MAC+C-ENC, 0x11=R-MAC
        """
        header = bytes([0x84, 0x82, security_level, 0x00, 0x10])
        mac = self.compute_c_mac(header[:4], host_cryptogram)
        return header + host_cryptogram + mac


# ---------------------------------------------------------------------------
# SCP03 (GP spec Amendment D — AES/CMAC)
# ---------------------------------------------------------------------------

class SCP03Session:
    """
    GlobalPlatform SCP03 secure channel session.

    Algorithms defined in GlobalPlatform Card Specification v2.3
    Amendment D (SCP03), sections 6 and 7.
    """

    # Key derivation label constants (GP SCP03 spec §6.2.1)
    _LABEL_ENC  = 0x04
    _LABEL_MAC  = 0x06
    _LABEL_RMAC = 0x07
    _LABEL_DEK  = 0x08

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) not in (16, 24, 32):
            raise ValueError("SCP03 master key must be 16, 24, or 32 bytes")
        self.master_key = master_key
        self.s_enc:  bytes = b''
        self.s_mac:  bytes = b''
        self.s_rmac: bytes = b''
        self.s_dek:  bytes = b''
        self.enc_counter: int = 0
        self.mac_chaining_value: bytes = b'\x00' * 16

    # ------------------------------------------------------------------
    # Key derivation  (GP SCP03 spec §6.2.1)
    # ------------------------------------------------------------------

    def _kdf(self, label: int, context: bytes, length_bits: int = 128) -> bytes:
        """
        AES-CMAC-based KDF per GP SCP03 spec §6.2.1.
        derivation_data = label(11B) || separation_indicator(1B=0x00)
                        || length(2B) || counter(1B=0x01) || context
        """
        label_bytes = b'\x00' * 11 + bytes([label])
        deriv = label_bytes + b'\x00' + struct.pack('>H', length_bits) + b'\x01' + context
        return _aes_cmac(self.master_key[:16], deriv)

    def derive_session_keys(self, host_challenge: bytes,
                             card_challenge: bytes) -> None:
        """Derive SCP03 session keys from host + card challenges."""
        context = host_challenge + card_challenge
        self.s_enc  = self._kdf(self._LABEL_ENC,  context)
        self.s_mac  = self._kdf(self._LABEL_MAC,  context)
        self.s_rmac = self._kdf(self._LABEL_RMAC, context)
        self.s_dek  = self._kdf(self._LABEL_DEK,  context)
        self.enc_counter = 0
        self.mac_chaining_value = b'\x00' * 16

    # ------------------------------------------------------------------
    # Cryptogram computation  (GP SCP03 spec §6.2.2)
    # ------------------------------------------------------------------

    def compute_card_cryptogram(self, host_challenge: bytes,
                                 card_challenge: bytes) -> bytes:
        """Compute expected 8-byte card cryptogram (first 8 bytes of CMAC)."""
        data = b'\x00' * 11 + b'\x02' + b'\x00\x40\x01' + host_challenge + card_challenge
        mac = _aes_cmac(self.s_mac, data)
        return mac[:8]

    def compute_host_cryptogram(self, host_challenge: bytes,
                                 card_challenge: bytes) -> bytes:
        """Compute 8-byte host cryptogram for EXTERNAL AUTHENTICATE."""
        data = b'\x00' * 11 + b'\x01' + b'\x00\x40\x01' + host_challenge + card_challenge
        mac = _aes_cmac(self.s_mac, data)
        return mac[:8]

    def compute_c_mac(self, apdu_bytes: bytes) -> bytes:
        """Compute C-MAC over chaining_value || apdu (without Le)."""
        mac_input = self.mac_chaining_value + apdu_bytes
        mac = _aes_cmac(self.s_mac, mac_input)
        self.mac_chaining_value = mac
        return mac

    def wrap_apdu(self, cla: int, ins: int, p1: int, p2: int,
                  data: bytes = b'') -> bytes:
        """Wrap APDU with SCP03 C-MAC."""
        secured_cla = cla | 0x04
        lc = len(data) + 8
        header_and_data = bytes([secured_cla, ins, p1, p2, lc]) + data
        mac = self.compute_c_mac(header_and_data)
        return header_and_data + mac

    def encrypt_data(self, plaintext: bytes) -> bytes:
        """Encrypt command data with S-ENC (AES-CBC, counter-based IV)."""
        self.enc_counter += 1
        iv_data = b'\x00' * 15 + bytes([self.enc_counter])
        cipher = Cipher(algorithms.AES(self.s_enc), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        iv = enc.update(iv_data) + enc.finalize()
        padded = _iso7816_pad(plaintext, 16)
        return _aes_cbc_encrypt(self.s_enc, iv, padded)

    @staticmethod
    def generate_host_challenge() -> bytes:
        """Generate a 32-byte random host challenge for SCP03."""
        return os.urandom(32)

    def build_initialize_update(self, host_challenge: bytes,
                                 key_version: int = 0) -> bytes:
        return bytes([0x80, 0x50, key_version, 0x00, len(host_challenge)]) + host_challenge + b'\x00'

    def parse_initialize_update_response(self, response: bytes) -> dict:
        """Parse 32-byte SCP03 INITIALIZE UPDATE response."""
        if len(response) < 32:
            raise ValueError(f"SCP03 INITIALIZE UPDATE response too short: {len(response)}")
        return {
            "key_diversification": response[0:10],
            "key_version":         response[10],
            "scp_id":              response[11],
            "card_challenge":      response[12:20],
            "card_cryptogram":     response[20:28],
            "sequence_counter":    response[28:31],
        }

    def build_external_authenticate(self, host_cryptogram: bytes,
                                     security_level: int = 0x01) -> bytes:
        """Build EXTERNAL AUTHENTICATE APDU for SCP03."""
        return self.wrap_apdu(0x84, 0x82, security_level, 0x00, host_cryptogram)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def make_scp02_session(master_key_hex: str) -> SCP02Session:
    return SCP02Session(bytes.fromhex(master_key_hex))


def make_scp03_session(master_key_hex: str) -> SCP03Session:
    return SCP03Session(bytes.fromhex(master_key_hex))


__all__ = [
    "SCP02Session",
    "SCP03Session",
    "make_scp02_session",
    "make_scp03_session",
]
