"""
GREENWIRE Key Generators
========================
Four independent, heavily-commented key-derivation engines covering every
layer of the payment/smartcard/HCE stack.

WHY FOUR SEPARATE GENERATORS?
──────────────────────────────
The same "master key" concept exists at multiple independent layers of the
payment ecosystem.  Each layer has its own specification, its own algorithm,
and its own threat model.  Mixing them up is the single most common cause of
integration bugs in lab environments:

  Layer 0 – Factory personalisation (who programs the chip)
            → Generator 1: GP_StaticDiversification

  Layer 1 – Cardholder transaction (every tap at a terminal)
            → Generator 2: EMV_DynamicSessionKeys

  Layer 2 – Secure OTA channel (pushing new applets to the card)
            → Generator 3: SCP03_AESKeyDerivation

  Layer 3 – Software card on a phone (HCE, no physical chip)
            → Generator 4: HCE_TokenKeyGenerator

ALL FOUR share the JCOP default lab master key for easy cross-comparison
in a controlled lab.  In production each layer uses a different key held
in a different HSM vault.

HOW THE NUMBERS RELATE
──────────────────────
                        ┌─────────────────────────────┐
                        │   Issuer Master Key (IMK)    │  ← lives in HSM
                        └────────────┬────────────────┘
                   ┌─────────────────┼─────────────────┐
                   ▼                 ▼                  ▼
          GP ENC/MAC/DEK      ICC_MK per card    SCP03 session
          (Gen 1 — factory)   (Gen 2 — per tap)  (Gen 3 — OTA)
                   │                 │
                   ▼                 ▼
          Programmed into SE   ARQC on each tap
                                     │
                                     ▼ (in HCE, TSP pre-computes this)
                              LUK batch (Gen 4)
                              Pushed OTA to Android TEE

QUICK START
───────────
  python core/key_generators.py                    # run all four demos
  python core/key_generators.py <32-hex-masterkey> # use custom key

  from core.key_generators import GP_StaticDiversification
  ks = GP_StaticDiversification("404142434445464748494A4B4C4D4E4F").derive("DEADBEEF01234567")
  print(ks.enc.hex().upper())   # → ENC key for that card serial

REFERENCE SPECIFICATIONS
─────────────────────────
  Gen 1 : GlobalPlatform Card Specification v2.3 §10.2
  Gen 2 : EMV Book 2 §A.1.3 (ICC MK Option A) + §A.3 (session key)
  Gen 3 : GlobalPlatform Card Spec v2.3 Amendment D (SCP03) §6.2.1
  Gen 4 : Visa Token Service (VTS) Tokenization Specification §5.3
          EMV Contactless Payment Application (CPA) §5.4

HSM INTEGRATION
───────────────
  All generators can store their outputs in the GREENWIRE HSM emulator:
    from core.key_generators import GP_StaticDiversification
    from core.hsm_service import HSMService
    gen = GP_StaticDiversification(master_key, hsm=HSMService())
    ks  = gen.derive("DEADBEEF01234567")   # automatically stored in HSM
"""

from __future__ import annotations

import hashlib
import os
import secrets
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# We use only the `cryptography` package (already required by GREENWIRE)
# so this file works in static/offline mode without PyCryptodome.
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _TripleDES
    from cryptography.hazmat.primitives.ciphers import algorithms
    algorithms.TripleDES = _TripleDES  # shim for consistent usage below
except ImportError:
    from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

# ─────────────────────────────────────────────────────────────────────────────
# PRIMITIVE BUILDING BLOCKS
# Every generator reduces to combinations of these five operations.
# Understanding these is sufficient to understand all four generators.
# ─────────────────────────────────────────────────────────────────────────────

def _tdes_ecb(key: bytes, block: bytes) -> bytes:
    """
    Triple-DES single-block ECB encryption.

    WHY 3DES?
    The EMV Book 2 specification predates AES (finalised 2001).  3DES with
    a 112-bit effective key was the strongest algorithm available at the time
    and is still mandatory for backward compatibility with every issued card.

    KEY EXPANSION:
    A 16-byte key [K1 K2] is internally treated as [K1 K2 K1] — the 24-byte
    "two-key triple-DES" (2TDEA) format.  This is slightly weaker than true
    3TDEA but was considered sufficient for EMV key derivation.

    BLOCK SIZE: always 8 bytes in, 8 bytes out.
    """
    if len(key) == 16:
        key = key + key[:8]       # 2TDEA expansion: [K1 K2] → [K1 K2 K1]
    if len(key) != 24:
        raise ValueError(f"3DES key must be 16 or 24 bytes, got {len(key)}")
    if len(block) != 8:
        raise ValueError(f"3DES ECB operates on one 8-byte block, got {len(block)}")
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def _tdes_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    """
    Triple-DES CBC encryption over multiple blocks.

    CBC (Cipher Block Chaining) XORs each plaintext block with the previous
    ciphertext block before encrypting.  This ensures that two identical
    plaintext blocks produce different ciphertext — critical for MAC security.

    PADDING: the caller is responsible for padding data to a multiple of
    8 bytes before calling this function (use _iso7816_pad).
    """
    if len(key) == 16:
        key = key + key[:8]
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    """
    AES-128 single-block ECB encryption (always 16 bytes in, 16 bytes out).

    Used in SCP03's counter-mode IV generation: the counter value is
    AES-encrypted to produce a pseudo-random IV for each command's CBC chain.
    This guarantees that even if the same plaintext is sent twice, the
    ciphertext differs because the IV changes with the command counter.
    """
    if len(block) != 16:
        raise ValueError(f"AES ECB block must be 16 bytes, got {len(block)}")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def _aes_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128/192/256 CBC encryption.  Caller must pre-pad data."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def _aes_cmac(key: bytes, data: bytes) -> bytes:
    """
    AES-CMAC per NIST SP 800-38B / RFC 4493 — always 16-byte output.

    CMAC is a Message Authentication Code built from AES.  In SCP03 it
    serves a dual role:
      1. As a Key Derivation Function (KDF): feeding it a structured
         label + context produces a pseudo-random session key that is
         computationally indistinguishable from a random key to anyone
         who does not know the master key.
      2. As a MAC: protecting each APDU command against tampering.

    SECURITY: breaking CMAC requires breaking AES-128 — currently
    considered computationally infeasible with known algorithms.
    """
    c = CMAC(algorithms.AES(key), backend=default_backend())
    c.update(data)
    return c.finalize()


def _iso7816_pad(data: bytes, block_size: int = 8) -> bytes:
    """
    ISO/IEC 7816-4 bit-padding.

    Appends a mandatory 0x80 byte then enough 0x00 bytes to reach the
    next block boundary.  This is the standard padding scheme for all
    EMV MAC and encryption operations.

    Example (block_size=8):
        Input  → AA BB CC                           (3 bytes)
        Output → AA BB CC  80 00 00 00 00           (8 bytes)

    The 0x80 byte marks where real data ends.  On the receiving side,
    scan from the right: skip 0x00 bytes then remove the 0x80.

    WHY NOT PKCS#7?  EMV predates the widespread adoption of TLS/PKCS#7.
    ISO 7816 padding was chosen by the smart-card community in the 1980s
    and is now frozen into every EMV card on the planet.
    """
    padded = data + b'\x80'
    remainder = len(padded) % block_size
    if remainder:
        padded += b'\x00' * (block_size - remainder)
    return padded


def _xor(a: bytes, b: bytes) -> bytes:
    """Bitwise XOR of two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError(f"XOR operands must be same length: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def _adjust_parity(key: bytes) -> bytes:
    """
    Set odd DES key parity on every byte of a 3DES key.

    WHY PARITY MATTERS:
    The DES algorithm ignores the least-significant bit of each key byte
    (bit 0).  This bit was originally used as a parity indicator so that
    hardware could detect single-bit transmission errors.  Modern HSMs and
    many software implementations verify that the parity is correct and
    will reject keys that fail the check.

    ODD PARITY means: counting the 1-bits in all 8 bits of each byte
    (including the parity bit) must give an odd number.

    We count the 1-bits in the top 7 bits, then set bit 0 to make the
    total count odd.
    """
    result = bytearray(key)
    for i, byte in enumerate(result):
        # Count 1-bits in bits 7..1 (top 7 bits)
        popcount = bin(byte >> 1).count('1')
        # bit 0 = 0 if already odd count, 1 if even count (to make it odd)
        result[i] = (byte & 0xFE) | (0 if popcount % 2 == 1 else 1)
    return bytes(result)


def _luhn_append(pan_body: str) -> str:
    """
    Append a Luhn check digit to make a valid PAN.

    The Luhn algorithm is used on every credit/debit card PAN as a simple
    checksum to catch typos.  Token generators MUST produce Luhn-valid PANs
    because POS terminals validate the check digit before even sending the
    transaction to the network.

    Algorithm:
      1. Starting from the rightmost digit, double every second digit.
      2. If doubling produces > 9, subtract 9.
      3. Sum all digits.
      4. The check digit is (10 − (sum mod 10)) mod 10.
    """
    digits = [int(d) for d in pan_body]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 0:      # every second digit from the right (0-indexed)
            d *= 2
            if d > 9:
                d -= 9      # two-digit results: subtract 9 (same as summing digits)
        total += d
    check = (10 - (total % 10)) % 10
    return pan_body + str(check)


# ═════════════════════════════════════════════════════════════════════════════
# GENERATOR 1 — GP Static Key Diversification  (Factory / Personalisation)
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class GP_KeySet:
    """
    The three keys permanently stored in a JCOP chip's Issuer Security Domain.

    ┌──────┬────────────────────────────────────────────────────────────────┐
    │ Key  │ Purpose                                                        │
    ├──────┼────────────────────────────────────────────────────────────────┤
    │ ENC  │ Encrypts sensitive data payloads (e.g. new key values sent     │
    │      │ via PUT KEY) so they are never in plaintext on the wire.       │
    ├──────┼────────────────────────────────────────────────────────────────┤
    │ MAC  │ Authenticates every APDU command in a secure channel.          │
    │      │ An 8-byte C-MAC is appended to each command so the card can   │
    │      │ verify the command came from a legitimate, authorised sender.  │
    ├──────┼────────────────────────────────────────────────────────────────┤
    │ DEK  │ Transport key: wraps key material before it is loaded onto     │
    │      │ the card.  A new key is 3DES-ECB encrypted under DEK so that  │
    │      │ the raw key value is never visible in an APDU capture.         │
    └──────┴────────────────────────────────────────────────────────────────┘

    All three are 16-byte 2TDEA keys when the card uses SCP02.
    SCP03 cards use 16-byte AES-128 keys instead (see Generator 3).
    """
    enc:         bytes   # S-ENC — encryption key
    mac:         bytes   # S-MAC — message authentication key
    dek:         bytes   # S-DEK — data encryption / transport key
    master_key:  bytes   # The root master key they were all derived from
    card_serial: bytes   # The diversification data (card serial / AID)

    def display(self) -> Dict[str, str]:
        """Return a human-readable dict for printing / logging."""
        return {
            "MASTER_KEY":  self.master_key.hex().upper(),
            "CARD_SERIAL": self.card_serial.hex().upper(),
            "ENC":         self.enc.hex().upper(),
            "MAC":         self.mac.hex().upper(),
            "DEK":         self.dek.hex().upper(),
        }

    def as_jcop_put_key(self) -> Dict[str, str]:
        """Format keys as hex strings suitable for gp.jar --put-key arguments."""
        return {
            "--key-enc": self.enc.hex().upper(),
            "--key-mac": self.mac.hex().upper(),
            "--key-dek": self.dek.hex().upper(),
        }


class GP_StaticDiversification:
    """
    GENERATOR 1 — GlobalPlatform Static Key Diversification.
    Reference: GP Card Specification v2.3 §10.2

    ╔══════════════════════════════════════════════════════════════════════╗
    ║ THE PROBLEM IT SOLVES                                                ║
    ║                                                                      ║
    ║ A card personalisation bureau produces millions of JCOP chips.       ║
    ║ They cannot store a different 48-byte keyset for each chip —         ║
    ║ the logistics are impossible.  Instead they hold ONE Master Key       ║
    ║ in their HSM and DERIVE a unique keyset for each chip by mixing       ║
    ║ the Master Key with the chip's serial number.                        ║
    ║                                                                      ║
    ║ Later, when a TSM or issuer needs to open a secure channel to a       ║
    ║ specific card, they read the serial from the card, re-derive the     ║
    ║ same keyset on the fly, and use it — no per-card database needed.    ║
    ╚══════════════════════════════════════════════════════════════════════╝

    ALGORITHM — for each of ENC, MAC, DEK:
    ───────────────────────────────────────
    1. Build a 16-byte "diversification data" block:
         [constant 2B] [card_serial padded to 12B] [00 00 2B]

    2. Encrypt with 3DES-ECB under the Master Key:
         derived_key = 3DES_ECB( MasterKey, diversification_data )

    Derivation constants (GP Table 10-1):
         ENC → 01 82
         MAC → 01 01
         DEK → 01 81

    The different constants ensure ENC ≠ MAC ≠ DEK even for the same
    serial.  Without constants, all three keys would be identical.

    ─────────────────────────────────────────────────────────────────────
    JCOP DEFAULT LAB KEY:  404142434445464748494A4B4C4D4E4F
    Every uninitialized JCOP card uses this key from the factory.
    Published in the GP specification examples; safe for lab use.
    ─────────────────────────────────────────────────────────────────────
    """

    # Diversification constants — GP Card Spec v2.3 Table 10-1
    # These two bytes prefix each 16-byte derivation block to ensure
    # ENC, MAC, and DEK derive to different values from the same serial.
    _CONST_ENC = bytes([0x01, 0x82])
    _CONST_MAC = bytes([0x01, 0x01])
    _CONST_DEK = bytes([0x01, 0x81])

    def __init__(
        self,
        master_key_hex: str,
        hsm: Any = None,      # optional HSMService for key storage
    ) -> None:
        """
        Args:
            master_key_hex: 32-char hex string (16-byte key).
                            The JCOP lab default is "404142434445464748494A4B4C4D4E4F".
            hsm:            Optional HSMService instance.  If provided, all
                            derived keys are automatically stored in the HSM
                            key store under labels like "ENC-<serial>".
        """
        raw = bytes.fromhex(master_key_hex.replace(" ", ""))
        if len(raw) not in (16, 24):
            raise ValueError("Master key must be 16 or 24 bytes (32 or 48 hex chars)")
        self.master_key = raw
        self._hsm = hsm

    def _derive_one(self, constant: bytes, serial: bytes) -> bytes:
        """
        Derive one key (ENC, MAC, or DEK) for a given card serial.

        Block structure (always 16 bytes total):
          ┌─────────┬─────────────────────────────┬─────────┐
          │ const   │  card_serial (zero-padded   │  00 00  │
          │ (2 B)   │  or truncated to 12 B)      │  (2 B)  │
          └─────────┴─────────────────────────────┴─────────┘

        Padding the serial on the LEFT means:
          serial=AABB     → 000000000000000000000000AABB
          serial=AABBCCDD → 00000000000000000000AABBCCDD
        Short serials are handled consistently without a length field.
        """
        # Take up to last 12 bytes of serial, left-pad with zeros
        padded_serial = serial[-12:].rjust(12, b'\x00')

        # 16-byte diversification block
        block = constant + padded_serial + b'\x00\x00'
        assert len(block) == 16, "Diversification block must be exactly 16 bytes"

        # GP key derivation: encrypt each 8-byte half of the block separately
        # and concatenate → 16-byte derived key (standard SCP02 / EMV method 2).
        left = _tdes_ecb(self.master_key, block[:8])
        right = _tdes_ecb(self.master_key, block[8:])
        return left + right

    def derive(self, card_serial_hex: str) -> GP_KeySet:
        """
        Derive a complete ENC/MAC/DEK keyset for one card.

        Args:
            card_serial_hex: Card serial as hex (2-24 chars).
                             On a real JCOP this is the CPLC Card Serial Number
                             or the ISD AID — anything that uniquely identifies
                             the chip.

        Returns:
            GP_KeySet containing enc, mac, dek bytes.

        Example:
            gen = GP_StaticDiversification("404142434445464748494A4B4C4D4E4F")
            ks  = gen.derive("DEADBEEF01234567")
            # ks.enc, ks.mac, ks.dek are now ready for gp.jar --key-enc etc.
        """
        serial = bytes.fromhex(card_serial_hex.replace(" ", ""))

        enc = self._derive_one(self._CONST_ENC, serial)
        mac = self._derive_one(self._CONST_MAC, serial)
        dek = self._derive_one(self._CONST_DEK, serial)

        ks = GP_KeySet(enc=enc, mac=mac, dek=dek,
                       master_key=self.master_key, card_serial=serial)

        # Optionally persist to HSM key store
        if self._hsm is not None:
            serial_tag = serial.hex().upper()
            try:
                self._hsm._emulator.import_key(f"ENC-{serial_tag}", enc)
                self._hsm._emulator.import_key(f"MAC-{serial_tag}", mac)
                self._hsm._emulator.import_key(f"DEK-{serial_tag}", dek)
            except Exception:
                pass   # HSM storage is best-effort in lab mode

        return ks

    def derive_random_card(self) -> GP_KeySet:
        """Generate a completely fresh card serial and derive its keyset — useful for
        spawning synthetic lab identities without a real card."""
        return self.derive(secrets.token_bytes(8).hex())


# ═════════════════════════════════════════════════════════════════════════════
# GENERATOR 2 — EMV Dynamic Session Keys + ARQC  (Per-Transaction)
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class EMV_SessionResult:
    """
    Output of one complete EMV transaction session derivation.

    icc_mk  — ICC Master Key.  Unique to this card (PAN+PSN).  Derived
               once during card personalisation and stored in the chip's
               EEPROM.  The issuer's HSM can re-derive it on demand.

    sk_enc  — Session Encryption Key for THIS specific transaction.
               Derived fresh from ICC_MK + ATC every single tap.
               After the tap, sk_enc is never used again.

    sk_mac  — Session MAC Key for THIS specific transaction.
               Same per-tap derivation as sk_enc, different constant.
               Used to compute (and later verify) the ARQC.

    arqc    — Application Request Cryptogram — the 8-byte "transaction
               proof".  The issuer re-derives sk_mac and verifies this
               value before authorising the transaction.

    atc     — Application Transaction Counter at the moment of the tap.
               Increments by 1 on every tap, providing replay protection.
    """
    icc_mk:  bytes
    sk_enc:  bytes
    sk_mac:  bytes
    arqc:    bytes
    atc:     int

    def display(self) -> Dict[str, str]:
        return {
            "ICC_MK": self.icc_mk.hex().upper(),
            "SK_ENC": self.sk_enc.hex().upper(),
            "SK_MAC": self.sk_mac.hex().upper(),
            "ARQC":   self.arqc.hex().upper(),
            "ATC":    str(self.atc),
        }


class EMV_DynamicSessionKeys:
    """
    GENERATOR 2 — EMV Per-Transaction Session Keys and ARQC.
    Reference: EMV Book 2 §A.1.3 (ICC MK), §A.3 (session keys), §A.4 (ARQC)

    ╔══════════════════════════════════════════════════════════════════════╗
    ║ THE THREE STEPS OF EVERY TAP                                         ║
    ║                                                                      ║
    ║  1. FIND:    Card looks up its ICC Master Key in EEPROM.             ║
    ║              (Derived from IMK + PAN at personalisation time.)       ║
    ║                                                                      ║
    ║  2. DERIVE:  Card computes fresh SK_ENC and SK_MAC from              ║
    ║              ICC_MK + ATC.  ATC is a counter that increments every   ║
    ║              tap — so the session keys change on every transaction.  ║
    ║                                                                      ║
    ║  3. PROVE:   Card computes ARQC = MAC(SK_MAC, txn_data) and sends    ║
    ║              it to the acquirer.  The issuer re-derives SK_MAC and   ║
    ║              verifies the ARQC to confirm the genuine card was used. ║
    ╚══════════════════════════════════════════════════════════════════════╝

    STEP 1 — ICC Master Key Derivation (EMV Book 2 §A.1.3, Option A):
    ──────────────────────────────────────────────────────────────────
      data_A = last-16-digits-of(PAN || PSN) as 8 raw bytes (BCD encoding)
      data_B = data_A XOR 0xFFFFFFFFFFFFFFFF   (bitwise complement)
      raw    = 3DES_ECB( IMK, data_A ) || 3DES_ECB( IMK, data_B )
      ICC_MK = adjust_odd_parity( raw )

    STEP 2 — Common Session Key Derivation (EMV Book 2 §A.3):
    ──────────────────────────────────────────────────────────
      r_enc = ATC_hi | ATC_lo | 0xF0 | 0x00 | ATC_hi | ATC_lo | 0xF0 | 0x00
      r_mac = ATC_hi | ATC_lo | 0x0F | 0x00 | ATC_hi | ATC_lo | 0x0F | 0x00

      SK_ENC = 3DES_ECB( ICC_MK, r_enc[:8] ) || 3DES_ECB( ICC_MK, r_enc_complement )
      SK_MAC = 3DES_ECB( ICC_MK, r_mac[:8] ) || 3DES_ECB( ICC_MK, r_mac_complement )

      The 0xF0 / 0x0F byte in position 2 is what makes SK_ENC ≠ SK_MAC.

    STEP 3 — ARQC (ISO 9797-1 Algorithm 3):
    ────────────────────────────────────────
      padded = ISO7816_pad( txn_data )
      ① Single-DES CBC with K_left over all-but-last block (cheap)
      ② Full 3DES on the final block with [K_left || K_right] (expensive)
      ARQC   = result[:8]

      Algorithm 3 is a "retail MAC" — it needs the full 16-byte key to
      forge.  Knowing only K_left (first 8 bytes) is not sufficient.
    """

    def __init__(self, iss_mk_hex: str, hsm: Any = None) -> None:
        """
        Args:
            iss_mk_hex: 32-char hex Issuer Master Key.
                        In production this never leaves the HSM.
                        For lab use: "404142434445464748494A4B4C4D4E4F".
            hsm:        Optional HSMService for storing ICC_MK in the
                        HSM key store (label = "ICC_MK-<pan_last4>").
        """
        raw = bytes.fromhex(iss_mk_hex.replace(" ", ""))
        if len(raw) != 16:
            raise ValueError("Issuer Master Key must be exactly 16 bytes (32 hex chars)")
        self.iss_mk = raw
        self._hsm = hsm

    def derive_icc_mk(self, pan: str, psn: str = "00") -> bytes:
        """
        Derive the ICC Master Key (Option A).

        This is the key stored permanently in the card chip.  The issuer
        re-derives it when they need to verify an ARQC.

        Option A uses the rightmost 16 digits of PAN+PSN as derivation data.
        Option B adds SHA-1 for PANs longer than 16 digits — not implemented
        here as 16-digit PANs cover all common Visa/MC formats.

        Args:
            pan: PAN as digit string (e.g. "4111111111111111").
            psn: PAN Sequence Number, usually "00".

        Returns:
            16-byte ICC Master Key with correct DES parity.
        """
        # Use the last 16 characters of PAN+PSN
        # This handles 16-digit (Visa) and 19-digit PANs uniformly.
        combined_tail = (pan + psn)[-16:].zfill(16)

        # Interpret as raw bytes (BCD: "41" → 0x41, not 41 decimal)
        data_a = bytes.fromhex(combined_tail)   # 8 bytes

        # Complement: each bit flipped (0xFF XOR each byte)
        data_b = _xor(data_a, b'\xFF' * 8)      # 8 bytes

        # Two 3DES-ECB operations give the 16-byte ICC_MK
        left  = _tdes_ecb(self.iss_mk, data_a)
        right = _tdes_ecb(self.iss_mk, data_b)

        icc_mk = _adjust_parity(left + right)

        # Optionally store in HSM
        if self._hsm is not None:
            try:
                label = f"ICC_MK-{pan[-4:]}"
                self._hsm._emulator.import_key(label, icc_mk)
            except Exception:
                pass

        return icc_mk

    def derive_session_keys(self, icc_mk: bytes, atc: int) -> Tuple[bytes, bytes]:
        """
        Derive SK_ENC and SK_MAC from ICC_MK and the current ATC.

        The ATC is a 16-bit counter (0x0000–0xFFFF).  We split it into
        high byte (ATC_hi) and low byte (ATC_lo) and build two 8-byte
        templates:

          ENC template: [ATC_hi][ATC_lo][F0][00][ATC_hi][ATC_lo][F0][00]
          MAC template: [ATC_hi][ATC_lo][0F][00][ATC_hi][ATC_lo][0F][00]

        The F0/0F byte in position 2 is the only difference between the
        ENC and MAC derivation — it ensures the two keys are unrelated.

        Each 8-byte template is encrypted with 3DES-ECB using ICC_MK to
        give one half of the 16-byte session key.  The "other half" is
        derived from the bitwise complement of the template.
        """
        hi = (atc >> 8) & 0xFF   # high byte of 2-byte ATC
        lo =  atc       & 0xFF   # low  byte of 2-byte ATC

        # ENC derivation template (position 2 = 0xF0)
        r_enc = bytes([hi, lo, 0xF0, 0x00, hi, lo, 0xF0, 0x00])
        # Complement: XOR with 00 00 FF FF 00 00 FF FF
        # (only the 0xF0 and 0x00 bytes flip; ATC bytes stay for uniqueness)
        r_enc_c = _xor(r_enc, b'\x00\x00\xFF\xFF\x00\x00\xFF\xFF')

        # MAC derivation template (position 2 = 0x0F)
        r_mac   = bytes([hi, lo, 0x0F, 0x00, hi, lo, 0x0F, 0x00])
        r_mac_c = _xor(r_mac, b'\x00\x00\xFF\xFF\x00\x00\xFF\xFF')

        # Each session key = 3DES(ICC_MK, template) || 3DES(ICC_MK, complement)
        sk_enc = _adjust_parity(_tdes_ecb(icc_mk, r_enc) + _tdes_ecb(icc_mk, r_enc_c))
        sk_mac = _adjust_parity(_tdes_ecb(icc_mk, r_mac) + _tdes_ecb(icc_mk, r_mac_c))

        return sk_enc, sk_mac

    def compute_arqc(self, sk_mac: bytes, txn_data: bytes) -> bytes:
        """
        Compute the ARQC via ISO 9797-1 Algorithm 3 (Retail MAC).

        The 16-byte sk_mac is split into K_left (bytes 0-7) and K_right
        (bytes 8-15).  Algorithm 3 uses K_left for cheap single-DES inner
        blocks and then applies full 3DES (K_left + K_right) to the final
        block.  This means forging the MAC requires knowing both halves.

        Steps:
          1. Pad txn_data with ISO 7816 padding to a multiple of 8 bytes.
          2. CBC through all-but-last block using single-DES with K_left.
          3. Apply 3DES [K_left || K_right] to the final block.
          4. Return the 8-byte result (first half of last ciphertext block).
        """
        padded  = _iso7816_pad(txn_data, block_size=8)
        k_left  = sk_mac[:8]
        k_right = sk_mac[8:16]
        k_3des  = k_left + k_right + k_left   # 24-byte 3TDEA key

        # Walk through all blocks except the last using single-DES CBC
        iv = b'\x00' * 8
        for i in range(0, len(padded) - 8, 8):
            block = _xor(padded[i:i+8], iv)
            # Single-DES with K_left only (performance optimisation in retail MACs)
            single_des = Cipher(
                algorithms.TripleDES(k_left * 3),   # expand 8B→24B for API
                modes.ECB(), backend=default_backend()
            )
            enc = single_des.encryptor()
            iv  = enc.update(block) + enc.finalize()

        # Final block: full 3DES for security (requires both K_left and K_right)
        final = _xor(padded[-8:], iv)
        return _tdes_ecb(k_3des, final)

    def generate(
        self,
        pan: str,
        psn: str = "00",
        atc: int = 1,
        txn_data: Optional[bytes] = None,
    ) -> EMV_SessionResult:
        """
        Run the full chain: IMK → ICC_MK → SK_ENC/SK_MAC → ARQC.

        Args:
            pan:       PAN as a digit string ("4111111111111111").
            psn:       PAN Sequence Number, usually "00".
            atc:       Application Transaction Counter (1–65535).
                       Each tap should use the next ATC value.
            txn_data:  22-byte EMV transaction data buffer.
                       Nil = all-zero placeholder (lab/test use only).

        Returns:
            EMV_SessionResult with all intermediate values populated.
            All values are deterministic — same inputs always give same output.
        """
        if txn_data is None:
            # 22-byte transaction data: amount(6) + other_amount(6) + currency(2)
            # + TVR(5) + txn_date(3) — all zeros for lab testing
            txn_data = b'\x00' * 22

        icc_mk           = self.derive_icc_mk(pan, psn)
        sk_enc, sk_mac   = self.derive_session_keys(icc_mk, atc)
        arqc             = self.compute_arqc(sk_mac, txn_data)

        return EMV_SessionResult(
            icc_mk=icc_mk, sk_enc=sk_enc, sk_mac=sk_mac, arqc=arqc, atc=atc
        )


# ═════════════════════════════════════════════════════════════════════════════
# GENERATOR 3 — SCP03 AES Key Derivation  (JCOP5 / Modern Secure Channel)
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SCP03_KeySet:
    """
    Session keys for one SCP03 AES secure channel.

    ┌────────┬─────────────────────────────────────────────────────────────┐
    │ Key    │ Purpose                                                     │
    ├────────┼─────────────────────────────────────────────────────────────┤
    │ S-ENC  │ Encrypts command data so eavesdroppers cannot see what is   │
    │        │ being written to or installed on the card.                  │
    ├────────┼─────────────────────────────────────────────────────────────┤
    │ S-MAC  │ Authenticates each command APDU.  Terminal appends a 16-    │
    │        │ byte AES-CMAC; card verifies it before executing.           │
    ├────────┼─────────────────────────────────────────────────────────────┤
    │ S-RMAC │ Authenticates response APDUs — proves the card's response   │
    │        │ was not tampered with on the way back to the terminal.      │
    ├────────┼─────────────────────────────────────────────────────────────┤
    │ S-DEK  │ Wraps sensitive key material (like PUT KEY payloads)        │
    │        │ inside the secure channel — AES version of SCP02's DEK.    │
    └────────┴─────────────────────────────────────────────────────────────┘

    All four are 16-byte AES-128 keys (SCP03 only supports AES).
    SCP03 never uses 3DES — this is the primary security improvement over SCP02.
    """
    s_enc:          bytes
    s_mac:          bytes
    s_rmac:         bytes
    s_dek:          bytes
    host_challenge: bytes   # nonce generated by the terminal
    card_challenge: bytes   # nonce from the card's INITIALIZE UPDATE response

    def display(self) -> Dict[str, str]:
        return {
            "HOST_CHALLENGE": self.host_challenge.hex().upper(),
            "CARD_CHALLENGE":  self.card_challenge.hex().upper(),
            "S-ENC":           self.s_enc.hex().upper(),
            "S-MAC":           self.s_mac.hex().upper(),
            "S-RMAC":          self.s_rmac.hex().upper(),
            "S-DEK":           self.s_dek.hex().upper(),
        }


class SCP03_AESKeyDerivation:
    """
    GENERATOR 3 — SCP03 AES-CMAC Key Derivation Function.
    Reference: GP Card Specification v2.3 Amendment D (SCP03) §6.2.1

    ╔══════════════════════════════════════════════════════════════════════╗
    ║ WHY SCP03 INSTEAD OF SCP02?                                          ║
    ║                                                                      ║
    ║ SCP02 uses 3DES and a fixed sequence counter for key derivation.     ║
    ║ Three problems:                                                       ║
    ║   1. 3DES is deprecated (NIST SP 800-131A Rev 2, 2019).              ║
    ║   2. A fixed sequence counter is predictable after compromising one  ║
    ║      session — the next counter value is counter+1.                  ║
    ║   3. SCP02 offers no response authentication (R-MAC is optional).    ║
    ║                                                                      ║
    ║ SCP03 fixes all three:                                               ║
    ║   1. Replaces 3DES with AES-128 throughout.                          ║
    ║   2. Replaces the counter with random 8-byte challenges from both    ║
    ║      terminal AND card — compromising one session reveals nothing     ║
    ║      about future sessions.                                          ║
    ║   3. Mandates S-RMAC for response authentication.                    ║
    ╚══════════════════════════════════════════════════════════════════════╝

    KDF CONSTRUCTION (GP SCP03 Amendment D §6.2.1):
    ─────────────────────────────────────────────────
    For each session key, build a 32-byte derivation data block:

        Bytes  0-10 : 0x00 × 11             (padding)
        Byte    11  : label_byte            (0x04=ENC, 0x06=MAC, 0x07=RMAC, 0x08=DEK)
        Byte    12  : 0x00                  (separation indicator)
        Bytes 13-14 : 0x00 0x80             (output length = 128 bits)
        Byte    15  : 0x01                  (counter = 1)
        Bytes 16-23 : host_challenge        (8 bytes)
        Bytes 24-31 : card_challenge        (8 bytes)

        session_key = AES_CMAC( master_key, derivation_data )  → 16 bytes

    Each label byte produces a completely different 16-byte key from the
    same challenges and master key.  This is the "domain separation"
    property of the KDF.
    """

    # Label constants — GP SCP03 Amendment D §6.2.1 Table 6-3
    _LABEL_ENC  = 0x04   # Encryption key
    _LABEL_MAC  = 0x06   # MAC key
    _LABEL_RMAC = 0x07   # Response-MAC key
    _LABEL_DEK  = 0x08   # Data encryption key

    def __init__(self, master_key_hex: str, hsm: Any = None) -> None:
        """
        Args:
            master_key_hex: 32-char hex AES-128 master key.
                            JCOP lab default: "404142434445464748494A4B4C4D4E4F".
            hsm:            Optional HSMService for key storage.
        """
        raw = bytes.fromhex(master_key_hex.replace(" ", ""))
        if len(raw) not in (16, 24, 32):
            raise ValueError("SCP03 master key must be 16, 24, or 32 bytes")
        self.master_key = raw[:16]   # Always AES-128 (first 16 bytes)
        self._hsm = hsm

    def _kdf(self, label: int, context: bytes) -> bytes:
        """
        Derive one 16-byte session key using the SCP03 KDF.

        The derivation_data structure is a fixed-length frame that acts
        as a unique "label" for each key type.  Changing even one bit of
        the derivation data completely changes the output key.

        This "domain separation" guarantee is what makes it safe to use
        the same master key for all four session keys — they cannot be
        related to each other by any known algorithm.
        """
        label_field  = b'\x00' * 11 + bytes([label])  # 12 bytes: 11 zeros + 1 label
        sep          = b'\x00'                          # separation indicator
        length_field = struct.pack('>H', 128)           # output length = 128 bits
        counter      = b'\x01'                          # always 1 (single block KDF)

        # Full derivation data: 12 + 1 + 2 + 1 + len(context) = 32 bytes for 16-byte context
        deriv = label_field + sep + length_field + counter + context
        return _aes_cmac(self.master_key, deriv)

    def derive(
        self,
        host_challenge: Optional[bytes] = None,
        card_challenge: Optional[bytes] = None,
    ) -> SCP03_KeySet:
        """
        Derive a complete SCP03 session keyset from random challenges.

        Args:
            host_challenge: 8-byte nonce from the terminal.
                            Generated fresh for every channel opening.
                            If None, os.urandom(8) is used.
            card_challenge: 8-byte nonce from the card's INITIALIZE UPDATE.
                            If None, os.urandom(8) is used (lab/simulation).

        Returns:
            SCP03_KeySet with all four session keys populated.

        SECURITY NOTE: Both challenges MUST be random and unpredictable.
        If either challenge is fixed or predictable, the session key
        derivation is effectively deterministic and replay attacks are possible.
        """
        if host_challenge is None:
            host_challenge = os.urandom(8)
        if card_challenge is None:
            card_challenge = os.urandom(8)

        # Context = host_challenge || card_challenge (16 bytes)
        context = host_challenge + card_challenge

        ks = SCP03_KeySet(
            s_enc          = self._kdf(self._LABEL_ENC,  context),
            s_mac          = self._kdf(self._LABEL_MAC,  context),
            s_rmac         = self._kdf(self._LABEL_RMAC, context),
            s_dek          = self._kdf(self._LABEL_DEK,  context),
            host_challenge = host_challenge,
            card_challenge = card_challenge,
        )

        if self._hsm is not None:
            try:
                tag = context[:4].hex().upper()
                self._hsm._emulator.import_key(f"SCP03-SENC-{tag}",  ks.s_enc)
                self._hsm._emulator.import_key(f"SCP03-SMAC-{tag}",  ks.s_mac)
                self._hsm._emulator.import_key(f"SCP03-SDEK-{tag}",  ks.s_dek)
            except Exception:
                pass

        return ks

    def derive_with_cryptograms(
        self,
        host_challenge: bytes,
        card_challenge: bytes,
    ) -> Tuple[SCP03_KeySet, bytes, bytes]:
        """
        Derive session keys AND the mutual authentication cryptograms.

        The SCP03 handshake:
          1. Terminal → Card:  INITIALIZE UPDATE (host_challenge)
          2. Card → Terminal:  card_challenge + CARD_CRYPTOGRAM
          3. Terminal verifies CARD_CRYPTOGRAM  (proves genuine card)
          4. Terminal → Card:  EXTERNAL AUTHENTICATE (HOST_CRYPTOGRAM)
          5. Card verifies HOST_CRYPTOGRAM  (proves genuine terminal)
          6. Channel is open — both parties share the four session keys

        Returns:
            (keyset, expected_card_cryptogram, host_cryptogram_to_send)
        """
        ks      = self.derive(host_challenge, card_challenge)
        context = host_challenge + card_challenge

        # Card cryptogram: label 0x02, 64-bit output (first 8 bytes of CMAC)
        card_cg_data = (b'\x00' * 11 + b'\x02' + b'\x00'
                        + struct.pack('>H', 64) + b'\x01' + context)
        card_cg = _aes_cmac(ks.s_mac, card_cg_data)[:8]

        # Host cryptogram: label 0x01, 64-bit output
        host_cg_data = (b'\x00' * 11 + b'\x01' + b'\x00'
                        + struct.pack('>H', 64) + b'\x01' + context)
        host_cg = _aes_cmac(ks.s_mac, host_cg_data)[:8]

        return ks, card_cg, host_cg


# ═════════════════════════════════════════════════════════════════════════════
# GENERATOR 4 — HCE Token Key Generator  (Android / TSP / No Physical SE)
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class HCE_Token:
    """
    A provisioned HCE payment token for Android.

    The device never holds the real card PAN.  Instead it holds:
      - A DPAN (Device PAN / token) — fake PAN in a special BIN range
      - Pre-computed LUK batch — one Limited Use Key per future ATC value
      - An ICC_MK derived from the DPAN (not the real PAN)

    When the phone taps a reader:
      1. It picks the LUK for the current ATC from the batch.
      2. Computes ARQC = MAC(LUK, txn_data).
      3. Sends DPAN + ARQC to the reader.
      4. Acquirer → network → TSP de-tokenises DPAN → issuer authorises.
    """
    dpan:        str             # Device PAN (16-digit token, different BIN from real card)
    token_ref:   str             # Unique token reference for TSP lifecycle calls
    icc_mk:      bytes           # Derived from IMK + DPAN (not real PAN — by design)
    luk_batch:   List[Dict]      # [{atc: int, luk: bytes}, ...]  pre-computed LUKs
    current_atc: int = 1         # Next ATC to use
    scheme:      str = "VISA"    # "VISA" or "MASTERCARD"
    expiry:      str = "2512"    # Token expiry MMYY

    def display(self) -> Dict[str, str]:
        out: Dict[str, str] = {
            "DPAN":      self.dpan,
            "TOKEN_REF": self.token_ref,
            "ICC_MK":    self.icc_mk.hex().upper(),
            "SCHEME":    self.scheme,
            "EXPIRY":    self.expiry,
            "ATC_NEXT":  str(self.current_atc),
            "LUK_COUNT": str(len(self.luk_batch)),
        }
        # Show first 3 LUKs so the lab operator can verify derivation
        for entry in self.luk_batch[:3]:
            out[f"LUK[ATC={entry['atc']}]"] = entry["luk"].hex().upper()
        return out


class HCE_TokenKeyGenerator:
    """
    GENERATOR 4 — HCE Token (DPAN) and Limited Use Key (LUK) Generator.
    Reference: Visa VTS Spec §5.3 / EMV Contactless Payment Application §5.4

    ╔══════════════════════════════════════════════════════════════════════╗
    ║ HCE vs PHYSICAL CARD — THE FUNDAMENTAL DIFFERENCE                   ║
    ║                                                                      ║
    ║ Physical JCOP card:                                                  ║
    ║   • Real PAN + ICC_MK stored in tamper-resistant silicon (EAL6+)    ║
    ║   • Session key derived ON CARD for each tap (never leaves chip)     ║
    ║   • Attacker must physically attack the silicon                       ║
    ║                                                                      ║
    ║ Android HCE:                                                         ║
    ║   • Real PAN NEVER on device — replaced by a DPAN (token)           ║
    ║   • ICC_MK derived from DPAN, stored in Android TEE / StrongBox     ║
    ║   • LUK = session key pre-computed by TSP, valid for 1 tap only     ║
    ║   • Attacker stealing a LUK can only use it for one ATC value       ║
    ║   • TSP (Visa VTS / MC MDES) pushes fresh LUKs when device runs low ║
    ╚══════════════════════════════════════════════════════════════════════╝

    DPAN GENERATION:
    ─────────────────
    Real PANs: 411111... (Visa), 555555... (MC)
    Token PANs use dedicated BIN ranges that the network knows are tokens:
      Visa tokens:  489537...   (token BIN registered with VisaNet)
      MC tokens:    535110...   (token BIN registered with Mastercard network)
    Same 16-digit length, same Luhn check — POS terminal treats it identically.

    LUK DERIVATION:
    ────────────────
    The LUK for ATC=n is simply the EMV common session key for that ATC:
      ICC_MK  = 3DES_ECB( IMK, DPAN_data )        (same as Gen 2, using DPAN)
      SK_ENC  = 3DES_ECB( ICC_MK, ATC_template_F0 )[:16]
      SK_MAC  = 3DES_ECB( ICC_MK, ATC_template_0F )[:16]
      LUK     = SK_ENC || SK_MAC                   (32 bytes, full key material)

    In practice:
      - Physical card: stores ICC_MK, derives SK per tap on-card.
      - HCE device:    TSP pre-derives SK (=LUK) for each ATC and pushes batch.
    The math is IDENTICAL — only the storage location and delivery differ.

    ARQC IN HCE:
    ─────────────
    ARQC = ISO9797_Alg3_MAC( LUK[SK_MAC half], txn_data )[:8]
    Identical to a physical card's ARQC computation — the issuer's
    verification path does not change between card and HCE.
    """

    _VISA_TOKEN_BIN = "489537"   # Visa sandbox token BIN (developer.visa.com)
    _MC_TOKEN_BIN   = "535110"   # MC sandbox token BIN   (developer.mastercard.com)

    def __init__(self, iss_mk_hex: str, hsm: Any = None) -> None:
        """
        Args:
            iss_mk_hex: 32-char hex Issuer Master Key.
                        Shared between issuer HSM and TSP under a key agreement.
                        Lab default: "404142434445464748494A4B4C4D4E4F".
            hsm:        Optional HSMService — LUKs are stored in the HSM so the
                        lab can independently verify ARQC values.
        """
        raw = bytes.fromhex(iss_mk_hex.replace(" ", ""))
        if len(raw) != 16:
            raise ValueError("Issuer master key must be 16 bytes (32 hex chars)")
        self.iss_mk  = raw
        self._hsm    = hsm
        # Reuse Generator 2's proven derivation code — avoids duplication
        self._emv    = EMV_DynamicSessionKeys(iss_mk_hex)

    def _make_dpan(self, scheme: str) -> str:
        """
        Generate a Luhn-valid 16-digit DPAN in the correct token BIN range.

        Security note: we use os.urandom (CSPRNG) for the body digits so
        that even knowing the BIN prefix (6 digits), an attacker must
        brute-force 10^9 remaining values to guess the DPAN.
        """
        prefix = self._VISA_TOKEN_BIN if scheme.upper() == "VISA" else self._MC_TOKEN_BIN
        # Generate 9 random digits for the middle (body will be 15 digits → Luhn adds 16th)
        body = prefix + str(int.from_bytes(os.urandom(5), 'big') % 10**9).zfill(9)
        return _luhn_append(body[:15])   # 15 digits + 1 Luhn = 16 digits

    def generate_token(
        self,
        fpan: str,
        psn: str = "00",
        scheme: str = "VISA",
        device_id: str = "greenwire_lab",
        luk_batch_size: int = 5,
        expiry: str = "2512",
    ) -> HCE_Token:
        """
        Generate a complete HCE token: DPAN + ICC_MK + LUK batch.

        In production this runs inside the TSP's HSM.  Here we replicate
        it locally so the lab can validate the full token lifecycle without
        needing a live VTS/MDES sandbox connection.

        Args:
            fpan:           Real card PAN.  Used ONLY to demonstrate that the
                            DPAN is distinct and separate from it.  In a real
                            TSP flow, fpan is submitted over TLS and immediately
                            forgotten — it never appears in the token record.
            psn:            PAN Sequence Number.
            scheme:         "VISA" or "MASTERCARD".
            device_id:      Unique device identifier for token binding.
            luk_batch_size: Number of LUKs to pre-compute (Visa default = 10).
            expiry:         Token expiry as MMYY.

        Returns:
            HCE_Token ready to load into modules/hce_manager.py.
        """
        # 1. DPAN — the only PAN that ever leaves this function
        dpan = self._make_dpan(scheme)

        # 2. ICC_MK derived from DPAN (NOT fpan) — this is the crucial security
        #    boundary. The device never needs to know the real card's ICC_MK.
        icc_mk = self._emv.derive_icc_mk(dpan, psn)

        # 3. Pre-compute LUK batch — one per ATC starting from 1
        luk_batch = []
        for atc in range(1, luk_batch_size + 1):
            sk_enc, sk_mac = self._emv.derive_session_keys(icc_mk, atc)
            luk = sk_enc + sk_mac   # full 32-byte key material
            luk_batch.append({"atc": atc, "luk": luk})

            # Store in HSM if available
            if self._hsm is not None:
                try:
                    self._hsm._emulator.import_key(
                        f"LUK-{dpan[-4:]}-ATC{atc}", luk[:16]
                    )
                except Exception:
                    pass

        token_ref = f"{scheme[:2].upper()}-{device_id[:8].upper()}-{secrets.token_hex(4).upper()}"

        return HCE_Token(
            dpan=dpan, token_ref=token_ref, icc_mk=icc_mk,
            luk_batch=luk_batch, current_atc=1,
            scheme=scheme.upper(), expiry=expiry,
        )

    def get_luk(self, token: HCE_Token, atc: Optional[int] = None) -> bytes:
        """Return the LUK for a given ATC, deriving on-the-fly if not in batch."""
        target = atc if atc is not None else token.current_atc
        for entry in token.luk_batch:
            if entry["atc"] == target:
                return entry["luk"]
        # Not in pre-computed batch — derive it now
        sk_enc, sk_mac = self._emv.derive_session_keys(token.icc_mk, target)
        return sk_enc + sk_mac

    def compute_arqc(
        self,
        token: HCE_Token,
        txn_data: Optional[bytes] = None,
        atc: Optional[int] = None,
    ) -> Tuple[bytes, int]:
        """
        Compute the ARQC for one HCE tap.

        The LUK is 32 bytes = SK_ENC (16B) || SK_MAC (16B).
        ARQC uses only the SK_MAC half — same algorithm as Generator 2.

        Returns:
            (arqc_bytes, atc_used)
        """
        target = atc if atc is not None else token.current_atc
        luk    = self.get_luk(token, target)
        sk_mac = luk[16:32]                           # second half = MAC key
        data   = txn_data if txn_data is not None else b'\x00' * 22
        arqc   = self._emv.compute_arqc(sk_mac, data)
        return arqc, target


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

# Default lab key — factory default on every uninitialized JCOP card.
# Published in the GP specification.  NEVER use in production.
JCOP_DEFAULT_LAB_KEY = "404142434445464748494A4B4C4D4E4F"

# Well-known test PANs (public test values documented by Visa/MC)
VISA_TEST_PAN = "4111111111111111"
MC_TEST_PAN   = "5425233430109903"


# ─────────────────────────────────────────────────────────────────────────────
# CLI DEMO — run `python core/key_generators.py` to see all four generators
# ─────────────────────────────────────────────────────────────────────────────

def _sep(title: str) -> None:
    w = 70
    print(f"\n{'═'*w}\n  {title}\n{'═'*w}")

def _row(label: str, value: str) -> None:
    print(f"  {label:<22} {value}")

def demo_all(master_key: str = JCOP_DEFAULT_LAB_KEY) -> None:
    """Print a full demonstration of all four generators."""
    print(f"\n  Master Key (JCOP lab default): {master_key}")

    _sep("GENERATOR 1 — GP Static Diversification  [Factory/Personalisation]")
    g1 = GP_StaticDiversification(master_key)
    ks1 = g1.derive("DEADBEEF01234567")
    for k, v in ks1.display().items():
        _row(k, v)
    print()
    print("  → These three keys are burned into the JCOP chip ISD at the factory.")
    print("  → ENC/MAC/DEK are unique per card serial; derived on demand by TSM.")

    _sep("GENERATOR 2 — EMV Dynamic Session Keys  [Per-Transaction ARQC]")
    g2 = EMV_DynamicSessionKeys(master_key)
    r2 = g2.generate(pan=VISA_TEST_PAN, psn="00", atc=5)
    for k, v in r2.display().items():
        _row(k, v)
    r2b = g2.generate(pan=VISA_TEST_PAN, psn="00", atc=6)
    print(f"\n  ATC=6 SK_ENC: {r2b.sk_enc.hex().upper()}  ← completely different from ATC=5")
    print(f"  ATC=6 ARQC:   {r2b.arqc.hex().upper()}  ← replay impossible")

    _sep("GENERATOR 3 — SCP03 AES Key Derivation  [JCOP5 OTA Channel]")
    g3 = SCP03_AESKeyDerivation(master_key)
    hc = bytes.fromhex("0102030405060708")
    cc = bytes.fromhex("A1B2C3D4E5F60708")
    ks3, card_cg, host_cg = g3.derive_with_cryptograms(hc, cc)
    for k, v in ks3.display().items():
        _row(k, v)
    _row("CARD_CRYPTOGRAM", card_cg.hex().upper())
    _row("HOST_CRYPTOGRAM", host_cg.hex().upper())
    print()
    print("  → S-ENC/S-MAC/S-RMAC/S-DEK protect each APDU in the OTA channel.")
    print("  → Cryptograms prove mutual authentication before channel opens.")

    _sep("GENERATOR 4 — HCE Token Key Generator  [Android NFC / No Physical SE]")
    g4    = HCE_TokenKeyGenerator(master_key)
    token = g4.generate_token(VISA_TEST_PAN, psn="00", scheme="VISA",
                               device_id="lab_android", luk_batch_size=3)
    for k, v in token.display().items():
        _row(k, v)
    arqc4, atc4 = g4.compute_arqc(token)
    _row(f"ARQC (ATC={atc4})", arqc4.hex().upper())
    print()
    print("  → DPAN is different from the real PAN — real PAN never on device.")
    print("  → LUK is pre-computed by TSP and delivered to Android TEE via OTA.")
    print("  → ARQC computed by HCEManager when reader sends GENERATE AC.")
    print(f"\n{'═'*70}\n")


if __name__ == "__main__":
    import sys
    key = sys.argv[1] if len(sys.argv) > 1 else JCOP_DEFAULT_LAB_KEY
    demo_all(key)
