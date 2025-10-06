#!/usr/bin/env python3
"""
Comprehensive MAC/CMAC Engine for GREENWIRE
Implements all EMV/ISO MAC variants for card personalization and fuzzing.
"""

import hashlib
import hmac
import struct
from typing import Optional, Union

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import cmac
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class MACEngine:
    """Comprehensive MAC generation engine for EMV and ISO standards."""

    def __init__(self):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography library required for MAC operations")

    # ========================================================================
    # ISO 9797-1 MAC Algorithms
    # ========================================================================

    def mac_iso9797_alg1(self, key: bytes, data: bytes) -> bytes:
        """
        ISO 9797-1 Algorithm 1: DES CBC-MAC with zero IV.

        Used for: Legacy EMV MAC generation
        Key: 8 bytes (single DES) or 16/24 bytes (3DES)
        Output: 8 bytes
        """
        padded = self._iso9797_pad(data)

        if len(key) == 8:
            # Single DES
            cipher = Cipher(algorithms.TripleDES(key * 3), modes.CBC(b'\x00' * 8), 
                            backend=default_backend())
        else:
            # 3DES
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b'\x00' * 8),
                            backend=default_backend())

        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        return encrypted[-8:]  # Last block is the MAC

    def mac_iso9797_alg3(self, key: bytes, data: bytes) -> bytes:
        """
        ISO 9797-1 Algorithm 3: Retail MAC (DES3-CBC-MAC).

        Most common EMV MAC algorithm.
        Process: DES CBC on all blocks except last, then 3DES on final block.
        Key: 16 or 24 bytes (3DES double or triple length)
        Output: 8 bytes

        This is the standard "Retail MAC" used in EMV transactions.
        """
        padded = self._iso9797_pad(data)

        # Extract keys for retail MAC
        if len(key) == 16:
            k1 = key[:8]
            k2 = key[8:16]
            k3 = k1  # Double length key: K3 = K1
        elif len(key) == 24:
            k1 = key[:8]
            k2 = key[8:16]
            k3 = key[16:24]
        else:
            raise ValueError("Key must be 16 or 24 bytes for Retail MAC")

        # CBC with single DES on all blocks except last
        iv = b'\x00' * 8
        for i in range(0, len(padded) - 8, 8):
            block = padded[i:i+8]
            xored = bytes(a ^ b for a, b in zip(block, iv))
            cipher = Cipher(algorithms.TripleDES(k1 * 3), modes.ECB(), 
                            backend=default_backend())
            encryptor = cipher.encryptor()
            iv = encryptor.update(xored) + encryptor.finalize()
            iv = iv[:8]

        # Final block with full 3DES
        last_block = padded[-8:]
        xored = bytes(a ^ b for a, b in zip(last_block, iv))

        # Encrypt with k1, decrypt with k2, encrypt with k3 (EDE)
        cipher1 = Cipher(algorithms.TripleDES(k1 * 3), modes.ECB(), 
                         backend=default_backend())
        temp = cipher1.encryptor().update(xored) + cipher1.encryptor().finalize()

        cipher2 = Cipher(algorithms.TripleDES(k2 * 3), modes.ECB(),
                         backend=default_backend())
        temp = cipher2.decryptor().update(temp[:8]) + cipher2.decryptor().finalize()

        cipher3 = Cipher(algorithms.TripleDES(k3 * 3), modes.ECB(),
                         backend=default_backend())
        mac = cipher3.encryptor().update(temp[:8]) + cipher3.encryptor().finalize()

        return mac[:8]

    # ========================================================================
    # CMAC (AES/3DES)
    # ========================================================================

    def cmac_aes(self, key: bytes, data: bytes) -> bytes:
        """
        CMAC with AES (NIST SP 800-38B).

        Used for: Modern EMV, JavaCard secure messaging
        Key: 16, 24, or 32 bytes (AES-128/192/256)
        Output: 16 bytes (full), truncate as needed
        """
        c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        c.update(data)
        return c.finalize()

    def cmac_3des(self, key: bytes, data: bytes) -> bytes:
        """
        CMAC with 3DES (NIST SP 800-38B).

        Used for: Legacy EMV secure messaging
        Key: 16 or 24 bytes (3DES)
        Output: 8 bytes
        """
        c = cmac.CMAC(algorithms.TripleDES(key), backend=default_backend())
        c.update(data)
        return c.finalize()

    # ========================================================================
    # HMAC Variants
    # ========================================================================

    def hmac_sha1(self, key: bytes, data: bytes) -> bytes:
        """HMAC-SHA1 (legacy EMV)."""
        return hmac.new(key, data, hashlib.sha1).digest()

    def hmac_sha256(self, key: bytes, data: bytes) -> bytes:
        """HMAC-SHA256 (modern EMV)."""
        return hmac.new(key, data, hashlib.sha256).digest()

    # ========================================================================
    # EMV-Specific MAC Operations
    # ========================================================================

    def emv_mac_session_key(self, master_key: bytes, atc: bytes, arqc: bytes = None) -> bytes:
        """
        Derive EMV session MAC key from master key and ATC.

        Process:
        1. Concatenate derivation data (ATC + padding or ARQC)
        2. Encrypt with master key using 3DES
        3. Return session key

        Args:
            master_key: 16 or 24 byte master key
            atc: 2-byte Application Transaction Counter
            arqc: Optional 8-byte ARQC for key diversification

        Returns:
            16-byte session MAC key
        """
        if arqc:
            # Method 1: Use ARQC for diversification
            derivation_data = arqc
        else:
            # Method 2: Use ATC with padding
            derivation_data = atc + b'\x00' * 6

        # Encrypt derivation data with master key
        cipher = Cipher(algorithms.TripleDES(master_key), modes.ECB(),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        session_key = encryptor.update(derivation_data) + encryptor.finalize()

        # Return 16 bytes (double length key)
        return session_key[:16]

    def emv_arqc_mac(self, session_key: bytes, transaction_data: bytes) -> bytes:
        """
        Generate EMV ARQC (Authorization Request Cryptogram).

        Uses ISO 9797-1 Algorithm 3 (Retail MAC) on transaction data.

        Args:
            session_key: 16-byte session MAC key
            transaction_data: Transaction data to MAC

        Returns:
            8-byte ARQC/MAC
        """
        return self.mac_iso9797_alg3(session_key, transaction_data)

    def emv_ac_mac(self, session_key: bytes, ac_data: bytes, ac_type: str = "ARQC") -> bytes:
        """
        Generate EMV Application Cryptogram (AC).

        AC Types:
        - ARQC: Authorization Request Cryptogram (online)
        - AAC: Application Authentication Cryptogram (declined)
        - TC: Transaction Certificate (offline approved)

        Args:
            session_key: Session key for MAC
            ac_data: Data to generate AC from
            ac_type: Type of AC (ARQC, AAC, TC)

        Returns:
            8-byte cryptogram
        """
        # All AC types use same MAC algorithm, differ in CDA (Cryptogram Version Number)
        return self.mac_iso9797_alg3(session_key, ac_data)

    # ========================================================================
    # Utility Functions
    # ========================================================================

    def _iso9797_pad(self, data: bytes) -> bytes:
        """
        ISO/IEC 9797-1 Padding Method 2 (ISO padding).

        Append 0x80 followed by zero bytes to reach block boundary.
        """
        padded = data + b'\x80'
        pad_len = 8 - (len(padded) % 8)
        if pad_len < 8:
            padded += b'\x00' * pad_len
        return padded

    def truncate_mac(self, mac: bytes, length: int) -> bytes:
        """Truncate MAC to specified length (common: 4 or 8 bytes)."""
        return mac[:length]

    # ========================================================================
    # Fuzzing Support: MAC Mutation
    # ========================================================================

    def fuzz_mac_bitflip(self, mac: bytes, bit_position: int) -> bytes:
        """Flip a single bit in MAC for fuzzing."""
        mac_array = bytearray(mac)
        byte_pos = bit_position // 8
        bit_pos = bit_position % 8
        mac_array[byte_pos] ^= (1 << bit_pos)
        return bytes(mac_array)

    def fuzz_mac_nibble(self, mac: bytes, nibble_position: int, new_value: int) -> bytes:
        """Replace a nibble (4 bits) in MAC."""
        mac_array = bytearray(mac)
        byte_pos = nibble_position // 2
        is_high = nibble_position % 2 == 0

        if is_high:
            mac_array[byte_pos] = (mac_array[byte_pos] & 0x0F) | ((new_value & 0x0F) << 4)
        else:
            mac_array[byte_pos] = (mac_array[byte_pos] & 0xF0) | (new_value & 0x0F)

        return bytes(mac_array)

    def fuzz_mac_incremental(self, mac: bytes) -> bytes:
        """Increment MAC as an integer (common fuzzing technique)."""
        mac_int = int.from_bytes(mac, 'big')
        mac_int = (mac_int + 1) % (2 ** (len(mac) * 8))
        return mac_int.to_bytes(len(mac), 'big')

    # ========================================================================
    # Verification
    # ========================================================================

    def verify_mac(self, key: bytes, data: bytes, expected_mac: bytes, 
                   algorithm: str = "retail") -> bool:
        """
        Verify MAC against expected value.

        Args:
            key: MAC key
            data: Data that was MACed
            expected_mac: MAC to verify against
            algorithm: MAC algorithm (retail, cmac_aes, hmac_sha256, etc.)

        Returns:
            True if MAC is valid
        """
        if algorithm == "retail":
            computed = self.mac_iso9797_alg3(key, data)
        elif algorithm == "cmac_aes":
            computed = self.cmac_aes(key, data)
        elif algorithm == "hmac_sha256":
            computed = self.hmac_sha256(key, data)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        return hmac.compare_digest(computed[:len(expected_mac)], expected_mac)

    # ========================================================================
    # Key Check Value (KCV)
    # ========================================================================

    def generate_kcv(self, key: bytes, algorithm: str = "3des") -> bytes:
        """
        Generate Key Check Value (KCV) for key verification.

        Process: Encrypt zero block with key, return first 3 bytes.

        Args:
            key: Cryptographic key
            algorithm: Encryption algorithm (3des, aes)

        Returns:
            3-byte KCV
        """
        zero_block = b'\x00' * 8 if algorithm == "3des" else b'\x00' * 16

        if algorithm == "3des":
            cipher = Cipher(algorithms.TripleDES(key), modes.ECB(),
                            backend=default_backend())
        elif algorithm == "aes":
            cipher = Cipher(algorithms.AES(key), modes.ECB(),
                            backend=default_backend())
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        encryptor = cipher.encryptor()
        encrypted = encryptor.update(zero_block) + encryptor.finalize()
        return encrypted[:3]


# Convenience functions for quick access
def generate_retail_mac(key: bytes, data: bytes) -> bytes:
    """Quick access to ISO 9797-1 Algorithm 3 (Retail MAC)."""
    engine = MACEngine()
    return engine.mac_iso9797_alg3(key, data)


def generate_cmac_aes(key: bytes, data: bytes) -> bytes:
    """Quick access to AES-CMAC."""
    engine = MACEngine()
    return engine.cmac_aes(key, data)


def generate_emv_arqc(session_key: bytes, transaction_data: bytes) -> bytes:
    """Quick access to EMV ARQC generation."""
    engine = MACEngine()
    return engine.emv_arqc_mac(session_key, transaction_data)


def verify_retail_mac(key: bytes, data: bytes, mac: bytes) -> bool:
    """Quick MAC verification."""
    engine = MACEngine()
    return engine.verify_mac(key, data, mac, algorithm="retail")


if __name__ == "__main__":
    # Test MAC engine
    print("MAC Engine Test Suite")
    print("=" * 60)

    engine = MACEngine()

    # Test Retail MAC (ISO 9797-1 Algorithm 3)
    test_key = b'TESTKEY1' * 2  # 16 bytes
    test_data = b'Transaction data for MAC'

    print("\n1. Retail MAC (ISO 9797-1 Algorithm 3)")
    retail_mac = engine.mac_iso9797_alg3(test_key, test_data)
    print(f"   Key: {test_key.hex().upper()}")
    print(f"   Data: {test_data.decode()}")
    print(f"   MAC: {retail_mac.hex().upper()}")

    # Test AES-CMAC
    aes_key = b'0123456789ABCDEF'  # 16 bytes
    print("\n2. AES-CMAC")
    aes_cmac = engine.cmac_aes(aes_key, test_data)
    print(f"   Key: {aes_key.hex().upper()}")
    print(f"   Data: {test_data.decode()}")
    print(f"   CMAC: {aes_cmac.hex().upper()}")

    # Test EMV ARQC
    master_key = b'MASTERKEY0000001'
    atc = b'\x00\x42'  # Transaction counter
    print("\n3. EMV ARQC Generation")
    session_key = engine.emv_mac_session_key(master_key, atc)
    print(f"   Master Key: {master_key.hex().upper()}")
    print(f"   ATC: {atc.hex().upper()}")
    print(f"   Session Key: {session_key.hex().upper()}")

    transaction_data = b'9F0206000000001000'  # Amount and other data
    arqc = engine.emv_arqc_mac(session_key, transaction_data)
    print(f"   Transaction Data: {transaction_data.hex().upper()}")
    print(f"   ARQC: {arqc.hex().upper()}")

    # Test KCV
    print("\n4. Key Check Value (KCV)")
    kcv = engine.generate_kcv(test_key, "3des")
    print(f"   Key: {test_key.hex().upper()}")
    print(f"   KCV: {kcv.hex().upper()}")

    print("\n" + "=" * 60)
    print("All MAC operations successful!")
