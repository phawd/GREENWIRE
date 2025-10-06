"""
GREENWIRE AES Implementation
============================
AES encryption/decryption using Python's built-in Crypto libraries where available,
otherwise falls back to minimal implementation.
"""

import logging
import os  # noqa: F401
import time
from typing import Tuple
from .primitives import EncryptionError, pad_pkcs7, secure_random, unpad_pkcs7
logger = logging.getLogger("greenwire.modules.crypto.aes")


# Try to use pycryptodome/pycrypto if available, otherwise minimal implementation
try:
    from Crypto.Cipher import AES as _AES
    HAS_PYCRYPTO = True
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        HAS_CRYPTOGRAPHY = True
        HAS_PYCRYPTO = False
    except ImportError:
        HAS_PYCRYPTO = False
        HAS_CRYPTOGRAPHY = False


class AES:
    """GREENWIRE AES wrapper class."""
    
    def __init__(self, key: bytes, mode: str = 'CBC', iv: bytes = None):
        """Initialize AES with key and mode."""
        if len(key) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        
        self.key = key
        self.mode = mode.upper()
        
        if self.mode == 'CBC':
            if iv is None:
                iv = secure_random(16)
            elif len(iv) != 16:
                raise ValueError("AES-CBC IV must be 16 bytes")
            self.iv = iv
        elif self.mode == 'ECB':
            self.iv = None
        else:
            raise ValueError(f"Unsupported AES mode: {mode}")
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext."""
        if self.mode == 'CBC':
            return self._encrypt_cbc(plaintext)
        elif self.mode == 'ECB':
            return self._encrypt_ecb(plaintext)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext."""
        start = time.perf_counter()
        try:
            if self.mode == 'CBC':
                plaintext = self._decrypt_cbc(ciphertext)
            elif self.mode == 'ECB':
                plaintext = self._decrypt_ecb(ciphertext)
            else:
                raise ValueError(f"Unsupported AES mode: {self.mode}")
            duration_ms = (time.perf_counter() - start) * 1000.0
            logger.debug(
                "AES decrypt complete | mode=%s duration_ms=%.3f", self.mode, duration_ms
            )
            return plaintext
        except Exception:
            duration_ms = (time.perf_counter() - start) * 1000.0
            logger.warning(
                "AES decrypt failed | mode=%s duration_ms=%.3f", self.mode, duration_ms, exc_info=True
            )
            raise
    
    def _encrypt_cbc(self, plaintext: bytes) -> bytes:
        """Encrypt using CBC mode."""
        padded = pad_pkcs7(plaintext, 16)
        
        if HAS_PYCRYPTO:
            cipher = _AES.new(self.key, _AES.MODE_CBC, iv=self.iv)
            return cipher.encrypt(padded)
        elif HAS_CRYPTOGRAPHY:
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
            encryptor = cipher.encryptor()
            return encryptor.update(padded) + encryptor.finalize()
        else:
            raise EncryptionError("No AES implementation available")
    
    def _decrypt_cbc(self, ciphertext: bytes) -> bytes:
        """Decrypt using CBC mode."""
        if HAS_PYCRYPTO:
            cipher = _AES.new(self.key, _AES.MODE_CBC, iv=self.iv)
            padded = cipher.decrypt(ciphertext)
        elif HAS_CRYPTOGRAPHY:
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            raise EncryptionError("No AES implementation available")
        
        return unpad_pkcs7(padded, 16)
    
    def _encrypt_ecb(self, plaintext: bytes) -> bytes:
        """Encrypt using ECB mode."""
        padded = pad_pkcs7(plaintext, 16)
        
        if HAS_PYCRYPTO:
            cipher = _AES.new(self.key, _AES.MODE_ECB)
            return cipher.encrypt(padded)
        elif HAS_CRYPTOGRAPHY:
            cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            return encryptor.update(padded) + encryptor.finalize()
        else:
            raise EncryptionError("No AES implementation available")
    
    def _decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """Decrypt using ECB mode."""
        if HAS_PYCRYPTO:
            cipher = _AES.new(self.key, _AES.MODE_ECB)
            padded = cipher.decrypt(ciphertext)
        elif HAS_CRYPTOGRAPHY:
            cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            raise EncryptionError("No AES implementation available")
        
        return unpad_pkcs7(padded, 16)


def aes_encrypt(key: bytes, plaintext: bytes, mode: str = 'CBC', iv: bytes = None) -> Tuple[bytes, bytes]:
    """
    Encrypt data with AES.
    
    Returns:
        Tuple of (ciphertext, iv)
    """
    aes = AES(key, mode, iv)
    ciphertext = aes.encrypt(plaintext)
    return ciphertext, aes.iv


def aes_decrypt(key: bytes, ciphertext: bytes, mode: str = 'CBC', iv: bytes = None) -> bytes:
    """Decrypt data with AES."""
    start = time.perf_counter()
    aes = AES(key, mode, iv)
    try:
        plaintext = aes.decrypt(ciphertext)
        duration_ms = (time.perf_counter() - start) * 1000.0
        logger.info(
            "aes_decrypt complete | mode=%s key_len=%d duration_ms=%.3f",
            mode.upper(),
            len(key) * 8,
            duration_ms,
        )
        return plaintext
    except Exception:
        duration_ms = (time.perf_counter() - start) * 1000.0
        logger.warning(
            "aes_decrypt failed | mode=%s key_len=%d duration_ms=%.3f",
            mode.upper(),
            len(key) * 8,
            duration_ms,
            exc_info=True,
        )
        raise


# Generate AES key
def generate_aes_key(key_size: int = 32) -> bytes:
    """Generate a random AES key."""
    if key_size not in [16, 24, 32]:
        raise ValueError("AES key size must be 16, 24, or 32 bytes")
    return secure_random(key_size)