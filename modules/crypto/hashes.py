"""
GREENWIRE Hash Functions
========================
Cryptographic hash functions using Python's built-in hashlib.
"""

import hashlib
import hmac
from typing import Union


def hash_sha256(data: Union[str, bytes]) -> bytes:
    """Compute SHA-256 hash of data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()


def hash_sha1(data: Union[str, bytes]) -> bytes:
    """Compute SHA-1 hash of data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha1(data).digest()


def hash_md5(data: Union[str, bytes]) -> bytes:
    """Compute MD5 hash of data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).digest()


def hash_sha512(data: Union[str, bytes]) -> bytes:
    """Compute SHA-512 hash of data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha512(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256 of data with key."""
    return hmac.new(key, data, hashlib.sha256).digest()


def pbkdf2(password: Union[str, bytes], salt: bytes, iterations: int = 10000, key_length: int = 32) -> bytes:
    """Derive key from password using PBKDF2-HMAC-SHA256."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, key_length)