"""
GREENWIRE Cryptographic Primitives
===================================
Core cryptographic functions and utilities.
"""

import os, secrets  # noqa: F401
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def secure_random(length: int = 16) -> bytes:
    """Generate cryptographically secure random bytes."""
    return secrets.token_bytes(length)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays of equal length."""
    if len(a) != len(b):
        raise ValueError("Byte arrays must be of equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding to data."""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def unpad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """Remove PKCS#7 padding from data."""
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    
    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding length")
    
    # Verify padding is correct
    for i in range(padding_length):
        if data[-(i + 1)] != padding_length:
            raise ValueError("Invalid padding")
    
    return data[:-padding_length]


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex().upper()


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_string)


def encrypt_tdes_ecb(key: bytes, data: bytes) -> bytes:
    """Encrypt data using Triple DES in ECB mode.
    
    Args:
        key: 16-byte or 24-byte Triple DES key
        data: Data to encrypt (must be multiple of 8 bytes)
        
    Returns:
        Encrypted data
    """
    if len(key) == 16:
        # Convert 2-key TDES to 3-key TDES by duplicating first key
        key = key + key[:8]
    elif len(key) != 24:
        raise ValueError("Key must be 16 or 24 bytes for Triple DES")
    
    if len(data) % 8 != 0:
        raise ValueError("Data length must be multiple of 8 bytes for DES")
    
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def decrypt_tdes_ecb(key: bytes, data: bytes) -> bytes:
    """Decrypt data using Triple DES in ECB mode.
    
    Args:
        key: 16-byte or 24-byte Triple DES key
        data: Data to decrypt (must be multiple of 8 bytes)
        
    Returns:
        Decrypted data
    """
    if len(key) == 16:
        # Convert 2-key TDES to 3-key TDES by duplicating first key
        key = key + key[:8]
    elif len(key) != 24:
        raise ValueError("Key must be 16 or 24 bytes for Triple DES")
    
    if len(data) % 8 != 0:
        raise ValueError("Data length must be multiple of 8 bytes for DES")
    
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def adjust_key_parity(key: bytes) -> bytes:
    """Adjust DES key parity bits.
    
    Each byte of a DES key should have odd parity (odd number of 1 bits).
    This function adjusts the least significant bit of each byte to ensure odd parity.
    
    Args:
        key: DES key bytes
        
    Returns:
        Key with adjusted parity bits
    """
    adjusted = bytearray()
    
    for byte in key:
        # Count number of 1 bits in the upper 7 bits
        ones = bin(byte >> 1).count('1')
        
        # Set LSB to make total number of 1 bits odd
        if ones % 2 == 0:
            # Even number of 1s in upper 7 bits, set LSB to 1
            adjusted.append((byte & 0xFE) | 0x01)
        else:
            # Odd number of 1s in upper 7 bits, set LSB to 0
            adjusted.append(byte & 0xFE)
    
    return bytes(adjusted)


def calculate_key_check_digits(key: bytes, digits: int = 3) -> bytes:
    """Calculate key check digits using Triple DES encryption of zeros.
    
    Args:
        key: DES key
        digits: Number of check digits to return (1-8)
        
    Returns:
        Check digits as bytes
    """
    # Encrypt 8 bytes of zeros with the key
    check_data = encrypt_tdes_ecb(key, b'\x00' * 8)
    
    # Return requested number of digits
    return check_data[:digits]


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string to bytes."""
    # Remove any spaces or colons
    hex_string = hex_string.replace(" ", "").replace(":", "")
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string must have even length")
    return bytes.fromhex(hex_string)


class GreenwireCryptoError(Exception):
    """Base exception for GREENWIRE crypto operations."""
    pass


class InvalidSignatureError(GreenwireCryptoError):
    """Exception raised when signature verification fails."""
    pass


class EncryptionError(GreenwireCryptoError):
    """Exception raised when encryption/decryption fails."""
    pass