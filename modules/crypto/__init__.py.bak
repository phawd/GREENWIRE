"""
GREENWIRE Cryptographic Library
===============================
A self-contained cryptographic module for GREENWIRE static distribution.
Provides RSA, AES, hashing, and other cryptographic primitives without external dependencies.

Based on Python's built-in hashlib and implements core cryptographic operations.
"""

__version__ = "1.0.0-greenwire"
__author__ = "GREENWIRE Project"

from .primitives import *
from .rsa import *
from .aes import *
from .hashes import *
from .emv_crypto import *
from .key_manager import *

__all__ = [
    'generate_rsa_keypair',
    'rsa_sign',
    'rsa_verify',
    'rsa_encrypt',
    'rsa_decrypt',
    'aes_encrypt',
    'aes_decrypt',
    'hash_sha256',
    'hash_sha1',
    'hash_md5',
    'secure_random',
    # EMV Cryptographic capabilities
    'EMVCryptoManager',
    'EMVKeyDerivation',
    'EMVApplicationCryptogram',
    'CVNType',
    'KeyDerivationMethod',
    'SessionKeyMethod',
    'VisaCVN10',
    'VisaCVN18',
    'VisaCVN22',
    'MasterCardCVN16',
    'MasterCardCVN17',
    'MasterCardCVN20',
    'MasterCardCVN21',
    'InteracCVN133',
    'create_emv_crypto_manager',
    'demonstrate_emv_capabilities',
    # Key Management & Cracking System
    'KeyManager',
    'KeyExtractor',
    'KeyCracker',
    'KeyDatabase',
    'ExtractedKey',
    'CrackingResult',
    'KeySource',
    'KeyType',
    'CrackingMethod',
    'create_key_manager',
]