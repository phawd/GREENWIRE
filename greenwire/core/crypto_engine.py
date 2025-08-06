

import hashlib
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("crypto_engine")

def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generate an RSA private key.
    :param key_size: Key size in bits (default 2048)
    :return: RSAPrivateKey object
    """
    try:
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    except Exception as e:
        logger.error(f"RSA key generation failed: {e}")
        raise

def rsa_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign data with RSA using SHA-256.
    :return: Signature bytes
    """
    try:
        return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        logger.error(f"RSA sign failed: {e}")
        raise

def rsa_verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """
    Verify RSA signature.
    :return: True if valid, False otherwise
    """
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception as e:
        logger.warning(f"RSA verify failed: {e}")
        return False

def rsa_encrypt(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    """
    Encrypt data with RSA using OAEP.
    :return: Ciphertext bytes
    """
    try:
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        logger.error(f"RSA encrypt failed: {e}")
        raise

def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """
    Decrypt OAEP ciphertext with RSA.
    :return: Plaintext bytes
    """
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        logger.error(f"RSA decrypt failed: {e}")
        raise

def generate_ec_key(curve=ec.SECP256R1()) -> ec.EllipticCurvePrivateKey:
    """
    Generate an ECC private key (default: P-256).
    :param curve: EllipticCurve object (default SECP256R1)
    :return: EllipticCurvePrivateKey object
    """
    try:
        return ec.generate_private_key(curve)
    except Exception as e:
        logger.error(f"EC key generation failed: {e}")
        raise

def ec_sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """
    Sign data with ECC using SHA-256.
    :return: Signature bytes
    """
    try:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    except Exception as e:
        logger.error(f"EC sign failed: {e}")
        raise

def ec_verify(public_key: ec.EllipticCurvePublicKey, signature: bytes, data: bytes) -> bool:
    """
    Verify ECC signature.
    :return: True if valid, False otherwise
    """
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        logger.warning(f"EC verify failed: {e}")
        return False

def aes_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """
    Encrypt plaintext using AES-CBC with PKCS7 padding.
    :return: Ciphertext bytes
    """
    try:
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        pad_len = 16 - len(plaintext) % 16
        padded = plaintext + bytes([pad_len] * pad_len)
        return encryptor.update(padded) + encryptor.finalize()
    except Exception as e:
        logger.error(f"AES encrypt failed: {e}")
        raise

def aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """
    Decrypt AES-CBC ciphertext with PKCS7 padding.
    :return: Plaintext bytes
    """
    try:
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded[-1]
        return padded[:-pad_len]
    except Exception as e:
        logger.error(f"AES decrypt failed: {e}")
        raise

def aes_gcm_encrypt(key: bytes, plaintext: bytes, iv: bytes, aad: bytes = b"") -> (bytes, bytes):
    """
    Encrypt plaintext using AES-GCM (authenticated encryption).
    :return: (ciphertext, tag)
    """
    try:
        aesgcm = aead.AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext, aad)
        # AESGCM returns ciphertext+tag; tag is last 16 bytes
        return ciphertext[:-16], ciphertext[-16:]
    except Exception as e:
        logger.error(f"AES-GCM encrypt failed: {e}")
        raise

def aes_gcm_decrypt(key: bytes, ciphertext: bytes, tag: bytes, iv: bytes, aad: bytes = b"") -> bytes:
    """
    Decrypt AES-GCM ciphertext.
    :return: Plaintext bytes
    """
    try:
        aesgcm = aead.AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext + tag, aad)
    except Exception as e:
        logger.error(f"AES-GCM decrypt failed: {e}")
        raise

def ed25519_generate_key() -> ed25519.Ed25519PrivateKey:
    """
    Generate an Ed25519 private key.
    :return: Ed25519PrivateKey object
    """
    try:
        return ed25519.Ed25519PrivateKey.generate()
    except Exception as e:
        logger.error(f"Ed25519 key generation failed: {e}")
        raise

def ed25519_sign(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """
    Sign data with Ed25519.
    :return: Signature bytes
    """
    try:
        return private_key.sign(data)
    except Exception as e:
        logger.error(f"Ed25519 sign failed: {e}")
        raise

def ed25519_verify(public_key: ed25519.Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """
    Verify Ed25519 signature.
    :return: True if valid, False otherwise
    """
    try:
        public_key.verify(signature, data)
        return True
    except Exception as e:
        logger.warning(f"Ed25519 verify failed: {e}")
        return False

def sha256(data: bytes) -> str:
    """
    Return the hex SHA-256 hash of data.
    :return: Hex string
    """
    return hashlib.sha256(data).hexdigest()

def sha3_256(data: bytes) -> str:
    """
    Return the hex SHA3-256 hash of data.
    :return: Hex string
    """
    return hashlib.sha3_256(data).hexdigest()
