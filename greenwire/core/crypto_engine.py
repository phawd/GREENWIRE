import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def rsa_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Sign data with RSA using SHA-256."""
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def rsa_verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """Verify RSA signature."""
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def generate_ec_key() -> ec.EllipticCurvePrivateKey:
    """Generate an ECC private key (P-256)."""
    return ec.generate_private_key(ec.SECP256R1())


def ec_sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Sign data with ECC using SHA-256."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def ec_verify(public_key: ec.EllipticCurvePublicKey, signature: bytes, data: bytes) -> bool:
    """Verify ECC signature."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def aes_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """Encrypt plaintext using AES-CBC with PKCS7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len] * pad_len)
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """Decrypt AES-CBC ciphertext with PKCS7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]


def sha256(data: bytes) -> str:
    """Return the hex SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()
