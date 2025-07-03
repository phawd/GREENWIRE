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


def rsa_verify(
    public_key: rsa.RSAPublicKey,
    signature: bytes,
    data: bytes,
) -> bool:
    """Verify RSA signature."""
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def rsa_encrypt(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    """Encrypt ``data`` with RSA using OAEP."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decrypt OAEP ``ciphertext`` with RSA."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def generate_ec_key() -> ec.EllipticCurvePrivateKey:
    """Generate an ECC private key (P-256)."""
    return ec.generate_private_key(ec.SECP256R1())


def ec_sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Sign data with ECC using SHA-256."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def ec_verify(
    public_key: ec.EllipticCurvePublicKey,
    signature: bytes,
    data: bytes,
) -> bool:
    """Verify ECC signature."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def aes_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """Encrypt plaintext using AES-CBC with PKCS7 padding."""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len] * pad_len)
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """Decrypt AES-CBC ciphertext with PKCS7 padding."""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]


def aes_gcm_encrypt(key: bytes, plaintext: bytes, iv: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt ``plaintext`` using AES-GCM with optional ``aad``."""
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag


def aes_gcm_decrypt(key: bytes, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt AES-GCM ``ciphertext`` verifying ``tag`` and ``aad``."""
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(aad)
    return decryptor.update(ciphertext) + decryptor.finalize()


def sha256(data: bytes) -> str:
    """Return the hex SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()
