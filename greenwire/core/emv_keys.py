from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def generate_rsa_keypair(key_size: int = 1024):
    """Generate an RSA private/public key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_bytes, public_bytes


def generate_emv_keyset(key_size: int = 1024):
    """Generate CA, issuer, and ICC key pairs for EMV SDA/DDA."""
    ca_priv, ca_pub = generate_rsa_keypair(key_size)
    issuer_priv, issuer_pub = generate_rsa_keypair(key_size)
    icc_priv, icc_pub = generate_rsa_keypair(key_size)
    return {
        "ca_private": ca_priv,
        "ca_public": ca_pub,
        "issuer_private": issuer_priv,
        "issuer_public": issuer_pub,
        "icc_private": icc_priv,
        "icc_public": icc_pub,
    }


def sign_sda_data(data: bytes, issuer_private_pem: bytes) -> bytes:
    """Create a simple signature over card static data (SDA)."""
    private_key = serialization.load_pem_private_key(issuer_private_pem, password=None)
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA1())

