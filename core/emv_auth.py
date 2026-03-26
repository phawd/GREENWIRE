"""
Lightweight EMV authentication helpers.

Provides functions to generate RSA/ECDSA keys, build simple X.509 certificates and
perform DDA/SDA-style signing and verification operations. This module requires the
`cryptography` package. If it's not installed the functions will raise a clear
RuntimeError explaining how to install the dependency.

Note: This is a research/test helper for EMV flows (SDA/DDA/CDA) and is not a
production PKI implementation. It intentionally keeps certificate fields minimal
and focuses on formats used by EMV (signature generation/verification).
"""
from typing import Tuple, Optional

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    raise RuntimeError(
        "The 'cryptography' package is required for GREENWIRE.core.emv_auth. "
        "Install it in your environment (pip install cryptography) and rerun. "
        f"Underlying error: {e}"
    )

import datetime


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA private key usable for EMV DDA signing.

    Returns the private key object (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey).
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())


def generate_ecdsa_key(curve: ec.EllipticCurve = ec.SECP256R1()) -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA private key (secp256r1 by default).

    Returns the private key object.
    """
    return ec.generate_private_key(curve, backend=default_backend())


def build_self_signed_cert(private_key, subject_common_name: str = 'GREENWIRE EMV Test CA') -> x509.Certificate:
    """Create a minimal self-signed X.509 certificate for testing.

    The certificate is valid for 10 years and contains only the common name.
    """
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
    )

    # Use appropriate signature algorithm depending on key type
    if isinstance(private_key, rsa.RSAPrivateKey):
        signature_algo = hashes.SHA256()
        return builder.sign(private_key, signature_algo, default_backend())
    else:
        signature_algo = hashes.SHA256()
        return builder.sign(private_key, signature_algo, default_backend())


def serialize_private_key_pem(private_key, password: Optional[bytes] = None) -> bytes:
    """Serialize a private key to PEM. If password provided, the key will be encrypted.
    """
    enc_algo = (
        serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo,
    )


def serialize_public_key_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def serialize_cert_pem(certificate: x509.Certificate) -> bytes:
    """Serialize an X.509 certificate to PEM bytes."""
    return certificate.public_bytes(serialization.Encoding.PEM)


def sign_dda_rsa(private_key: rsa.RSAPrivateKey, data: bytes, hash_alg=hashes.SHA256()) -> bytes:
    """Sign data using RSA PKCS#1 v1.5 suitable for EMV DDA.

    EMV historically used SHA1 with RSA; this helper defaults to SHA256 but callers
    can pass a different hash algorithm if needed for compatibility.
    """
    signer = private_key.sign(
        data,
        padding.PKCS1v15(),
        hash_alg
    )
    return signer


def verify_dda_rsa(public_key, data: bytes, signature: bytes, hash_alg=hashes.SHA256()) -> bool:
    """Verify DDA RSA signature. Returns True if signature is valid, False otherwise."""
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hash_alg)
        return True
    except Exception:
        return False


def sign_dda_ecdsa(private_key: ec.EllipticCurvePrivateKey, data: bytes, hash_alg=hashes.SHA256()) -> bytes:
    """Sign data using ECDSA (for newer EMV ECC-based DDA variants)."""
    signature = private_key.sign(data, ec.ECDSA(hash_alg))
    return signature


def verify_dda_ecdsa(public_key, data: bytes, signature: bytes, hash_alg=hashes.SHA256()) -> bool:
    try:
        public_key.verify(signature, data, ec.ECDSA(hash_alg))
        return True
    except Exception:
        return False


def emv_create_static_auth_data(certificate: x509.Certificate, *, issuer: str = None, holder: str = None, merchant: str = None, static_data: bytes = None) -> bytes:
    """Create a basic SDA-like artifact for tests.

    Parameters can be passed either via a pre-built `static_data` bytes blob or
    via `issuer`, `holder`, and `merchant` strings which will be concatenated.

    Returns: DER(cert) || b"--EMV-SDA--" || static_data_bytes
    """
    if static_data is None:
        parts = []
        if issuer:
            parts.append(f"ISSUER:{issuer}")
        if holder:
            parts.append(f"HOLDER:{holder}")
        if merchant:
            parts.append(f"MERCHANT:{merchant}")
        static_data = "|".join(parts).encode('utf-8')

    return certificate.public_bytes(serialization.Encoding.DER) + b"--EMV-SDA--" + static_data
