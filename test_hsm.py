"""
This script demonstrates RSA key generation, serialization, file storage, loading, encryption/decryption, and signing/verification using the `cryptography` library.
Functionality:
- Generates new RSA key pairs for EMV use cases (ICC, CA, Issuer, Acquirer, Terminal, etc.)
- Optionally generates semi-random keys (with random or user-supplied seed)
- Serializes and saves keys to PEM files
- Loads keys back from PEM files
- Encrypts and decrypts a test message
- Signs and verifies a test message
- Can generate a self-signed CA certificate
Dependencies:
- cryptography
- os
- base64
Intended for demonstration and testing purposes only. Not for use in production environments without proper key management and security practices.
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

import base64
import argparse
import sys
import random
from datetime import datetime
import os
import logging


EMV_KEY_TYPES = {
    'icc': 1024,         # ICC (card) key, usually 1024 bits
    'ca': 1024,          # Certification Authority (CA) key, usually 1024 bits
    'issuer': 1024,      # Issuer key, usually 1024 bits
    'acquirer': 1024,    # Acquirer key, usually 1024 bits
    'terminal': 1024,    # Terminal key, sometimes 1024 bits
    'test2048': 2048,    # For testing 2048-bit keys
}

def generate_rsa_key(key_size=1024, seed=None):
    if seed is not None:
        random.seed(seed)
        # cryptography does not support deterministic keygen, so this is for demonstration only
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

def save_key_to_file(key, filename, is_private=True):
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filename, "wb") as f:
        f.write(pem)

def load_private_key(filename):
    with open(filename, "rb") as f:
        return load_pem_private_key(f.read(), password=None)

def load_public_key(filename):
    with open(filename, "rb") as f:
        return load_pem_public_key(f.read())

def test_encrypt_decrypt(private_key, public_key):
    message = b"Test message for encryption"
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    assert message == decrypted, "Decryption failed"
    print("Encryption and decryption test passed.")

def test_sign_verify(private_key, public_key):
    message = b"Test message for signing"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signing and verification test passed.")

def generate_self_signed_ca(private_key, subject_name="EMV Test CA"):
    from cryptography.x509 import NameOID, Name, CertificateBuilder, random_serial_number, BasicConstraints, SubjectAlternativeName
    import cryptography.x509 as x509
    subject = issuer = Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
    cert = CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow().replace(year=datetime.utcnow().year + 5)
    ).add_extension(
        BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256())
    return cert

def generate_key(key_type, key_size=2048, seed=None):
    if seed:
        random.seed(seed)
    if key_type == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        return private_key
    # Add other key types as needed
    return None

def generate_root_ca(command_type):
    """
    Generate a root CA for the specified command type (DDA/SDA).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    subject_name = f"Root CA for {command_type}"
    return generate_self_signed_ca(private_key, subject_name)

def validate_root_ca(ca_certificate, command_type):
    """
    Validate the root CA for the specified command type.
    """
    # Example validation logic
    if f"Root CA for {command_type}" in ca_certificate.subject.rfc4514_string():
        logging.info(f"Root CA for {command_type} is valid.")
        return True
    else:
        logging.error(f"Root CA for {command_type} is invalid.")
        return False

def main():
    parser = argparse.ArgumentParser(description="EMV/Smartcard RSA Key Utility")
    parser.add_argument('--type', choices=list(EMV_KEY_TYPES.keys()), default='icc', help='Type of EMV key to generate')
    parser.add_argument('--key-size', type=int, help='Override key size (bits)')
    parser.add_argument('--seed', type=int, help='Seed for semi-random key generation (demo only)')
    parser.add_argument('--ca', action='store_true', help='Generate a self-signed CA certificate')
    parser.add_argument('--test', action='store_true', help='Test encryption/decryption and signing/verification')
    parser.add_argument('--out', type=str, default=None, help='Output file prefix (default: type)')
    parser.add_argument('--generate-ca', action='store_true', help='Generate root CA for issuing commands')
    parser.add_argument('--validate-ca', action='store_true', help='Validate root CA for issuing commands')
    args = parser.parse_args()

    key_size = args.key_size or EMV_KEY_TYPES[args.type]
    private_key = generate_rsa_key(key_size=key_size, seed=args.seed)
    public_key = private_key.public_key()

    prefix = args.out or args.type
    priv_file = f"{prefix}_private.pem"
    pub_file = f"{prefix}_public.pem"
    save_key_to_file(private_key, priv_file, is_private=True)
    save_key_to_file(public_key, pub_file, is_private=False)
    print(f"Generated {args.type} key pair ({key_size} bits). Saved to {priv_file}, {pub_file}")

    if args.ca:
        cert = generate_self_signed_ca(private_key, subject_name=f"EMV {args.type.upper()} CA")
        cert_file = f"{prefix}_ca_cert.pem"
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"Self-signed CA certificate saved to {cert_file}")

    if args.test:
        # Reload keys from files for test
        loaded_private_key = load_private_key(priv_file)
        loaded_public_key = load_public_key(pub_file)
        test_encrypt_decrypt(loaded_private_key, loaded_public_key)
        test_sign_verify(loaded_private_key, loaded_public_key)

    if args.generate_ca:
        for command_type in ['DDA', 'SDA']:
            ca = generate_root_ca(command_type)
            logging.info(f"Generated root CA for {command_type}: {ca}")

    if args.validate_ca:
        # Example validation logic
        for command_type in ['DDA', 'SDA']:
            ca_certificate = load_ca_certificate(command_type)  # Assume this function loads the CA certificate
            validate_root_ca(ca_certificate, command_type)

if __name__ == "__main__":
    main()
