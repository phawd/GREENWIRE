"""
Unit tests for greenwire.core.crypto_engine cryptographic functions.
"""
import os
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from greenwire.core import crypto_engine

def test_generate_rsa_key():
    key = crypto_engine.generate_rsa_key(2048)
    assert isinstance(key, RSAPrivateKey)
    assert key.key_size == 2048

def test_rsa_sign_and_verify():
    key = crypto_engine.generate_rsa_key()
    data = b"test data"
    sig = crypto_engine.rsa_sign(key, data)
    pub = key.public_key()
    assert crypto_engine.rsa_verify(pub, sig, data)
    assert not crypto_engine.rsa_verify(pub, sig, b"wrong data")

def test_rsa_encrypt_decrypt():
    key = crypto_engine.generate_rsa_key()
    pub = key.public_key()
    plaintext = b"secret message"
    ciphertext = crypto_engine.rsa_encrypt(pub, plaintext)
    decrypted = crypto_engine.rsa_decrypt(key, ciphertext)
    assert decrypted == plaintext

def test_generate_ec_key():
    key = crypto_engine.generate_ec_key()
    assert isinstance(key, EllipticCurvePrivateKey)

def test_ec_sign_and_verify():
    key = crypto_engine.generate_ec_key()
    data = b"test data"
    sig = crypto_engine.ec_sign(key, data)
    pub = key.public_key()
    assert crypto_engine.ec_verify(pub, sig, data)
    assert not crypto_engine.ec_verify(pub, sig, b"wrong data")

def test_aes_encrypt_decrypt():
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = b"test block data 123"
    ciphertext = crypto_engine.aes_encrypt(key, plaintext, iv)
    decrypted = crypto_engine.aes_decrypt(key, ciphertext, iv)
    assert decrypted == plaintext

def test_sha256():
    data = b"abc"
    h = crypto_engine.sha256(data)
    assert h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
