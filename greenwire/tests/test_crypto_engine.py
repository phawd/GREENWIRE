import importlib.util
from pathlib import Path
import hashlib

_crypto_path = Path(__file__).resolve().parents[1] / "core" / "crypto_engine.py"
spec = importlib.util.spec_from_file_location("crypto_engine", _crypto_path)
crypto_engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crypto_engine)


def test_rsa_sign_verify():
    priv = crypto_engine.generate_rsa_key()
    data = b"hello"
    sig = crypto_engine.rsa_sign(priv, data)
    assert crypto_engine.rsa_verify(priv.public_key(), sig, data)


def test_ec_sign_verify():
    priv = crypto_engine.generate_ec_key()
    data = b"hello ecc"
    sig = crypto_engine.ec_sign(priv, data)
    assert crypto_engine.ec_verify(priv.public_key(), sig, data)


def test_aes_encrypt_decrypt():
    key = b"k" * 32
    iv = b"i" * 16
    plaintext = b"secret data"
    ciphertext = crypto_engine.aes_encrypt(key, plaintext, iv)
    assert crypto_engine.aes_decrypt(key, ciphertext, iv) == plaintext


def test_sha256():
    data = b"data"
    assert crypto_engine.sha256(data) == hashlib.sha256(data).hexdigest()
