import os
import sys

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from greenwire.core.emv_keys import generate_rsa_keypair, generate_emv_keyset, sign_sda_data
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def test_generate_rsa_keypair():
    priv, pub = generate_rsa_keypair(1024)
    priv_key = load_pem_private_key(priv, password=None)
    pub_key = load_pem_public_key(pub)
    assert priv_key.key_size == 1024
    assert pub_key.key_size == 1024


def test_generate_emv_keyset():
    keys = generate_emv_keyset()
    assert set(keys.keys()) == {
        'ca_private', 'ca_public', 'issuer_private', 'issuer_public', 'icc_private', 'icc_public'
    }
    priv = load_pem_private_key(keys['issuer_private'], password=None)
    assert priv.key_size == 1024


def test_sign_sda_data():
    priv, pub = generate_rsa_keypair(1024)
    signature = sign_sda_data(b'data', priv)
    assert isinstance(signature, bytes)
    assert len(signature) > 0


