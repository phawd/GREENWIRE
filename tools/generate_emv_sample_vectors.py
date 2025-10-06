"""Utility script to generate deterministic EMV offline authentication test vectors.

The generated data covers:
- Certification Authority (CA) public key
- Issuer public key certificate + remainder
- ICC public key certificate + remainder
- Signed static application data (SDA)
- Signed dynamic application data (DDA)
- Combined dynamic data payload (CDA)

The output is emitted as JSON with hexadecimal fields so it can be copied into
`greenwire/crypto/sample_vectors.py` and `ca_keys.json` for unit tests.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass
from typing import Dict, Tuple

PAD_BYTE = 0xBB
_rng = random.SystemRandom()


@dataclass
class RSAKey:
    n: int
    e: int
    d: int

    @property
    def length(self) -> int:
        return (self.n.bit_length() + 7) // 8


def _is_probable_prime(n: int, rounds: int = 12) -> bool:
    if n in (2, 3):
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # write n - 1 as 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = _rng.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = _rng.getrandbits(bits)
        candidate |= 1  # ensure odd
        candidate |= (1 << (bits - 1))  # ensure high bit set
        if _is_probable_prime(candidate):
            return candidate


def generate_rsa_key(bits: int, e: int = 65537) -> RSAKey:
    while True:
        p = _generate_prime(bits // 2)
        q = _generate_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        d = pow(e, -1, phi)
        return RSAKey(n=p * q, e=e, d=d)


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if length is None:
        length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


def build_issuer_certificate(ca_key: RSAKey, issuer_key: RSAKey) -> Tuple[bytes, bytes, bytes]:
    ca_len = ca_key.length
    issuer_len = issuer_key.length
    fragment_len = ca_len - 36
    issuer_modulus = int_to_bytes(issuer_key.n, issuer_len)
    fragment = issuer_modulus[:fragment_len]
    remainder = issuer_modulus[fragment_len:]
    exponent_bytes = int_to_bytes(issuer_key.e)

    body = bytearray()
    body.append(0x6A)
    body.append(0x02)
    issuer_identifier = bytes.fromhex("A00001B2")
    certificate_expiration = bytes.fromhex("2512")
    certificate_serial = bytes.fromhex("010203")
    hash_algorithm_indicator = 0x01
    public_key_algorithm_indicator = 0x01

    body.extend(issuer_identifier)
    body.extend(certificate_expiration)
    body.extend(certificate_serial)
    body.append(hash_algorithm_indicator)
    body.append(public_key_algorithm_indicator)
    body.append(issuer_len)
    body.append(len(exponent_bytes))
    body.extend(fragment)

    hash_input = bytearray()
    hash_input.append(0x02)
    hash_input.extend(issuer_identifier)
    hash_input.extend(certificate_expiration)
    hash_input.extend(certificate_serial)
    hash_input.append(hash_algorithm_indicator)
    hash_input.append(public_key_algorithm_indicator)
    hash_input.append(issuer_len)
    hash_input.append(len(exponent_bytes))
    hash_input.extend(fragment)
    hash_input.extend(remainder)
    hash_input.extend(exponent_bytes)

    digest = hashlib.sha1(hash_input).digest()
    body.extend(digest)
    body.append(0xBC)
    assert len(body) == ca_len

    cert_int = pow(int.from_bytes(body, "big"), ca_key.d, ca_key.n)
    cert_bytes = cert_int.to_bytes(ca_len, "big")
    return cert_bytes, remainder, exponent_bytes


def build_icc_certificate(issuer_key: RSAKey, icc_key: RSAKey) -> Tuple[bytes, bytes, bytes]:
    issuer_len = issuer_key.length
    icc_len = icc_key.length
    fragment_len = issuer_len - 42

    icc_modulus = int_to_bytes(icc_key.n, icc_len)
    fragment = icc_modulus[:fragment_len]
    remainder = icc_modulus[fragment_len:]
    exponent_bytes = int_to_bytes(icc_key.e)

    body = bytearray()
    body.append(0x6A)
    body.append(0x04)
    pan = bytes.fromhex("43219876543210000000")
    certificate_expiration = bytes.fromhex("2412")
    certificate_serial = bytes.fromhex("ABCDEF")
    hash_algorithm_indicator = 0x01
    public_key_algorithm_indicator = 0x01

    body.extend(pan)
    body.extend(certificate_expiration)
    body.extend(certificate_serial)
    body.append(hash_algorithm_indicator)
    body.append(public_key_algorithm_indicator)
    body.append(icc_len)
    body.append(len(exponent_bytes))
    body.extend(fragment)

    hash_input = bytearray()
    hash_input.append(0x04)
    hash_input.extend(pan)
    hash_input.extend(certificate_expiration)
    hash_input.extend(certificate_serial)
    hash_input.append(hash_algorithm_indicator)
    hash_input.append(public_key_algorithm_indicator)
    hash_input.append(icc_len)
    hash_input.append(len(exponent_bytes))
    hash_input.extend(fragment)
    hash_input.extend(remainder)
    hash_input.extend(exponent_bytes)

    digest = hashlib.sha1(hash_input).digest()
    body.extend(digest)
    body.append(0xBC)
    assert len(body) == issuer_len

    cert_int = pow(int.from_bytes(body, "big"), issuer_key.d, issuer_key.n)
    cert_bytes = cert_int.to_bytes(issuer_len, "big")
    return cert_bytes, remainder, exponent_bytes


def build_signature_block(private_key: RSAKey, format_byte: int, payload: bytes) -> bytes:
    key_len = private_key.length
    body = bytearray()
    body.append(0x6A)
    body.append(format_byte)
    body.extend(payload)

    while len(body) < key_len - (20 + 1):
        body.append(PAD_BYTE)

    digest = hashlib.sha1(payload).digest()
    body.extend(digest)
    body.append(0xBC)
    assert len(body) == key_len

    signature_int = pow(int.from_bytes(body, "big"), private_key.d, private_key.n)
    return signature_int.to_bytes(key_len, "big")


def main() -> None:
    ca_key = generate_rsa_key(768)
    issuer_key = generate_rsa_key(704)
    icc_key = generate_rsa_key(640)

    issuer_cert, issuer_remainder, issuer_exp_bytes = build_issuer_certificate(ca_key, issuer_key)
    icc_cert, icc_remainder, icc_exp_bytes = build_icc_certificate(issuer_key, icc_key)

    static_payload = bytes.fromhex("701EAABBCCDDEEFF00112233445566778899AABBCCDDEEFF0102")
    dynamic_payload = bytes.fromhex("9F3704A1B2C3D49F36020001")
    cda_payload = dynamic_payload + bytes.fromhex("9F2701A0")

    sda_signature = build_signature_block(issuer_key, 0x03, static_payload)
    dda_signature = build_signature_block(icc_key, 0x05, dynamic_payload)
    cda_signature = build_signature_block(icc_key, 0x06, cda_payload)

    vectors: Dict[str, str] = {
        "rid": "A0000000F0",
        "ca_key_index": "01",
        "ca_modulus": ca_key.n.to_bytes(ca_key.length, "big").hex().upper(),
        "ca_exponent": f"{ca_key.e:X}",
        "issuer_public_key_certificate": issuer_cert.hex().upper(),
        "issuer_public_key_remainder": issuer_remainder.hex().upper(),
        "issuer_public_key_exponent": issuer_exp_bytes.hex().upper(),
        "icc_public_key_certificate": icc_cert.hex().upper(),
        "icc_public_key_remainder": icc_remainder.hex().upper(),
        "icc_public_key_exponent": icc_exp_bytes.hex().upper(),
        "signed_static_data": sda_signature.hex().upper(),
        "static_payload": static_payload.hex().upper(),
        "signed_dynamic_data": dda_signature.hex().upper(),
        "dynamic_payload": dynamic_payload.hex().upper(),
        "signed_cda_data": cda_signature.hex().upper(),
        "cda_payload": cda_payload.hex().upper(),
    }

    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
