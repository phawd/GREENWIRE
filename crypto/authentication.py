"""GREENWIRE EMV offline data authentication utilities.

This module implements Static Data Authentication (SDA), Dynamic Data
Authentication (DDA) and Combined Data Authentication (CDA) using only the
Python standard library so it can be bundled inside the static GREENWIRE
distribution.

The implementation follows EMV Book 2 specifications for recovering and
validating issuer and ICC public key certificates, reconstructing public
keys, and verifying RSA signatures that contain the SHA-1 digest of the
static or dynamic data elements exchanged during card personalization or
transactions.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .keys import find_ca_key

# Constants defined by EMV specifications for recovered signature blocks.
HEADER_BYTE = 0x6A
TRAILER_BYTE = 0xBC
SHA1_DIGEST_LENGTH = 20
PAD_BYTE = 0xBB


@dataclass
class RSAKey:
    """Simple representation of an RSA public key."""

    modulus: int
    exponent: int
    modulus_length: int
    exponent_length: int


def _hex_to_int(value: str) -> int:
    return int(value, 16)


def _rsa_recover(signature: bytes, exponent: int, modulus: int, expected_length: int) -> Optional[bytes]:
    """Performs textbook RSA recovery and returns the plaintext block."""

    try:
        recovered_int = pow(int.from_bytes(signature, "big"), exponent, modulus)
        recovered_bytes = recovered_int.to_bytes(expected_length, "big")
        return recovered_bytes
    except Exception as exc:  # pragma: no cover - defensive
        print(f"RSA recovery failed: {exc}")
        return None


def _strip_padding(value: bytes) -> bytes:
    """Remove EMV pad bytes (0xBB) from the end of a field."""

    return value.rstrip(bytes([PAD_BYTE]))


def _load_ca_key(rid: str, index: str) -> Optional[Tuple[int, int, int]]:
    """Locate the CA public key and return modulus, exponent and length."""

    ca_entry = find_ca_key(rid, index)
    if not ca_entry:
        print(f"CA key not found for RID {rid} index {index}.")
        return None

    modulus_hex = ca_entry["modulus"].replace(" ", "").replace("\n", "")
    exponent_hex = ca_entry["exponent"].replace(" ", "")

    modulus_int = _hex_to_int(modulus_hex)
    exponent_int = _hex_to_int(exponent_hex)
    modulus_length = len(modulus_hex) // 2

    return modulus_int, exponent_int, modulus_length


def _ensure_length(data: bytes, expected_length: int, description: str) -> bool:
    """Validate input length and print a descriptive error on mismatch."""

    if len(data) != expected_length:
        print(f"{description} length {len(data)} does not match expected {expected_length} bytes.")
        return False
    return True


def _parse_issuer_certificate(
    ca_modulus: int,
    ca_exponent: int,
    ca_modulus_len: int,
    issuer_certificate: bytes,
    issuer_pk_remainder: bytes,
    issuer_pk_exponent: bytes,
) -> Optional[RSAKey]:
    """Recover and validate the issuer public key certificate."""

    if not _ensure_length(issuer_certificate, ca_modulus_len, "Issuer certificate"):
        return None

    recovered = _rsa_recover(issuer_certificate, ca_exponent, ca_modulus, ca_modulus_len)
    if recovered is None:
        return None

    if recovered[0] != HEADER_BYTE or recovered[-1] != TRAILER_BYTE:
        print("Issuer certificate has invalid header or trailer bytes.")
        return None

    if recovered[1] != 0x02:
        print(f"Unexpected issuer certificate format byte {recovered[1]:02X} (expected 0x02).")
        return None

    pointer = 2
    issuer_identifier = recovered[pointer : pointer + 4]
    pointer += 4
    certificate_expiration = recovered[pointer : pointer + 2]
    pointer += 2
    certificate_serial = recovered[pointer : pointer + 3]
    pointer += 3
    hash_algorithm_indicator = recovered[pointer]
    pointer += 1
    public_key_algorithm_indicator = recovered[pointer]
    pointer += 1
    issuer_pk_length = recovered[pointer]
    pointer += 1
    issuer_pk_exponent_length = recovered[pointer]
    pointer += 1

    modulus_fragment = recovered[pointer : -SHA1_DIGEST_LENGTH - 1]
    hash_result = recovered[-SHA1_DIGEST_LENGTH - 1 : -1]

    modulus_fragment = _strip_padding(modulus_fragment)
    issuer_pk_remainder = issuer_pk_remainder or b""

    issuer_modulus_bytes = modulus_fragment + issuer_pk_remainder
    if len(issuer_modulus_bytes) != issuer_pk_length:
        print(
            "Issuer public key length mismatch between certificate and provided remainder."
        )
        return None

    exponent_bytes = issuer_pk_exponent or b""
    if len(exponent_bytes) != issuer_pk_exponent_length:
        if len(exponent_bytes) == 0:
            print("Issuer public key exponent is required but was not provided.")
            return None
        exponent_bytes = exponent_bytes.rjust(issuer_pk_exponent_length, b"\x00")

    issuer_exponent_int = int.from_bytes(exponent_bytes, "big")
    issuer_modulus_int = int.from_bytes(issuer_modulus_bytes, "big")

    hash_input = bytearray()
    hash_input.append(0x02)
    hash_input.extend(issuer_identifier)
    hash_input.extend(certificate_expiration)
    hash_input.extend(certificate_serial)
    hash_input.append(hash_algorithm_indicator)
    hash_input.append(public_key_algorithm_indicator)
    hash_input.append(issuer_pk_length)
    hash_input.append(issuer_pk_exponent_length)
    hash_input.extend(issuer_modulus_bytes)
    hash_input.extend(exponent_bytes)

    expected_hash = hashlib.sha1(hash_input).digest()
    if expected_hash != hash_result:
        print("Issuer certificate hash verification failed.")
        return None

    return RSAKey(
        modulus=issuer_modulus_int,
        exponent=issuer_exponent_int,
        modulus_length=issuer_pk_length,
        exponent_length=issuer_pk_exponent_length,
    )


def _parse_icc_certificate(
    issuer_key: RSAKey,
    icc_certificate: bytes,
    icc_pk_remainder: bytes,
    icc_pk_exponent: bytes,
) -> Optional[RSAKey]:
    """Recover and validate the ICC public key certificate."""

    issuer_modulus_len = issuer_key.modulus_length
    if not _ensure_length(icc_certificate, issuer_modulus_len, "ICC certificate"):
        return None

    recovered = _rsa_recover(icc_certificate, issuer_key.exponent, issuer_key.modulus, issuer_modulus_len)
    if recovered is None:
        return None

    if recovered[0] != HEADER_BYTE or recovered[-1] != TRAILER_BYTE:
        print("ICC certificate has invalid header or trailer bytes.")
        return None

    if recovered[1] not in (0x04, 0x05):
        print(f"Unexpected ICC certificate format byte {recovered[1]:02X} (expected 0x04 or 0x05).")
        return None

    pointer = 2
    application_pan = recovered[pointer : pointer + 10]
    pointer += 10
    certificate_expiration = recovered[pointer : pointer + 2]
    pointer += 2
    certificate_serial = recovered[pointer : pointer + 3]
    pointer += 3
    hash_algorithm_indicator = recovered[pointer]
    pointer += 1
    public_key_algorithm_indicator = recovered[pointer]
    pointer += 1
    icc_pk_length = recovered[pointer]
    pointer += 1
    icc_pk_exponent_length = recovered[pointer]
    pointer += 1

    modulus_fragment = recovered[pointer : -SHA1_DIGEST_LENGTH - 1]
    hash_result = recovered[-SHA1_DIGEST_LENGTH - 1 : -1]

    modulus_fragment = _strip_padding(modulus_fragment)
    icc_pk_remainder = icc_pk_remainder or b""
    icc_modulus_bytes = modulus_fragment + icc_pk_remainder
    if len(icc_modulus_bytes) != icc_pk_length:
        print("ICC public key length mismatch between certificate and remainder.")
        return None

    exponent_bytes = icc_pk_exponent or b""
    if len(exponent_bytes) != icc_pk_exponent_length:
        if len(exponent_bytes) == 0:
            print("ICC public key exponent is required but was not provided.")
            return None
        exponent_bytes = exponent_bytes.rjust(icc_pk_exponent_length, b"\x00")

    icc_exponent_int = int.from_bytes(exponent_bytes, "big")
    icc_modulus_int = int.from_bytes(icc_modulus_bytes, "big")

    hash_input = bytearray()
    hash_input.append(recovered[1])
    hash_input.extend(application_pan)
    hash_input.extend(certificate_expiration)
    hash_input.extend(certificate_serial)
    hash_input.append(hash_algorithm_indicator)
    hash_input.append(public_key_algorithm_indicator)
    hash_input.append(icc_pk_length)
    hash_input.append(icc_pk_exponent_length)
    hash_input.extend(icc_modulus_bytes)
    hash_input.extend(exponent_bytes)

    expected_hash = hashlib.sha1(hash_input).digest()
    if expected_hash != hash_result:
        print("ICC certificate hash verification failed.")
        return None

    return RSAKey(
        modulus=icc_modulus_int,
        exponent=icc_exponent_int,
        modulus_length=icc_pk_length,
        exponent_length=icc_pk_exponent_length,
    )


def _recover_dynamic_auth_keys(
    rid: str,
    ca_key_index: str,
    issuer_pk_cert: bytes,
    icc_pk_cert: bytes,
    issuer_pk_exponent: bytes,
    icc_pk_exponent: bytes,
    issuer_pk_remainder: bytes = b"",
    icc_pk_remainder: bytes = b"",
) -> Optional[Tuple[RSAKey, RSAKey]]:
    """Recover issuer and ICC keys required for DDA/CDA."""

    ca_key = _load_ca_key(rid, ca_key_index)
    if not ca_key:
        return None

    ca_modulus, ca_exponent, ca_modulus_len = ca_key

    issuer_key = _parse_issuer_certificate(
        ca_modulus,
        ca_exponent,
        ca_modulus_len,
        issuer_pk_cert,
        issuer_pk_remainder,
        issuer_pk_exponent,
    )
    if issuer_key is None:
        return None

    icc_key = _parse_icc_certificate(issuer_key, icc_pk_cert, icc_pk_remainder, icc_pk_exponent)
    if icc_key is None:
        return None

    return issuer_key, icc_key


def _verify_signature_block(
    key: RSAKey,
    signature: bytes,
    expected_format: Tuple[int, ...],
    expected_hash: bytes,
    label: str,
) -> bool:
    """Decrypt a signature block and verify its digest."""

    recovered = _rsa_recover(signature, key.exponent, key.modulus, key.modulus_length)
    if recovered is None:
        return False

    if recovered[0] != HEADER_BYTE or recovered[-1] != TRAILER_BYTE:
        print(f"{label} signature block has invalid header or trailer bytes.")
        return False

    if recovered[1] not in expected_format:
        formats = ", ".join(f"0x{fmt:02X}" for fmt in expected_format)
        print(f"{label} signature format {recovered[1]:02X} not in expected set [{formats}].")
        return False

    recovered_hash = recovered[-SHA1_DIGEST_LENGTH - 1 : -1]
    if recovered_hash != expected_hash:
        print(f"{label} hash mismatch.")
        return False

    return True


def perform_sda(
    rid: str,
    ca_key_index: str,
    issuer_pk_cert: bytes,
    signed_static_data: bytes,
    static_data_to_hash: bytes,
    issuer_pk_exponent: bytes,
    issuer_pk_remainder: bytes = b"",
) -> bool:
    """Validate Static Data Authentication (SDA)."""

    ca_key = _load_ca_key(rid, ca_key_index)
    if not ca_key:
        return False

    ca_modulus, ca_exponent, ca_modulus_len = ca_key

    issuer_key = _parse_issuer_certificate(
        ca_modulus,
        ca_exponent,
        ca_modulus_len,
        issuer_pk_cert,
        issuer_pk_remainder,
        issuer_pk_exponent,
    )
    if issuer_key is None:
        return False

    expected_hash = hashlib.sha1(static_data_to_hash).digest()
    return _verify_signature_block(
        issuer_key,
        signed_static_data,
        expected_format=(0x03,),
        expected_hash=expected_hash,
        label="SDA",
    )


def perform_dda(
    rid: str,
    ca_key_index: str,
    issuer_pk_cert: bytes,
    icc_pk_cert: bytes,
    signed_dynamic_data: bytes,
    dynamic_data_to_hash: bytes,
    issuer_pk_exponent: bytes,
    icc_pk_exponent: bytes,
    issuer_pk_remainder: bytes = b"",
    icc_pk_remainder: bytes = b"",
) -> bool:
    """Validate Dynamic Data Authentication (DDA)."""

    recovered_keys = _recover_dynamic_auth_keys(
        rid,
        ca_key_index,
        issuer_pk_cert,
        icc_pk_cert,
        issuer_pk_exponent,
        icc_pk_exponent,
        issuer_pk_remainder,
        icc_pk_remainder,
    )
    if recovered_keys is None:
        return False

    _, icc_key = recovered_keys

    expected_hash = hashlib.sha1(dynamic_data_to_hash).digest()
    return _verify_signature_block(
        icc_key,
        signed_dynamic_data,
        expected_format=(0x05, 0x06),
        expected_hash=expected_hash,
        label="DDA",
    )


def perform_cda(
    rid: str,
    ca_key_index: str,
    issuer_pk_cert: bytes,
    icc_pk_cert: bytes,
    signed_dynamic_data: bytes,
    dynamic_data_to_hash: bytes,
    issuer_pk_exponent: bytes,
    icc_pk_exponent: bytes,
    issuer_pk_remainder: bytes = b"",
    icc_pk_remainder: bytes = b"",
) -> bool:
    """Validate Combined Data Authentication (CDA)."""

    recovered_keys = _recover_dynamic_auth_keys(
        rid,
        ca_key_index,
        issuer_pk_cert,
        icc_pk_cert,
        issuer_pk_exponent,
        icc_pk_exponent,
        issuer_pk_remainder,
        icc_pk_remainder,
    )
    if recovered_keys is None:
        return False

    _, icc_key = recovered_keys

    expected_hash = hashlib.sha1(dynamic_data_to_hash).digest()
    return _verify_signature_block(
        icc_key,
        signed_dynamic_data,
        expected_format=(0x05, 0x06),
        expected_hash=expected_hash,
        label="CDA",
    )

