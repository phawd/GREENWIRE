"""Validation helpers for card creation and issuance policy gates."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Dict, List

from core.emv_ca_locator import build_emv_certificate_inventory
from core.globalplatform_reference import common_test_keys
from core.emv_reference_vectors import load_reference_vectors
from core.pipeline_providers import EmulatorHSMBackend, build_cryptogram_payload
from core.synthetic_identity import validate_luhn


_KNOWN_TEST_KEYS = {value.upper() for value in common_test_keys()}
_HEX_32_RE = re.compile(r"^[0-9A-F]{32}$")


def is_test_function_invocation(command_name: str | None, explicit_test_function: bool = False) -> bool:
    if explicit_test_function:
        return True
    return "test" in (command_name or "").lower()


def validate_card_identity(
    *,
    pan: str,
    expiry: str,
    cvv: str,
    cardholder_name: str,
    issuer_name: str,
) -> List[str]:
    errors: List[str] = []
    normalized_pan = "".join(ch for ch in pan if ch.isdigit())
    if not normalized_pan or not validate_luhn(normalized_pan):
        errors.append("PAN must pass Luhn validation")
    if len(normalized_pan) < 13 or len(normalized_pan) > 19:
        errors.append("PAN length must be between 13 and 19 digits")

    try:
        parsed_expiry = datetime.strptime(expiry, "%m/%y")
        # Compare against the first day of current month.
        now = datetime.now(timezone.utc).replace(tzinfo=None).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if parsed_expiry.replace(day=1) < now:
            errors.append("Expiry must be in the future")
    except ValueError:
        errors.append("Expiry must be in MM/YY format")

    if not cvv.isdigit() or len(cvv) not in (3, 4):
        errors.append("CVV must be 3 or 4 digits")
    if len((cardholder_name or "").strip()) < 2:
        errors.append("Cardholder name is required")
    if len((issuer_name or "").strip()) < 2:
        errors.append("Issuer name is required")
    return errors


def validate_merchant_required_fields(context: Dict[str, str]) -> List[str]:
    errors: List[str] = []
    required = ("merchant_id", "terminal_id", "mcc", "acquirer_id", "country_code", "currency")
    for key in required:
        value = str(context.get(key, "")).strip()
        if not value:
            errors.append(f"Missing merchant-required field: {key}")

    mcc = str(context.get("mcc", "")).strip()
    if mcc and (len(mcc) != 4 or not mcc.isdigit()):
        errors.append("MCC must be a 4-digit numeric value")
    country_code = str(context.get("country_code", "")).strip()
    if country_code and (len(country_code) != 3 or not country_code.isdigit()):
        errors.append("Country code must be 3 numeric digits (ISO 3166 numeric)")
    currency = str(context.get("currency", "")).strip().upper()
    if currency and len(currency) != 3:
        errors.append("Currency must be a 3-letter ISO 4217 code")
    return errors


def validate_pin_value(pin: str) -> List[str]:
    normalized = str(pin or "").strip()
    if not normalized.isdigit():
        return ["PIN must contain only digits"]
    if len(normalized) < 4 or len(normalized) > 12:
        return ["PIN length must be between 4 and 12 digits"]
    return []


def validate_key_profile(
    *,
    key_profile: str,
    is_test_function: bool,
    candidate_keys: Dict[str, str] | None = None,
) -> List[str]:
    errors: List[str] = []
    normalized_profile = (key_profile or "production").strip().lower()
    if normalized_profile != "production":
        if is_test_function:
            errors.append(
                "Test runs must still use production-like synthetic data; test key profiles are not allowed"
            )
        else:
            errors.append("Only production key profile is allowed for card creation and issuance")

    if not candidate_keys:
        return errors

    for name, value in candidate_keys.items():
        key_hex = str(value or "").strip().upper()
        if key_hex and key_hex in _KNOWN_TEST_KEYS:
            errors.append(f"Field '{name}' uses a known test key in production mode")
    return errors


def _scheme_from_pan(pan: str) -> str:
    normalized = "".join(ch for ch in pan if ch.isdigit())
    if normalized.startswith("4"):
        return "visa"
    if normalized[:2] in {"34", "37"}:
        return "amex"
    if normalized[:2] in {"51", "52", "53", "54", "55"}:
        return "mastercard"
    if normalized.startswith("6"):
        return "discover"
    return "visa"


def _validate_transport_cryptogram(
    *,
    hsm: EmulatorHSMBackend,
    pan: str,
    atc: int,
    track2: str,
    amount: float,
    currency: str,
    terminal_country: str,
    transaction_id: str,
    label: str,
) -> List[str]:
    errors: List[str] = []
    payload = build_cryptogram_payload(
        pan=pan,
        track2=track2,
        amount=amount,
        currency=currency,
        terminal_country=terminal_country,
        transaction_id=transaction_id,
        atc=atc,
    )
    try:
        arqc = hsm.generate_arqc(pan=pan, atc=atc, payload=payload)
        if not hsm.verify_arqc(pan=pan, atc=atc, payload=payload, arqc=arqc):
            errors.append(f"{label} ARQC verification self-test failed")
    except Exception as exc:
        errors.append(f"{label} ARQC generation/verification self-test failed: {exc}")
    return errors


def validate_issuance_crypto_readiness(*, pan: str, atc: int = 1, include_atm: bool = False) -> List[str]:
    errors: List[str] = []
    inventory = build_emv_certificate_inventory()
    if int(inventory.get("count", 0)) <= 0:
        errors.append("No EMV CA/certificate assets found in emv* directories")

    scheme = _scheme_from_pan(pan)
    vectors = load_reference_vectors()
    if not vectors:
        errors.append("No EMV reference vectors available for CA/key validation")

    try:
        hsm = EmulatorHSMBackend()
        session_keys = hsm.derive_session_keys(pan=pan, pan_sequence="00", atc=atc)
    except Exception as exc:
        errors.append(f"HSM key derivation self-test failed: {exc}")
        return errors

    derived = {
        "mac_key": session_keys.mac_key,
        "enc_key": session_keys.enc_key,
        "dek_key": session_keys.dek_key,
    }
    for key_name, key_hex in derived.items():
        value = str(key_hex or "").upper()
        if not _HEX_32_RE.match(value):
            errors.append(f"Derived {key_name} is not a valid 16-byte hex key")
        if value in _KNOWN_TEST_KEYS:
            errors.append(f"Derived {key_name} unexpectedly matches a known test key")

    track2 = f"{pan}D25122010000000000"
    errors.extend(
        _validate_transport_cryptogram(
            hsm=hsm,
            pan=pan,
            atc=atc,
            track2=track2,
            amount=1.00,
            currency="USD",
            terminal_country="840",
            transaction_id="MERCHANTCHK",
            label="Merchant",
        )
    )
    if include_atm:
        errors.extend(
            _validate_transport_cryptogram(
                hsm=hsm,
                pan=pan,
                atc=atc,
                track2=track2,
                amount=20.00,
                currency="USD",
                terminal_country="840",
                transaction_id="ATMCHK",
                label="ATM",
            )
        )

    return errors
