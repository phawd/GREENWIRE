from __future__ import annotations

from commands.card_commands import card_create
from core.synthetic_identity import generate_cardholder_name, generate_identity, validate_luhn


class _Args:
    pan = None
    generate_pan = True
    bin_prefix = "40031234"
    length = 16
    expiry = None
    cvv = None
    name = None
    card_type = "visa"
    issuer = None
    emv_data = True
    crypto_keys = False
    output = None
    dry_run = True


def test_generate_identity_uses_plausible_visa_defaults() -> None:
    identity = generate_identity("visa")
    assert identity["issuer_name"] in {"Northstar Digital Bank", "Summit Retail Bank"}
    assert identity["pan"].startswith("4")
    assert len(identity["pan"]) == 16
    assert validate_luhn(identity["pan"])
    assert 2 <= len(identity["cardholder_name"]) <= 26
    assert identity["cardholder_name"] == identity["cardholder_name"].upper()


def test_generate_identity_uses_amex_length_and_luhn() -> None:
    identity = generate_identity("amex")
    assert identity["pan"].startswith(("34", "37"))
    assert len(identity["pan"]) == 15
    assert validate_luhn(identity["pan"])


def test_generate_cardholder_name_normalizes_user_input() -> None:
    assert generate_cardholder_name("Taylor Reed 123") == "TAYLOR REED"


def test_card_create_uses_synthetic_identity_defaults() -> None:
    result = card_create(_Args())
    assert result.success is True
    data = result.data or {}
    assert validate_luhn(data["pan"])
    assert data["pan"].startswith("4")


def test_card_create_preserves_scheme_default_length_for_amex() -> None:
    class _AmexArgs(_Args):
        card_type = "amex"
        bin_prefix = None
        length = None

    result = card_create(_AmexArgs())
    assert result.success is True
    data = result.data or {}
    assert len(data["pan"]) == 15
    assert data["pan"].startswith(("34", "37"))
    assert validate_luhn(data["pan"])
