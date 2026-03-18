from __future__ import annotations

from argparse import Namespace

import pytest
from commands.card_commands import card_create
from commands.issuer_pipeline import IssuerPipelineCommand, _resolve_interface_flag


def _card_args(**overrides) -> Namespace:
    data = {
        "pan": None,
        "generate_pan": True,
        "bin_prefix": None,
        "length": None,
        "expiry": None,
        "cvv": None,
        "name": None,
        "card_type": "visa",
        "issuer": None,
        "emv_data": False,
        "crypto_keys": False,
        "output": None,
        "dry_run": True,
        "key_profile": "production",
        "merchant_id": "MERCHANT-0001",
        "terminal_id": "POS-EMU-01",
        "mcc": "5411",
        "acquirer_id": "00000012345",
        "country_code": "840",
        "currency": "USD",
        "test_function": False,
        "nfc": False,
        "no_nfc": False,
        "rfid": False,
        "no_rfid": False,
        "validate_atm": False,
        "command": "card-create",
    }
    data.update(overrides)
    return Namespace(**data)


@pytest.fixture(autouse=True)
def _stub_crypto_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("commands.card_commands.validate_issuance_crypto_readiness", lambda **_: [])
    monkeypatch.setattr("commands.issuer_pipeline.validate_issuance_crypto_readiness", lambda **_: [])


def test_card_create_rejects_test_key_profile_without_test_function() -> None:
    result = card_create(_card_args(key_profile="test"))
    assert result.success is False
    assert "validation failed" in result.message.lower()


def test_card_create_rejects_test_key_profile_even_with_explicit_test_function() -> None:
    result = card_create(_card_args(key_profile="test", test_function=True))
    assert result.success is False
    assert "validation failed" in result.message.lower()


def test_card_create_allows_production_profile_with_explicit_test_function() -> None:
    result = card_create(_card_args(key_profile="production", test_function=True))
    assert result.success is True
    assert result.data["test_context"] is True


def test_card_create_defaults_pin_to_6666(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConfigManager:
        def data(self):
            return {"cards": {"default_nfc_enabled": True, "default_rfid_enabled": True}}

        def default_card_pin(self) -> str:
            return "6666"

    monkeypatch.setattr("commands.card_commands.get_configuration_manager", lambda: _FakeConfigManager())
    result = card_create(_card_args())
    assert result.success is True
    assert result.data["pin"] == "6666"


def test_card_create_uses_configured_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConfigManager:
        def data(self):
            return {"cards": {"default_nfc_enabled": True, "default_rfid_enabled": True}}

        def default_card_pin(self) -> str:
            return "7777"

    monkeypatch.setattr("commands.card_commands.get_configuration_manager", lambda: _FakeConfigManager())
    result = card_create(_card_args())
    assert result.success is True
    assert result.data["pin"] == "7777"


def test_card_create_allows_explicit_duplicate_pan() -> None:
    explicit_pan = "4111111111111111"
    first = card_create(_card_args(pan=explicit_pan, generate_pan=False))
    second = card_create(_card_args(pan=explicit_pan, generate_pan=False))
    assert first.success is True
    assert second.success is True
    assert first.data["pan"] == explicit_pan
    assert second.data["pan"] == explicit_pan


def test_card_create_defaults_nfc_and_rfid_enabled() -> None:
    result = card_create(_card_args())
    assert result.success is True
    assert result.data["nfc_enabled"] is True
    assert result.data["rfid_enabled"] is True


def test_card_create_allows_cli_override_for_nfc_and_rfid() -> None:
    result = card_create(_card_args(no_nfc=True, no_rfid=True))
    assert result.success is True
    assert result.data["nfc_enabled"] is False
    assert result.data["rfid_enabled"] is False


def test_issuer_pipeline_rejects_test_key_profile_without_test_function() -> None:
    command = IssuerPipelineCommand()
    result = command.execute(
        [
            "--pan",
            "4003123412341234",
            "--key-profile",
            "test",
        ]
    )
    assert result["success"] is False
    assert "validation failed" in result["message"].lower()


def test_issuer_pipeline_rejects_test_key_profile_with_test_function() -> None:
    command = IssuerPipelineCommand()
    result = command.execute(
        [
            "--pan",
            "4003123412341234",
            "--key-profile",
            "test",
            "--test-function",
        ]
    )
    assert result["success"] is False
    assert "validation failed" in result["message"].lower()


def test_issuer_pipeline_rejects_invalid_merchant_required_values() -> None:
    command = IssuerPipelineCommand()
    result = command.execute(
        [
            "--pan",
            "4003123412341234",
            "--mcc",
            "54A1",
        ]
    )
    assert result["success"] is False
    assert "validation failed" in result["message"].lower()


def test_issuer_interface_flags_default_and_cli_override() -> None:
    assert _resolve_interface_flag(enabled_flag=False, disabled_flag=False, config_default=True) is True
    assert _resolve_interface_flag(enabled_flag=False, disabled_flag=False, config_default=False) is False
    assert _resolve_interface_flag(enabled_flag=True, disabled_flag=False, config_default=False) is True
    assert _resolve_interface_flag(enabled_flag=False, disabled_flag=True, config_default=True) is False
