from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import pytest
from commands.mutant_card_commands import mutant_card_command


def _create_args(tmp_path: Path) -> Namespace:
    return Namespace(
        action="create",
        mode="merchant",
        card_file=None,
        card_type="visa",
        pan=None,
        name=None,
        issuer=None,
        expiry=None,
        cvv=None,
        length=None,
        atc=1,
        floor_limit=50,
        cvm_method="offline_pin_signature",
        mutation_profile="balanced",
        amount=12.5,
        output=str(tmp_path / "mutant_card.json"),
        dry_run=False,
    )


def test_mutant_card_create_and_run_merchant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConfigManager:
        def default_card_pin(self) -> str:
            return "6666"

    monkeypatch.setattr("commands.mutant_card_commands.get_configuration_manager", lambda: _FakeConfigManager())
    create_result = mutant_card_command(_create_args(tmp_path))
    assert create_result.success is True
    card_file = Path(create_result.data["card_file"])
    assert card_file.exists()
    card_payload = json.loads(card_file.read_text(encoding="utf-8"))
    assert card_payload["pin"] == "6666"
    assert card_payload["processing_profile"]["mode"] == "normal"
    assert card_payload["processing_profile"]["normal_handling_required"] is True

    run_args = _create_args(tmp_path)
    run_args.action = "run"
    run_args.card_file = str(card_file)
    run_args.mode = "merchant"
    run_result = mutant_card_command(run_args)

    assert run_result.success is True
    assert run_result.data["result"]["mode"] == "merchant"
    assert run_result.data["result"]["issuer_valid"] is True
    assert run_result.data["result"]["processor_status"] == "approved"
    assert run_result.data["result"]["authorization_response_code"] == "00"
    assert run_result.data["result"]["processing_mode"] == "normal"
    assert run_result.data["returned_logs"]["sealed_records"] >= 1
    assert run_result.data["returned_logs"]["decoded_records"] >= 1


def test_mutant_card_create_run_atm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeConfigManager:
        def default_card_pin(self) -> str:
            return "6666"

    monkeypatch.setattr("commands.mutant_card_commands.get_configuration_manager", lambda: _FakeConfigManager())
    args = _create_args(tmp_path)
    args.action = "create-run"
    args.mode = "atm"
    result = mutant_card_command(args)

    assert result.success is True
    assert result.data["result"]["mode"] == "atm"
    assert result.data["result"]["issuer_valid"] is True
    assert result.data["result"]["processor_status"] == "approved"
    assert result.data["result"]["authorization_response_code"] == "00"
    assert result.data["result"]["processing_mode"] == "normal"
    assert result.data["returned_logs"]["sealed_records"] >= 1
    assert result.data["returned_logs"]["decoded_records"] >= 1
