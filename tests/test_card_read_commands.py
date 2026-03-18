from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from commands.card_commands import card_history, card_read, card_read_full
from core.operator_log_codec import seal_log_payload


def _write_card(tmp_path: Path) -> Path:
    card_payload = {
        "kind": "mutant_test_card",
        "pan": "4003123412341234",
        "expiry": "12/30",
        "cvv": "123",
        "pin": "6666",
        "cardholder_name": "ALEX DOE",
        "card_type": "visa",
        "issuer": "Northstar Digital Bank",
        "track2": "4003123412341234D30122010000000000",
        "interface_profile": {"nfc_enabled": True, "rfid_enabled": True},
        "communication_log": [
            {
                "format": "gwlog-v1",
                "blob": seal_log_payload(
                    {
                        "timestamp": "2026-01-01T00:00:00Z",
                        "channel": "merchant",
                        "operation": "authorization",
                        "status": "approved",
                        "summary": {"transaction_id": "ABC123", "amount": 12.5},
                    }
                ),
            }
        ],
        "transaction_log_records": [
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "channel": "merchant",
                "operation": "authorization",
                "status": "approved",
                "details": seal_log_payload(
                    {
                        "timestamp": "2026-01-01T00:00:01Z",
                        "channel": "merchant",
                        "operation": "authorization",
                        "status": "approved",
                        "summary": {"transaction_id": "ABC123", "amount": 12.5},
                    }
                ),
            }
        ],
        "terminal_snapshots": [
            {
                "timestamp": "2026-01-01T00:00:02Z",
                "channel": "merchant",
                "scenario": "contactless",
                "request": {"amount_cents": 1250},
                "response": {"status": "approved"},
            }
        ],
    }
    card_file = tmp_path / "card.json"
    card_file.write_text(json.dumps(card_payload, indent=2), encoding="utf-8")
    return card_file


def test_card_read_masks_sensitive_fields_and_decodes_logs(tmp_path: Path) -> None:
    card_file = _write_card(tmp_path)
    result = card_read(
        Namespace(
            file=str(card_file),
            live=False,
            reader=None,
            aid=None,
            include_sensitive=False,
            no_decode_logs=False,
        )
    )
    assert result.success is True
    assert result.data["pan"].startswith("400312")
    assert "*" in result.data["pan"]
    assert result.data["log_decode"]["decode_successes"] == 2


def test_card_read_full_returns_sanitized_payload(tmp_path: Path) -> None:
    card_file = _write_card(tmp_path)
    result = card_read_full(
        Namespace(
            file=str(card_file),
            live=False,
            reader=None,
            aid=None,
            max_sfi=5,
            max_records=5,
            include_sensitive=False,
            no_decode_logs=False,
        )
    )
    assert result.success is True
    assert result.data["card"]["pin"] == "[REDACTED]"
    assert result.data["card"]["cvv"] == "[REDACTED]"
    assert result.data["decoded_logs"]["communication_log"][0]["decoded"]["status"] == "approved"


def test_card_history_collects_multiple_sources_with_limit(tmp_path: Path) -> None:
    card_file = _write_card(tmp_path)
    result = card_history(
        Namespace(
            file=str(card_file),
            limit=2,
            ascending=False,
            include_sensitive=False,
            no_decode_logs=False,
        )
    )
    assert result.success is True
    assert len(result.data["history"]) == 2
    assert result.data["history_stats"]["decode_successes"] == 2


def test_card_history_reports_missing_file() -> None:
    result = card_history(
        Namespace(
            file="missing_card.json",
            limit=10,
            ascending=False,
            include_sensitive=False,
            no_decode_logs=True,
        )
    )
    assert result.success is False
    assert result.exit_code == 1
