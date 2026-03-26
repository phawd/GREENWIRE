"""Mutant test-card workflow commands for operator use."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

from core.pipeline_providers import (
    EmulatorATMDevice,
    EmulatorHSMBackend,
    EmulatorPOSTerminalGateway,
    build_cryptogram_payload,
)
from core.configuration_manager import get_configuration_manager
from core.operator_log_codec import seal_log_payload, unseal_log_payload
from core.pan_registry import acquire_unique_pan, register_pan
from core.synthetic_identity import generate_cvv, generate_identity, generate_pan
from greenwire_modern import CommandResult, GreenwireCLI


def _build_mutant_card(args: argparse.Namespace) -> Dict[str, Any]:
    config_manager = get_configuration_manager()
    identity = generate_identity(
        args.card_type,
        cardholder_name=args.name,
        issuer_name=args.issuer,
        pan_length=args.length or None,
    )
    if args.pan:
        pan = "".join(ch for ch in str(args.pan) if ch.isdigit())
        if not getattr(args, "dry_run", False):
            register_pan(pan, source="mutant-card:explicit", allow_existing=True)
    else:
        pan = acquire_unique_pan(
            lambda: generate_pan(
                args.card_type,
                length=args.length or None,
                issuer_name=args.issuer or identity["issuer_name"],
            ),
            source="mutant-card:auto",
            reserve=not getattr(args, "dry_run", False),
        )
    expiry = args.expiry or (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=365 * 3)).strftime("%m/%y")
    cvv = args.cvv or generate_cvv(args.card_type)
    pin = str(getattr(args, "pin", None) or config_manager.default_card_pin() or "6666")
    floor_limit = int(args.floor_limit if args.floor_limit is not None else 50)
    cvm_method = args.cvm_method or "offline_pin_signature"
    atc = int(args.atc if args.atc is not None else 1)
    track2 = f"{pan}D{expiry.replace('/', '')}201{atc:04d}0000000"

    return {
        "kind": "mutant_test_card",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "card_type": args.card_type,
        "issuer": args.issuer or identity["issuer_name"],
        "cardholder_name": args.name or identity["cardholder_name"],
        "pan": pan,
        "expiry": expiry,
        "cvv": cvv,
        "pin": pin,
        "track2": track2,
        "atc": atc,
        "mutation_profile": args.mutation_profile,
        "floor_limit": floor_limit,
        "cvm_method": cvm_method,
        "processing_profile": {
            "mode": "normal",
            "normal_handling_required": True,
            "authorization_response_code": "00",
            "emv_outcome": "TC",
            "service_code": "201",
            "supported_mechanisms": ["merchant", "atm", "wallet", "nfc", "rfid", "pcsc", "hsm"],
        },
        "merchant_test_matrix": ["contact", "contactless", "magstripe_fallback"],
        "atm_test_matrix": ["cash_withdrawal", "balance_inquiry"],
    }


def _save_card(card_data: Dict[str, Any], output: str | None, dry_run: bool) -> Path:
    output_path = Path(output) if output else Path(f"mutant_card_{card_data['pan'][-4:]}.json")
    if not dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(card_data, indent=2), encoding="utf-8")
    return output_path


def _load_card(path: str) -> Dict[str, Any]:
    card_path = Path(path)
    if not card_path.exists():
        raise FileNotFoundError(f"Card file not found: {card_path}")
    return json.loads(card_path.read_text(encoding="utf-8"))


def _run_same_machine_emulation(card_data: Dict[str, Any], mode: str, amount: float) -> Dict[str, Any]:
    pan = card_data["pan"]
    track2 = card_data.get("track2", pan)
    atc = int(card_data.get("atc", 1))
    txn_id = hashlib.sha1(f"{pan}:{amount}:{mode}".encode()).hexdigest()[:12].upper()
    payload = build_cryptogram_payload(
        pan=pan,
        track2=track2,
        amount=amount,
        currency="USD",
        terminal_country="840",
        transaction_id=txn_id,
        atc=atc,
    )

    hsm = EmulatorHSMBackend()
    arqc = hsm.generate_arqc(pan=pan, atc=atc, payload=payload)
    issuer_valid = hsm.verify_arqc(pan=pan, atc=atc, payload=payload, arqc=arqc)
    response_code = card_data.get("processing_profile", {}).get("authorization_response_code", "00")

    if mode == "merchant":
        terminal = EmulatorPOSTerminalGateway()
        terminal_result = terminal.confirm_contactless_transaction(
            payload={
                "transaction_id": txn_id,
                "amount": amount,
                "currency": "USD",
                "contactless_profile": card_data.get("card_type", "EMV"),
                "cdcvm": {"type": "pin", "status": "verified"},
                "assurance_level": "standard",
            }
        )
        return {
            "mode": "merchant",
            "transaction_id": terminal_result.transaction_id,
            "terminal_status": terminal_result.status,
            "terminal_metadata": terminal_result.metadata,
            "amount": terminal_result.amount,
            "currency": terminal_result.currency,
            "processor_status": "approved" if issuer_valid else "declined",
            "authorization_response_code": response_code if issuer_valid else "05",
            "processing_mode": "normal",
            "emv_outcome": "TC" if issuer_valid else "AAC",
            "arqc": arqc,
            "issuer_valid": issuer_valid,
        }

    atm = EmulatorATMDevice()
    prepared = atm.prepare_card(profile=card_data)
    dispensed = atm.dispense_cash(
        request={
            "request_id": txn_id,
            "amount": amount,
            "currency": "USD",
            "atm_id": prepared["atm_id"],
            "cdcvm": {"type": "pin", "status": "verified"},
        }
    )
    return {
        "mode": "atm",
        "transaction_id": txn_id,
        "atm_status": dispensed.status,
        "atm_metadata": dispensed.metadata,
        "amount": dispensed.amount,
        "currency": dispensed.currency,
        "processor_status": "approved" if issuer_valid else "declined",
        "authorization_response_code": response_code if issuer_valid else "05",
        "processing_mode": "normal",
        "emv_outcome": "TC" if issuer_valid else "AAC",
        "arqc": arqc,
        "issuer_valid": issuer_valid,
    }


def _decode_returned_logs(card_data: Dict[str, Any]) -> Tuple[int, int]:
    total = 0
    decoded = 0
    for record in card_data.get("communication_log", []):
        if not isinstance(record, dict):
            continue
        blob = record.get("blob")
        if not blob:
            continue
        total += 1
        try:
            unseal_log_payload(blob)
            decoded += 1
        except Exception:
            continue
    return total, decoded


def _append_processing_log(card_data: Dict[str, Any], mode: str, result: Dict[str, Any]) -> None:
    card_data.setdefault("communication_log", []).append(
        {
            "format": "gwlog-v1",
            "blob": seal_log_payload(
                {
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "channel": mode,
                    "operation": "mutant_card_run",
                    "status": result.get("terminal_status") or result.get("atm_status") or "completed",
                    "summary": {
                        "transaction_id": result.get("transaction_id"),
                        "amount": result.get("amount"),
                        "currency": result.get("currency"),
                        "issuer_valid": result.get("issuer_valid"),
                    },
                }
            ),
        }
    )


def mutant_card_command(args: argparse.Namespace) -> CommandResult:
    action = args.action
    try:
        if action == "create":
            card_data = _build_mutant_card(args)
            output_path = _save_card(card_data, args.output, args.dry_run)
            return CommandResult(
                True,
                "Mutant test card created",
                data={
                    "card_file": str(output_path),
                    "pan": card_data["pan"],
                    "card_type": card_data["card_type"],
                    "mutation_profile": card_data["mutation_profile"],
                },
            )

        if action == "run":
            card_data = _load_card(args.card_file)
            emu_result = _run_same_machine_emulation(card_data, args.mode, args.amount)
            _append_processing_log(card_data, args.mode, emu_result)
            Path(args.card_file).write_text(json.dumps(card_data, indent=2), encoding="utf-8")
            total_logs, decoded_logs = _decode_returned_logs(card_data)
            return CommandResult(
                True,
                "Mutant test card emulation completed",
                data={
                    "card_file": args.card_file,
                    "card_pan": card_data["pan"],
                    "result": emu_result,
                    "returned_logs": {
                        "sealed_records": total_logs,
                        "decoded_records": decoded_logs,
                    },
                },
            )

        card_data = _build_mutant_card(args)
        output_path = _save_card(card_data, args.output, args.dry_run)
        emu_result = _run_same_machine_emulation(card_data, args.mode, args.amount)
        _append_processing_log(card_data, args.mode, emu_result)
        if not args.dry_run:
            output_path.write_text(json.dumps(card_data, indent=2), encoding="utf-8")
        total_logs, decoded_logs = _decode_returned_logs(card_data)
        return CommandResult(
            True,
            "Mutant test card created and executed",
            data={
                "card_file": str(output_path),
                "card_pan": card_data["pan"],
                "result": emu_result,
                "returned_logs": {
                    "sealed_records": total_logs,
                    "decoded_records": decoded_logs,
                },
            },
        )
    except Exception as exc:
        return CommandResult(False, f"Mutant card workflow failed: {exc}", exit_code=1)


def register_mutant_card_commands(cli: GreenwireCLI) -> None:
    cli.register_command(
        name="mutant-card",
        func=mutant_card_command,
        description="Create and run a mutant test card on the same machine in merchant or ATM emulation mode",
        args=[
            {"name": "action", "choices": ["create", "run", "create-run"]},
            {"name": "--mode", "choices": ["merchant", "atm"], "default": "merchant"},
            {"name": "--card-file", "type": str, "help": "Existing mutant card JSON (required for run)"},
            {"name": "--card-type", "choices": ["visa", "mastercard", "amex", "discover"], "default": "visa"},
            {"name": "--pan", "type": str, "help": "Optional PAN override"},
            {"name": "--name", "type": str, "help": "Cardholder name override"},
            {"name": "--issuer", "type": str, "help": "Issuer name override"},
            {"name": "--expiry", "type": str, "help": "Expiry date MM/YY"},
            {"name": "--cvv", "type": str, "help": "Card CVV/CVC"},
            {"name": "--pin", "type": str, "help": "Card PIN override"},
            {"name": "--length", "type": int, "help": "PAN length override"},
            {"name": "--atc", "type": int, "default": 1, "help": "Application transaction counter"},
            {"name": "--floor-limit", "type": int, "default": 50, "help": "Mutant profile floor limit"},
            {"name": "--cvm-method", "type": str, "default": "offline_pin_signature", "help": "Mutant profile CVM"},
            {"name": "--mutation-profile", "choices": ["balanced", "aggressive", "chaos"], "default": "balanced"},
            {"name": "--amount", "type": float, "default": 12.50, "help": "Emulation amount"},
            {"name": "--output", "type": str, "help": "Output card file path"},
        ],
        aliases=["mutant-test-card"],
    )
