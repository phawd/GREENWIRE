"""
Card Management Commands
========================

Commands for creating, managing, and manipulating payment cards.
"""

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import the CLI framework
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.synthetic_identity import (
    calculate_luhn_checksum,
    generate_cardholder_name,
    generate_cvv,
    generate_identity,
    generate_issuer_name,
    generate_pan,
    validate_luhn,
)
from core.configuration_manager import get_configuration_manager
from core.operator_log_codec import unseal_log_payload
from core.pan_registry import acquire_unique_pan, register_pan
from core.issuance_validation import (
    is_test_function_invocation,
    validate_card_identity,
    validate_issuance_crypto_readiness,
    validate_key_profile,
    validate_merchant_required_fields,
    validate_pin_value,
)
from greenwire_modern import CommandResult, GreenwireCLI


def card_create(args: argparse.Namespace) -> CommandResult:
    """Create a new payment card with specified parameters"""
    config_manager = get_configuration_manager()
    config = config_manager.data()
    key_profile = getattr(args, "key_profile", "production")
    merchant_id = getattr(args, "merchant_id", "MERCHANT-0001")
    terminal_id = getattr(args, "terminal_id", "POS-EMU-01")
    mcc = getattr(args, "mcc", "5411")
    acquirer_id = getattr(args, "acquirer_id", "00000012345")
    country_code = getattr(args, "country_code", "840")
    currency = str(getattr(args, "currency", "USD")).upper()
    is_test_function = is_test_function_invocation(
        getattr(args, "command", None),
        getattr(args, "test_function", False),
    )
    
    # Validate required parameters
    if not args.pan and not args.generate_pan:
        return CommandResult(
            success=False,
            message="Either --pan or --generate-pan must be specified",
            exit_code=2
        )
    
    requested_iin = (
        args.bin_prefix
        if args.bin_prefix and len("".join(ch for ch in args.bin_prefix if ch.isdigit())) >= 6
        else None
    )
    identity = generate_identity(
        args.card_type,
        cardholder_name=args.name,
        issuer_name=args.issuer,
        pan_length=args.length or None,
        iin=requested_iin,
    )

    if args.pan:
        pan = "".join(ch for ch in str(args.pan) if ch.isdigit())
        if not args.dry_run:
            register_pan(pan, source="card-create:explicit", allow_existing=True)
    else:
        issuer_for_pan = args.issuer or identity["issuer_name"]
        pan = acquire_unique_pan(
            lambda: generate_pan(
                args.card_type,
                length=args.length or None,
                iin=requested_iin,
                issuer_name=issuer_for_pan,
            ),
            source="card-create:auto",
            reserve=not args.dry_run,
        )
    cardholder_name = generate_cardholder_name(args.name or identity["cardholder_name"])
    issuer_name = args.issuer or identity["issuer_name"] or generate_issuer_name(args.card_type)
    pin = _resolve_card_pin(
        explicit_pin=getattr(args, "pin", None),
        config_default=config_manager.default_card_pin(),
    )
    nfc_enabled = _resolve_interface_flag(
        enabled_flag=bool(getattr(args, "nfc", False)),
        disabled_flag=bool(getattr(args, "no_nfc", False)),
        config_default=bool(config.get("cards", {}).get("default_nfc_enabled", True)),
    )
    rfid_enabled = _resolve_interface_flag(
        enabled_flag=bool(getattr(args, "rfid", False)),
        disabled_flag=bool(getattr(args, "no_rfid", False)),
        config_default=bool(config.get("cards", {}).get("default_rfid_enabled", True)),
    )

    # Card data structure
    card_data = {
        'pan': pan,
        'expiry': args.expiry or _generate_expiry(),
        'cvv': args.cvv or _generate_cvv(args.card_type),
        'pin': pin,
        'cardholder_name': cardholder_name,
        'created_at': datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        'card_type': args.card_type,
        'issuer': issuer_name,
        'key_profile': key_profile,
        'test_context': bool(is_test_function),
        'interface_profile': {
            'nfc_enabled': nfc_enabled,
            'rfid_enabled': rfid_enabled,
        },
        'merchant_context': {
            'merchant_id': merchant_id,
            'terminal_id': terminal_id,
            'mcc': mcc,
            'acquirer_id': acquirer_id,
            'country_code': country_code,
            'currency': currency,
        },
    }

    key_errors = validate_key_profile(
        key_profile=key_profile,
        is_test_function=is_test_function,
    )
    identity_errors = validate_card_identity(
        pan=card_data["pan"],
        expiry=card_data["expiry"],
        cvv=card_data["cvv"],
        cardholder_name=card_data["cardholder_name"],
        issuer_name=card_data["issuer"],
    )
    merchant_errors = validate_merchant_required_fields(card_data["merchant_context"])
    pin_errors = validate_pin_value(pin)
    crypto_errors = validate_issuance_crypto_readiness(
        pan=pan,
        atc=1,
        include_atm=bool(getattr(args, "validate_atm", False)),
    )
    errors = key_errors + identity_errors + merchant_errors + pin_errors + crypto_errors
    if errors:
        return CommandResult(
            success=False,
            message="Card creation validation failed",
            data={"errors": errors},
            exit_code=2,
        )
    
    # Add EMV data if requested
    if args.emv_data:
        card_data['emv'] = _generate_emv_data(card_data)
    
    # Add cryptographic keys if requested
    if args.crypto_keys:
        card_data['crypto'] = _generate_crypto_keys()
    
    # Save card data
    output_file = args.output or f"card_{card_data['pan'][-4:]}.json"
    
    if not args.dry_run:
        with open(output_file, 'w') as f:
            json.dump(card_data, f, indent=2)
    
    return CommandResult(
        success=True,
        message=f"Card created successfully: {card_data['pan']}",
        data={
            'pan': card_data['pan'],
            'expiry': card_data['expiry'],
            'output_file': output_file,
            'has_emv': args.emv_data,
            'has_crypto': args.crypto_keys,
            'key_profile': key_profile,
            'test_context': bool(is_test_function),
            'pin': pin,
            'nfc_enabled': nfc_enabled,
            'rfid_enabled': rfid_enabled,
        }
    )


def card_list(args: argparse.Namespace) -> CommandResult:
    """List available card files"""
    
    search_dir = Path(args.directory or ".")
    pattern = args.pattern or "*.json"
    
    card_files = list(search_dir.glob(pattern))
    cards_data = []
    
    for card_file in card_files:
        try:
            with open(card_file) as f:
                card_data = json.load(f)
            
            if 'pan' in card_data:  # Looks like a card file
                cards_data.append({
                    'file': str(card_file),
                    'pan': _mask_pan(card_data['pan']),
                    'expiry': card_data.get('expiry', 'N/A'),
                    'type': card_data.get('card_type', 'Unknown'),
                    'created': card_data.get('created_at', 'N/A')
                })
        except (json.JSONDecodeError, KeyError):
            continue  # Skip non-card files
    
    return CommandResult(
        success=True,
        message=f"Found {len(cards_data)} card files",
        data={'cards': cards_data}
    )


def card_validate(args: argparse.Namespace) -> CommandResult:
    """Validate card data integrity and compliance"""
    
    try:
        with open(args.file) as f:
            card_data = json.load(f)
    except FileNotFoundError:
        return CommandResult(
            success=False,
            message=f"Card file not found: {args.file}",
            exit_code=1
        )
    except json.JSONDecodeError as e:
        return CommandResult(
            success=False,
            message=f"Invalid JSON in card file: {e}",
            exit_code=1
        )
    
    validation_results = {}
    
    # Validate PAN
    pan = card_data.get('pan', '')
    validation_results['pan_present'] = bool(pan)
    validation_results['pan_length'] = len(pan) in [15, 16, 17, 18, 19]
    validation_results['luhn_valid'] = _validate_luhn(pan)
    
    # Validate expiry
    expiry = card_data.get('expiry', '')
    validation_results['expiry_present'] = bool(expiry)
    validation_results['expiry_format'] = len(expiry) == 5 and expiry[2] == '/'
    
    # Validate CVV
    cvv = card_data.get('cvv', '')
    validation_results['cvv_present'] = bool(cvv)
    validation_results['cvv_length'] = len(cvv) in [3, 4]
    
    # Overall validation
    all_valid = all(validation_results.values())
    
    return CommandResult(
        success=all_valid,
        message="Card validation passed" if all_valid else "Card validation failed",
        data={'validation': validation_results, 'card_file': str(args.file)}
    )


def card_clone(args: argparse.Namespace) -> CommandResult:
    """Clone an existing card with modifications"""
    
    try:
        with open(args.source) as f:
            source_card = json.load(f)
    except FileNotFoundError:
        return CommandResult(
            success=False,
            message=f"Source card file not found: {args.source}",
            exit_code=1
        )
    
    # Clone and modify
    cloned_card = source_card.copy()
    
    if args.new_pan:
        cloned_card['pan'] = args.new_pan
    elif args.generate_new_pan:
        cloned_card['pan'] = _generate_pan()
    
    if args.new_expiry:
        cloned_card['expiry'] = args.new_expiry
    
    if args.new_name:
        cloned_card['cardholder_name'] = args.new_name
    
    # Update metadata
    cloned_card['cloned_from'] = str(args.source)
    cloned_card['cloned_at'] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    # Save cloned card
    output_file = args.output or f"cloned_{cloned_card['pan'][-4:]}.json"
    
    if not args.dry_run:
        with open(output_file, 'w') as f:
            json.dump(cloned_card, f, indent=2)
    
    return CommandResult(
        success=True,
        message=f"Card cloned successfully",
        data={
            'source': str(args.source),
            'output': output_file,
            'new_pan': _mask_pan(cloned_card['pan'])
        }
    )


def card_read(args: argparse.Namespace) -> CommandResult:
    """Read card metadata from file or live reader."""
    include_sensitive = bool(getattr(args, "include_sensitive", False))
    decode_logs = not bool(getattr(args, "no_decode_logs", False))
    live_mode = bool(getattr(args, "live", False))

    if live_mode:
        live_result = _attempt_live_card_read(
            reader=getattr(args, "reader", None),
            aid=getattr(args, "aid", None),
            full_scan=False,
            max_sfi=1,
            max_records=1,
        )
        return CommandResult(
            success=live_result["success"],
            message=live_result["message"],
            data=live_result["data"],
            exit_code=0 if live_result["success"] else 1,
        )

    card_data, load_error = _load_card_file(getattr(args, "file", None))
    if load_error:
        return CommandResult(False, load_error, exit_code=1)

    assert card_data is not None
    decoded_logs = _decode_log_sections(
        card_data=card_data,
        decode_logs=decode_logs,
        include_sensitive=include_sensitive,
    )
    summary = _build_card_summary(card_data, include_sensitive=include_sensitive)
    summary["card_file"] = str(Path(args.file))
    summary["log_decode"] = decoded_logs["decode_stats"]

    return CommandResult(
        success=True,
        message="Card read completed",
        data=summary,
    )


def card_read_full(args: argparse.Namespace) -> CommandResult:
    """Attempt full card read from file or live reader."""
    include_sensitive = bool(getattr(args, "include_sensitive", False))
    decode_logs = not bool(getattr(args, "no_decode_logs", False))
    live_mode = bool(getattr(args, "live", False))

    if live_mode:
        live_result = _attempt_live_card_read(
            reader=getattr(args, "reader", None),
            aid=getattr(args, "aid", None),
            full_scan=True,
            max_sfi=max(1, int(getattr(args, "max_sfi", 10))),
            max_records=max(1, int(getattr(args, "max_records", 10))),
        )
        return CommandResult(
            success=live_result["success"],
            message=live_result["message"],
            data=live_result["data"],
            exit_code=0 if live_result["success"] else 1,
        )

    card_data, load_error = _load_card_file(getattr(args, "file", None))
    if load_error:
        return CommandResult(False, load_error, exit_code=1)

    assert card_data is not None
    decoded_logs = _decode_log_sections(
        card_data=card_data,
        decode_logs=decode_logs,
        include_sensitive=include_sensitive,
    )
    sanitized_card = _sanitize_payload(card_data, include_sensitive=include_sensitive)
    decode_stats = decoded_logs["decode_stats"]
    decode_failures = int(decode_stats.get("decode_failures", 0))
    message = (
        "Card full-read attempt completed with partial log decode"
        if decode_failures > 0
        else "Card full-read attempt completed"
    )

    return CommandResult(
        success=True,
        message=message,
        data={
            "card_file": str(Path(args.file)),
            "card": sanitized_card,
            "decoded_logs": {
                "communication_log": decoded_logs["communication_entries"],
                "transaction_log_records": decoded_logs["transaction_entries"],
            },
            "decode_stats": decode_stats,
        },
    )


def card_history(args: argparse.Namespace) -> CommandResult:
    """Read transaction history from card artifacts."""
    include_sensitive = bool(getattr(args, "include_sensitive", False))
    decode_logs = not bool(getattr(args, "no_decode_logs", False))
    limit = max(0, int(getattr(args, "limit", 50)))

    card_data, load_error = _load_card_file(getattr(args, "file", None))
    if load_error:
        return CommandResult(False, load_error, exit_code=1)

    assert card_data is not None
    history_entries, history_stats = _build_card_history(
        card_data=card_data,
        decode_logs=decode_logs,
        include_sensitive=include_sensitive,
    )

    ascending = bool(getattr(args, "ascending", False))
    history_entries.sort(
        key=lambda entry: str(entry.get("timestamp") or ""),
        reverse=not ascending,
    )
    if limit > 0:
        history_entries = history_entries[:limit]

    return CommandResult(
        success=True,
        message=f"Card history read completed ({len(history_entries)} records)",
        data={
            "card_file": str(Path(args.file)),
            "history": history_entries,
            "history_stats": history_stats,
            "order": "ascending" if ascending else "descending",
            "limit": limit,
        },
    )


def _load_card_file(path_value: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not path_value:
        return None, "--file is required unless --live is used"

    card_path = Path(path_value)
    if not card_path.exists():
        return None, f"Card file not found: {card_path}"

    try:
        return json.loads(card_path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as exc:
        return None, f"Invalid JSON in card file: {exc}"
    except OSError as exc:
        return None, f"Failed to read card file: {exc}"


def _build_card_summary(card_data: Dict[str, Any], include_sensitive: bool) -> Dict[str, Any]:
    pan_value = str(card_data.get("pan", ""))
    return {
        "kind": card_data.get("kind", "card"),
        "pan": pan_value if include_sensitive else _mask_pan(pan_value),
        "expiry": card_data.get("expiry"),
        "cardholder_name": card_data.get("cardholder_name"),
        "card_type": card_data.get("card_type"),
        "issuer": card_data.get("issuer"),
        "created_at": card_data.get("created_at"),
        "interfaces": card_data.get("interface_profile", {}),
        "has_emv": "emv" in card_data,
        "has_crypto": "crypto" in card_data,
        "communication_log_count": len(card_data.get("communication_log", [])),
        "transaction_log_count": len(card_data.get("transaction_log_records", [])),
        "terminal_snapshot_count": len(card_data.get("terminal_snapshots", [])),
    }


def _mask_track2(track2: str) -> str:
    if not track2:
        return track2
    if "D" in track2:
        pan_part, remainder = track2.split("D", 1)
        return f"{_mask_pan(pan_part)}D{remainder}"
    if "=" in track2:
        pan_part, remainder = track2.split("=", 1)
        return f"{_mask_pan(pan_part)}={remainder}"
    return _mask_pan(track2)


def _sanitize_payload(payload: Any, include_sensitive: bool) -> Any:
    if include_sensitive:
        return payload

    if isinstance(payload, dict):
        sanitized: Dict[str, Any] = {}
        for key, value in payload.items():
            lowered = str(key).lower()
            if lowered in {"pan", "card_number", "primary_account_number"} and isinstance(value, str):
                sanitized[key] = _mask_pan(value)
                continue
            if lowered in {"track2", "track2_data"} and isinstance(value, str):
                sanitized[key] = _mask_track2(value)
                continue
            if lowered in {"cvv", "cvv2", "cvc", "pin", "pin_block"} and value is not None:
                sanitized[key] = "[REDACTED]"
                continue
            sanitized[key] = _sanitize_payload(value, include_sensitive=False)
        return sanitized

    if isinstance(payload, list):
        return [_sanitize_payload(item, include_sensitive=False) for item in payload]

    return payload


def _decode_sealed_blob(blob: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not blob:
        return None, "empty_blob"
    if not isinstance(blob, str) or not blob.startswith("gwlog-v1:"):
        return None, "unsupported_format"
    try:
        return unseal_log_payload(blob), None
    except Exception as exc:  # pragma: no cover - machine-bound decode failures are runtime-dependent
        return None, str(exc)


def _decode_log_sections(
    card_data: Dict[str, Any],
    decode_logs: bool,
    include_sensitive: bool,
) -> Dict[str, Any]:
    communication_entries: List[Dict[str, Any]] = []
    transaction_entries: List[Dict[str, Any]] = []
    decode_successes = 0
    decode_failures = 0

    for index, record in enumerate(card_data.get("communication_log", [])):
        entry: Dict[str, Any] = {
            "index": index,
            "format": record.get("format"),
            "has_blob": bool(record.get("blob")),
        }
        blob = record.get("blob")
        if decode_logs and isinstance(blob, str):
            decoded, error = _decode_sealed_blob(blob)
            if decoded is not None:
                entry["decoded"] = _sanitize_payload(decoded, include_sensitive=include_sensitive)
                decode_successes += 1
            elif error:
                entry["decode_error"] = error
                decode_failures += 1
        communication_entries.append(entry)

    for index, record in enumerate(card_data.get("transaction_log_records", [])):
        entry = {
            "index": index,
            "timestamp": record.get("timestamp"),
            "operation": record.get("operation"),
            "channel": record.get("channel"),
            "status": record.get("status"),
            "has_details": bool(record.get("details")),
        }
        details = record.get("details")
        if decode_logs and isinstance(details, str) and details.startswith("gwlog-v1:"):
            decoded, error = _decode_sealed_blob(details)
            if decoded is not None:
                entry["decoded"] = _sanitize_payload(decoded, include_sensitive=include_sensitive)
                decode_successes += 1
            elif error:
                entry["decode_error"] = error
                decode_failures += 1
        transaction_entries.append(entry)

    return {
        "communication_entries": communication_entries,
        "transaction_entries": transaction_entries,
        "decode_stats": {
            "decode_requested": bool(decode_logs),
            "decode_successes": decode_successes,
            "decode_failures": decode_failures,
            "communication_records": len(communication_entries),
            "transaction_records": len(transaction_entries),
        },
    }


def _build_card_history(
    card_data: Dict[str, Any],
    decode_logs: bool,
    include_sensitive: bool,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    history_entries: List[Dict[str, Any]] = []
    decode_successes = 0
    decode_failures = 0

    for index, record in enumerate(card_data.get("transaction_log_records", [])):
        entry: Dict[str, Any] = {
            "source": "transaction_log_records",
            "index": index,
            "timestamp": record.get("timestamp"),
            "channel": record.get("channel"),
            "operation": record.get("operation"),
            "status": record.get("status"),
        }
        details = record.get("details")
        if decode_logs and isinstance(details, str) and details.startswith("gwlog-v1:"):
            decoded, error = _decode_sealed_blob(details)
            if decoded is not None:
                entry["details"] = _sanitize_payload(decoded, include_sensitive=include_sensitive)
                decode_successes += 1
            elif error:
                entry["decode_error"] = error
                decode_failures += 1
        elif details is not None:
            entry["details"] = _sanitize_payload(details, include_sensitive=include_sensitive)
        history_entries.append(entry)

    for index, record in enumerate(card_data.get("communication_log", [])):
        entry = {
            "source": "communication_log",
            "index": index,
            "timestamp": None,
            "channel": None,
            "operation": "communication_log_entry",
            "status": "sealed" if record.get("blob") else "empty",
        }
        blob = record.get("blob")
        if decode_logs and isinstance(blob, str):
            decoded, error = _decode_sealed_blob(blob)
            if decoded is not None:
                entry["timestamp"] = decoded.get("timestamp")
                entry["channel"] = decoded.get("channel")
                entry["operation"] = decoded.get("operation") or entry["operation"]
                entry["status"] = decoded.get("status") or entry["status"]
                entry["summary"] = _sanitize_payload(
                    decoded.get("summary"),
                    include_sensitive=include_sensitive,
                )
                decode_successes += 1
            elif error:
                entry["decode_error"] = error
                decode_failures += 1
        history_entries.append(entry)

    for index, snapshot in enumerate(card_data.get("terminal_snapshots", [])):
        history_entries.append(
            {
                "source": "terminal_snapshots",
                "index": index,
                "timestamp": snapshot.get("timestamp"),
                "channel": snapshot.get("channel"),
                "operation": snapshot.get("scenario"),
                "status": "snapshot",
                "request": _sanitize_payload(snapshot.get("request"), include_sensitive=include_sensitive),
                "response": _sanitize_payload(snapshot.get("response"), include_sensitive=include_sensitive),
            }
        )

    stats = {
        "transaction_log_records": len(card_data.get("transaction_log_records", [])),
        "communication_log_records": len(card_data.get("communication_log", [])),
        "terminal_snapshot_records": len(card_data.get("terminal_snapshots", [])),
        "decode_requested": bool(decode_logs),
        "decode_successes": decode_successes,
        "decode_failures": decode_failures,
    }
    return history_entries, stats


def _attempt_live_card_read(
    *,
    reader: Optional[str],
    aid: Optional[str],
    full_scan: bool,
    max_sfi: int,
    max_records: int,
) -> Dict[str, Any]:
    try:
        from apdu_communicator import APDUCommunicator
    except Exception as exc:  # pragma: no cover - depends on runtime modules
        return {
            "success": False,
            "message": f"Live card read unavailable: {exc}",
            "data": {"live_mode": True, "reason": "apdu_communicator_import_failed"},
        }

    communicator = APDUCommunicator(verbose=False)
    available_readers = communicator.list_readers()
    if not available_readers:
        return {
            "success": False,
            "message": "No PC/SC readers detected",
            "data": {"live_mode": True, "available_readers": []},
        }

    if not communicator.connect_reader(reader):
        return {
            "success": False,
            "message": "Failed to connect to reader or card",
            "data": {"live_mode": True, "available_readers": available_readers, "requested_reader": reader},
        }

    try:
        atr = communicator.get_atr()
        steps: List[Dict[str, Any]] = []

        ppse = "00A404000E325041592E5359532E444446303100"
        ppse_response, ppse_status = communicator.send_apdu(ppse)
        steps.append(
            {
                "command": "SELECT_PPSE",
                "apdu": ppse,
                "status": ppse_status,
                "response": ppse_response,
            }
        )

        if aid:
            normalized_aid = "".join(ch for ch in aid if ch in "0123456789abcdefABCDEF").upper()
            if not normalized_aid:
                return {
                    "success": False,
                    "message": "AID must include hexadecimal characters",
                    "data": {"live_mode": True, "available_readers": available_readers},
                }
            if len(normalized_aid) % 2 != 0:
                return {
                    "success": False,
                    "message": "AID must contain an even number of hex characters",
                    "data": {"live_mode": True, "available_readers": available_readers},
                }
            select_aid = f"00A40400{len(normalized_aid) // 2:02X}{normalized_aid}"
            aid_response, aid_status = communicator.send_apdu(select_aid)
            steps.append(
                {
                    "command": "SELECT_AID",
                    "apdu": select_aid,
                    "status": aid_status,
                    "response": aid_response,
                }
            )

        records: List[Dict[str, Any]] = []
        if full_scan:
            for sfi in range(1, max_sfi + 1):
                for record in range(1, max_records + 1):
                    p2 = (sfi << 3) | 0x04
                    apdu = f"00B2{record:02X}{p2:02X}00"
                    response, status = communicator.send_apdu(apdu)
                    if status == "9000" and response:
                        records.append(
                            {
                                "sfi": sfi,
                                "record": record,
                                "status": status,
                                "response": response,
                            }
                        )

        selected_reader = communicator.reader_name or reader or available_readers[0]
        return {
            "success": True,
            "message": "Live card read completed" if not full_scan else "Live full-read attempt completed",
            "data": {
                "live_mode": True,
                "reader": selected_reader,
                "atr": atr,
                "available_readers": available_readers,
                "steps": steps,
                "read_records": records,
                "read_record_count": len(records),
            },
        }
    finally:
        communicator.disconnect()


def _generate_pan(bin_prefix: str = "4000", length: int = 16) -> str:
    """Generate a valid PAN with Luhn checksum"""
    normalized_iin = bin_prefix if len("".join(ch for ch in bin_prefix if ch.isdigit())) >= 6 else None
    return generate_pan("visa", length=length, iin=normalized_iin)


def _generate_expiry() -> str:
    """Generate future expiry date"""
    import random
    from datetime import datetime, timedelta
    
    future_date = datetime.now() + timedelta(days=random.randint(365, 1825))  # 1-5 years
    return future_date.strftime("%m/%y")


def _generate_cvv(card_type: str = "visa") -> str:
    """Generate random CVV"""
    return generate_cvv(card_type)


def _generate_emv_data(card_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate EMV application data"""
    return {
        'aid': '315041592E5359532E4444463031',  # Visa DDF
        'application_label': card_data['card_type'].upper(),
        'track2_data': f"{card_data['pan']}D{card_data['expiry'].replace('/', '')}101",
        'tags': {
            '5A': card_data['pan'],  # Application PAN
            '5F24': card_data['expiry'].replace('/', ''),  # Expiry date
            '9F08': '0002',  # Application version
            '9F42': '840',   # Application currency code (USD)
        }
    }


def _generate_crypto_keys() -> Dict[str, Any]:
    """Generate cryptographic keys for the card"""
    import secrets
    
    return {
        'ac_key': secrets.token_hex(16),  # Application Cryptogram key
        'smc_key': secrets.token_hex(16),  # Secure Messaging for Confidentiality
        'smi_key': secrets.token_hex(16),  # Secure Messaging for Integrity
        'dac_key': secrets.token_hex(16),  # Data Authentication Code key
    }


def _mask_pan(pan: str) -> str:
    """Mask PAN for safe display"""
    if len(pan) < 8:
        return pan
    return pan[:6] + '*' * (len(pan) - 10) + pan[-4:]


def _validate_luhn(pan: str) -> bool:
    """Validate PAN using Luhn algorithm"""
    return validate_luhn(pan)


def _resolve_interface_flag(*, enabled_flag: bool, disabled_flag: bool, config_default: bool) -> bool:
    if enabled_flag:
        return True
    if disabled_flag:
        return False
    return bool(config_default)


def _resolve_card_pin(*, explicit_pin: Optional[str], config_default: str) -> str:
    if explicit_pin is not None and str(explicit_pin).strip():
        return str(explicit_pin).strip()
    return str(config_default or "6666").strip() or "6666"


def _calculate_luhn_checksum(partial_pan: str) -> int:
    """Calculate Luhn checksum digit"""
    return calculate_luhn_checksum(partial_pan)


def register_card_commands(cli: GreenwireCLI):
    """Register all card management commands"""
    
    # Card create command
    cli.register_command(
        name='card-create',
        func=card_create,
        description='Create a new payment card',
        args=[
            {'name': '--pan', 'type': str, 'help': 'Primary Account Number'},
            {'name': '--generate-pan', 'action': 'store_true', 'help': 'Generate random PAN'},
            {'name': '--bin-prefix', 'type': str, 'help': 'Optional 6-8 digit IIN/BIN prefix for generated PAN'},
            {'name': '--length', 'type': int, 'help': 'Optional PAN length override'},
            {'name': '--expiry', 'type': str, 'help': 'Expiry date (MM/YY)'},
            {'name': '--cvv', 'type': str, 'help': 'Card verification value'},
            {'name': '--pin', 'type': str, 'help': 'Card PIN/PIN block source value'},
            {'name': '--name', 'type': str, 'help': 'Cardholder name'},
            {'name': '--card-type', 'choices': ['visa', 'mastercard', 'amex', 'discover'], 
             'default': 'visa', 'help': 'Card type'},
            {'name': '--issuer', 'type': str, 'help': 'Issuer identifier'},
            {'name': '--emv-data', 'action': 'store_true', 'help': 'Include EMV application data'},
            {'name': '--crypto-keys', 'action': 'store_true', 'help': 'Generate cryptographic keys'},
            {'name': '--output', 'type': str, 'help': 'Output file path'},
            {'name': '--key-profile', 'choices': ['production', 'test'], 'default': 'production', 'help': 'Issuance key profile'},
            {'name': '--merchant-id', 'type': str, 'default': 'MERCHANT-0001', 'help': 'Merchant identifier'},
            {'name': '--terminal-id', 'type': str, 'default': 'POS-EMU-01', 'help': 'Terminal identifier'},
            {'name': '--mcc', 'type': str, 'default': '5411', 'help': 'Merchant category code'},
            {'name': '--acquirer-id', 'type': str, 'default': '00000012345', 'help': 'Acquirer identifier'},
            {'name': '--country-code', 'type': str, 'default': '840', 'help': 'Numeric country code'},
            {'name': '--currency', 'type': str, 'default': 'USD', 'help': 'Currency code'},
            {'name': '--test-function', 'action': 'store_true', 'help': 'Mark the operation as a test workflow while still using production-style data'},
            {'name': '--nfc', 'action': 'store_true', 'default': False, 'help': 'Enable NFC interface'},
            {'name': '--no-nfc', 'action': 'store_true', 'default': False, 'help': 'Disable NFC interface'},
            {'name': '--rfid', 'action': 'store_true', 'default': False, 'help': 'Enable RFID interface'},
            {'name': '--no-rfid', 'action': 'store_true', 'default': False, 'help': 'Disable RFID interface'},
            {'name': '--validate-atm', 'action': 'store_true', 'default': False, 'help': 'Also validate readiness for ATM transport'},
        ],
        aliases=['create-card']
    )
    cli.register_command(
        name='card-create-test',
        func=card_create,
        description='Create a new payment card using test-function validation mode',
        args=[
            {'name': '--pan', 'type': str, 'help': 'Primary Account Number'},
            {'name': '--generate-pan', 'action': 'store_true', 'help': 'Generate random PAN'},
            {'name': '--bin-prefix', 'type': str, 'help': 'Optional 6-8 digit IIN/BIN prefix for generated PAN'},
            {'name': '--length', 'type': int, 'help': 'Optional PAN length override'},
            {'name': '--expiry', 'type': str, 'help': 'Expiry date (MM/YY)'},
            {'name': '--cvv', 'type': str, 'help': 'Card verification value'},
            {'name': '--pin', 'type': str, 'help': 'Card PIN/PIN block source value'},
            {'name': '--name', 'type': str, 'help': 'Cardholder name'},
            {'name': '--card-type', 'choices': ['visa', 'mastercard', 'amex', 'discover'],
             'default': 'visa', 'help': 'Card type'},
            {'name': '--issuer', 'type': str, 'help': 'Issuer identifier'},
            {'name': '--emv-data', 'action': 'store_true', 'help': 'Include EMV application data'},
            {'name': '--crypto-keys', 'action': 'store_true', 'help': 'Generate cryptographic keys'},
            {'name': '--output', 'type': str, 'help': 'Output file path'},
            {'name': '--key-profile', 'choices': ['production', 'test'], 'default': 'production', 'help': 'Issuance key profile'},
            {'name': '--merchant-id', 'type': str, 'default': 'MERCHANT-0001', 'help': 'Merchant identifier'},
            {'name': '--terminal-id', 'type': str, 'default': 'POS-EMU-01', 'help': 'Terminal identifier'},
            {'name': '--mcc', 'type': str, 'default': '5411', 'help': 'Merchant category code'},
            {'name': '--acquirer-id', 'type': str, 'default': '00000012345', 'help': 'Acquirer identifier'},
            {'name': '--country-code', 'type': str, 'default': '840', 'help': 'Numeric country code'},
            {'name': '--currency', 'type': str, 'default': 'USD', 'help': 'Currency code'},
            {'name': '--test-function', 'action': 'store_true', 'default': True, 'help': 'Enabled for test command while still using production-style data'},
            {'name': '--nfc', 'action': 'store_true', 'default': False, 'help': 'Enable NFC interface'},
            {'name': '--no-nfc', 'action': 'store_true', 'default': False, 'help': 'Disable NFC interface'},
            {'name': '--rfid', 'action': 'store_true', 'default': False, 'help': 'Enable RFID interface'},
            {'name': '--no-rfid', 'action': 'store_true', 'default': False, 'help': 'Disable RFID interface'},
            {'name': '--validate-atm', 'action': 'store_true', 'default': False, 'help': 'Also validate readiness for ATM transport'},
        ],
        aliases=['create-card-test']
    )

    cli.register_command(
        name='card-read',
        func=card_read,
        description='Read card metadata from file or live reader',
        args=[
            {'name': '--file', 'type': str, 'help': 'Card JSON file path'},
            {'name': '--live', 'action': 'store_true', 'help': 'Read directly from connected PC/SC reader'},
            {'name': '--reader', 'type': str, 'help': 'Optional reader name filter for live mode'},
            {'name': '--aid', 'type': str, 'help': 'Optional hex AID for live SELECT'},
            {'name': '--include-sensitive', 'action': 'store_true', 'help': 'Include PAN/PIN/CVV fields unmasked'},
            {'name': '--no-decode-logs', 'action': 'store_true', 'help': 'Skip decoding machine-sealed log blobs'},
        ],
        aliases=['read-card']
    )

    cli.register_command(
        name='card-read-full',
        func=card_read_full,
        description='Attempt full card read from file or live reader',
        args=[
            {'name': '--file', 'type': str, 'help': 'Card JSON file path'},
            {'name': '--live', 'action': 'store_true', 'help': 'Read directly from connected PC/SC reader'},
            {'name': '--reader', 'type': str, 'help': 'Optional reader name filter for live mode'},
            {'name': '--aid', 'type': str, 'help': 'Optional hex AID for live SELECT'},
            {'name': '--max-sfi', 'type': int, 'default': 10, 'help': 'Maximum SFI to probe in live mode'},
            {'name': '--max-records', 'type': int, 'default': 10, 'help': 'Maximum records per SFI in live mode'},
            {'name': '--include-sensitive', 'action': 'store_true', 'help': 'Include PAN/PIN/CVV fields unmasked'},
            {'name': '--no-decode-logs', 'action': 'store_true', 'help': 'Skip decoding machine-sealed log blobs'},
        ],
        aliases=['read-card-full']
    )

    cli.register_command(
        name='card-history',
        func=card_history,
        description='Read card transaction history from sealed and journal logs',
        args=[
            {'name': '--file', 'type': str, 'help': 'Card JSON file path'},
            {'name': '--limit', 'type': int, 'default': 50, 'help': 'Maximum history records to return (0 for all)'},
            {'name': '--ascending', 'action': 'store_true', 'help': 'Sort oldest to newest (default newest first)'},
            {'name': '--include-sensitive', 'action': 'store_true', 'help': 'Include PAN/PIN/CVV fields unmasked'},
            {'name': '--no-decode-logs', 'action': 'store_true', 'help': 'Skip decoding machine-sealed log blobs'},
        ],
        aliases=['card-transactions']
    )
    
    # Card list command
    cli.register_command(
        name='card-list',
        func=card_list,
        description='List available card files',
        args=[
            {'name': '--directory', 'type': str, 'help': 'Directory to search'},
            {'name': '--pattern', 'type': str, 'help': 'File pattern to match'},
        ],
        aliases=['list-cards']
    )
    
    # Card validate command
    cli.register_command(
        name='card-validate',
        func=card_validate,
        description='Validate card data integrity',
        args=[
            {'name': 'file', 'help': 'Card file to validate'},
        ],
        aliases=['validate-card']
    )
    
    # Card clone command
    cli.register_command(
        name='card-clone',
        func=card_clone,
        description='Clone an existing card with modifications',
        args=[
            {'name': 'source', 'help': 'Source card file'},
            {'name': '--new-pan', 'type': str, 'help': 'New PAN for cloned card'},
            {'name': '--generate-new-pan', 'action': 'store_true', 'help': 'Generate new PAN'},
            {'name': '--new-expiry', 'type': str, 'help': 'New expiry date'},
            {'name': '--new-name', 'type': str, 'help': 'New cardholder name'},
            {'name': '--output', 'type': str, 'help': 'Output file path'},
        ],
        aliases=['clone-card']
    )
