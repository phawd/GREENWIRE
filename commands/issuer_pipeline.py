"""Modern CLI command for the issuer pipeline demo."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict

from core.pipeline_events import (
    ISSUE_CARD_REQUEST,
    PAYMENT_GATEWAY_COMPLETED,
    TRANSACTION_COMPLETED,
)
from core.pipeline_providers import build_providers
from core.configuration_manager import get_configuration_manager
from core.pipeline_services import (
    IssuerService,
    MerchantService,
    PaymentGatewayService,
    PersonalizationService,
    PipelineHSMService,
    TransactionService,
)
from core.service_orchestrator import ServiceOrchestrator
from core.issuance_validation import (
    is_test_function_invocation,
    validate_card_identity,
    validate_issuance_crypto_readiness,
    validate_key_profile,
    validate_merchant_required_fields,
    validate_pin_value,
)
from core.synthetic_identity import generate_cardholder_name


class IssuerPipelineCommand:
    """Execute the multithreaded issuer pipeline end-to-end."""

    def get_name(self) -> str:
        return "card-issue"

    def get_description(self) -> str:
        return "Issue and personalize a payment card via the multithreaded pipeline"

    def execute(self, args: list) -> Dict[str, object]:
        parser = argparse.ArgumentParser(
            prog="greenwire card-issue",
            description=self.get_description(),
        )
        parser.add_argument("--pan", required=True, help="Primary account number (PAN)")
        parser.add_argument("--cardholder", help="Cardholder name")
        parser.add_argument("--pin", help="Card PIN override")
        parser.add_argument("--amount", type=float, default=1.00, help="Initial transaction amount")
        parser.add_argument("--mode", choices=["emulator"], default="emulator", help="Pipeline mode")
        parser.add_argument("--pan-sequence", default="00", help="PAN sequence number")
        parser.add_argument("--atc", type=int, default=1, help="Application transaction counter")
        parser.add_argument(
            "--network",
            choices=["ach", "fedwire", "sepa"],
            default="ach",
            help="Payment network to route the settlement",
        )
        parser.add_argument("--timeout", type=float, default=15.0, help="Operation timeout in seconds")
        parser.add_argument("--key-profile", choices=["production", "test"], default="production", help="Issuance key profile")
        parser.add_argument("--merchant-id", default="MERCHANT-0001", help="Merchant identifier")
        parser.add_argument("--terminal-id", default="POS-EMU-01", help="Terminal identifier")
        parser.add_argument("--mcc", default="5411", help="Merchant category code")
        parser.add_argument("--acquirer-id", default="00000012345", help="Acquirer identifier")
        parser.add_argument("--country-code", default="840", help="Numeric country code")
        parser.add_argument("--currency", default="USD", help="Transaction currency code")
        parser.add_argument("--test-function", action="store_true", help="Mark the issuance as a test workflow while still using production-style data")
        parser.add_argument("--nfc", action="store_true", default=False, help="Enable NFC interface for issued card")
        parser.add_argument("--no-nfc", action="store_true", default=False, help="Disable NFC interface for issued card")
        parser.add_argument("--rfid", action="store_true", default=False, help="Enable RFID interface for issued card")
        parser.add_argument("--no-rfid", action="store_true", default=False, help="Disable RFID interface for issued card")
        parser.add_argument("--validate-atm", action="store_true", default=False, help="Also validate readiness for ATM transport")

        try:
            parsed = parser.parse_args(args)
        except SystemExit:
            return {"success": True, "message": "Displayed help for card-issue command."}

        config_manager = get_configuration_manager()
        config = config_manager.data()
        pin = _resolve_card_pin(
            explicit_pin=parsed.pin,
            config_default=config_manager.default_card_pin(),
        )
        nfc_enabled = _resolve_interface_flag(
            enabled_flag=parsed.nfc,
            disabled_flag=parsed.no_nfc,
            config_default=bool(config.get("cards", {}).get("default_nfc_enabled", True)),
        )
        rfid_enabled = _resolve_interface_flag(
            enabled_flag=parsed.rfid,
            disabled_flag=parsed.no_rfid,
            config_default=bool(config.get("cards", {}).get("default_rfid_enabled", True)),
        )
        is_test_function = is_test_function_invocation("card-issue", parsed.test_function)
        merchant_context = {
            "merchant_id": parsed.merchant_id,
            "terminal_id": parsed.terminal_id,
            "mcc": parsed.mcc,
            "acquirer_id": parsed.acquirer_id,
            "country_code": parsed.country_code,
            "currency": parsed.currency.upper(),
        }
        cardholder = parsed.cardholder or generate_cardholder_name()
        key_errors = validate_key_profile(
            key_profile=parsed.key_profile,
            is_test_function=is_test_function,
        )
        merchant_errors = validate_merchant_required_fields(merchant_context)
        pin_errors = validate_pin_value(pin)
        identity_errors = validate_card_identity(
            pan=parsed.pan,
            expiry="12/99",
            cvv="999",
            cardholder_name=cardholder,
            issuer_name="Issuer Pipeline",
        )
        crypto_errors = validate_issuance_crypto_readiness(
            pan=parsed.pan,
            atc=parsed.atc,
            include_atm=parsed.validate_atm,
        )
        validation_errors = key_errors + merchant_errors + pin_errors + [e for e in identity_errors if not e.startswith("Expiry")]
        validation_errors.extend(crypto_errors)
        if validation_errors:
            return {
                "success": False,
                "message": "Issuer pipeline validation failed",
                "data": {"errors": validation_errors},
            }

        providers = build_providers(parsed.mode)
        artifact_root = Path("artifacts")
        artifact_root.mkdir(exist_ok=True)
        orchestrator = ServiceOrchestrator(
            artifact_dir=artifact_root,
            database_path=artifact_root / "orchestrator.db",
            config={"mode": parsed.mode},
            providers=providers,
        )
        orchestrator.switch_mode(parsed.mode)

        services = [
            PipelineHSMService,
            IssuerService,
            PersonalizationService,
            MerchantService,
            TransactionService,
            PaymentGatewayService,
        ]

        for service_cls in services:
            orchestrator.register(service_cls)

        orchestrator.start_all()
        try:
            payload = {
                "pan": parsed.pan,
                "cardholder": cardholder,
                "pin": pin,
                "amount": parsed.amount,
                "mode": parsed.mode,
                "pan_sequence": parsed.pan_sequence,
                "atc": parsed.atc,
                "network": parsed.network,
                "key_profile": parsed.key_profile,
                "test_context": bool(is_test_function),
                "interface_profile": {
                    "nfc_enabled": nfc_enabled,
                    "rfid_enabled": rfid_enabled,
                },
                "merchant_context": merchant_context,
            }
            orchestrator.dispatch(ISSUE_CARD_REQUEST, payload, source="cli")
            completion = orchestrator.wait_for_completion(TRANSACTION_COMPLETED, timeout=parsed.timeout)
            gateway_message = orchestrator.wait_for_completion(
                PAYMENT_GATEWAY_COMPLETED,
                timeout=parsed.timeout,
            )
            status = orchestrator.get_status()
        finally:
            orchestrator.stop_all()

        if completion is None:
            return {
                "success": False,
                "message": "Pipeline run timed out",
                "data": {"status": status},
            }

        result_payload = completion.payload
        if not isinstance(result_payload, dict):
            result_payload = {"raw": result_payload}

        gateway_payload = None
        if gateway_message is not None:
            gateway_payload = gateway_message.payload
            if not isinstance(gateway_payload, dict):
                gateway_payload = {"raw": gateway_payload}

        return {
            "success": True,
            "message": "Card issued and transaction completed",
            "data": {
                "status": status,
                "result": result_payload,
                "payment_gateway": gateway_payload,
                "pin": pin,
                "interface_profile": {
                    "nfc_enabled": nfc_enabled,
                    "rfid_enabled": rfid_enabled,
                },
            },
        }


def get_command() -> IssuerPipelineCommand:
    return IssuerPipelineCommand()


def _resolve_interface_flag(*, enabled_flag: bool, disabled_flag: bool, config_default: bool) -> bool:
    if enabled_flag:
        return True
    if disabled_flag:
        return False
    return bool(config_default)


def _resolve_card_pin(*, explicit_pin: str | None, config_default: str) -> str:
    if explicit_pin is not None and str(explicit_pin).strip():
        return str(explicit_pin).strip()
    return str(config_default or "6666").strip() or "6666"
