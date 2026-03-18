"""Wallet and NFC/RFID provisioning commands for the modern CLI."""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.pipeline_providers import (
    EmulatorMobileWalletIntegrator,
    EmulatorPOSTerminalGateway,
    EmulatorTokenizationProvider,
)
from core.native_wireless_support import (
    build_wireless_support_matrix,
    select_wireless_backend,
)
from core.synthetic_identity import generate_identity
from greenwire_modern import CommandResult, GreenwireCLI


SUPPORTED_WALLETS = ["google", "apple", "samsung", "generic_nfc", "transit_rfid"]
PAYMENT_CARD_TYPES = ["visa", "mastercard", "amex", "discover"]
NFC_CARD_TYPES = PAYMENT_CARD_TYPES + ["mifare", "ntag"]


def _default_artifacts(card_type: str, pan: str | None = None) -> Dict[str, str]:
    if card_type in PAYMENT_CARD_TYPES:
        identity = generate_identity(card_type)
        resolved_pan = pan or identity["pan"]
        return {
            "pan": resolved_pan,
            "scheme": card_type,
            "track2": f"{resolved_pan}=31122010000000000000",
            "cardholder_name": identity["cardholder_name"],
            "issuer": identity["issuer_name"],
        }

    uid = "04112233445566" if card_type == "mifare" else "04A1B2C3D4"
    return {
        "pan": pan or "0000000000000000",
        "scheme": card_type,
        "track2": "",
        "uid": uid,
        "issuer": "GREENWIRE LAB",
        "cardholder_name": "LAB NFC PROFILE",
    }


def _device_metadata(args: argparse.Namespace) -> Dict[str, object]:
    return {
        "cdcvm": {"type": args.cdcvm, "status": "verified"},
        "google": {"device_account_id": args.device_account_id or "pixel-emulator"},
        "apple": {
            "device_account_number": args.device_account_number or "ADP-EMU-0001",
            "secure_element_id": args.secure_element_id or "SE-EMU",
        },
        "samsung": {
            "device_account_id": args.device_account_id or "galaxy-emulator",
            "secure_element_id": args.secure_element_id or "SE-SAM-EMU",
            "wallet_profile": "mst_nfc",
        },
        "generic_nfc": {
            "uid": args.uid or "04A1B2C3D4",
            "tech": "ISO14443-4" if args.card_type in PAYMENT_CARD_TYPES else "NDEF",
            "ndef_profile": "payment-card" if args.card_type in PAYMENT_CARD_TYPES else "tag-emulation",
        },
        "transit_rfid": {
            "uid": args.uid or "04112233445566",
            "transit_agency": args.transit_agency or "Metro Transit Lab",
            "reader_profile": "iso14443a-gate",
        },
    }


def wallet_provision(args: argparse.Namespace) -> CommandResult:
    """Provision wallet or NFC/RFID targets using emulator providers."""

    artifacts = _default_artifacts(args.card_type, pan=args.pan)
    tokenizer = EmulatorTokenizationProvider()
    integrator = EmulatorMobileWalletIntegrator()
    support_matrix = build_wireless_support_matrix()
    selected_transport = select_wireless_backend(
        requested_transport=args.transport,
        wallets=args.wallets,
        support_matrix=support_matrix,
    )

    token_result = tokenizer.generate_tokens(artifacts=artifacts, scheme=artifacts["scheme"])
    metadata = _device_metadata(args)

    results = []
    for wallet in args.wallets:
        if wallet == "google":
            result = integrator.provision_google_wallet(artifacts=artifacts, device_metadata=metadata["google"])
        elif wallet == "apple":
            result = integrator.provision_apple_wallet(artifacts=artifacts, device_metadata=metadata["apple"])
        elif wallet == "samsung":
            result = integrator.provision_samsung_wallet(artifacts=artifacts, device_metadata=metadata["samsung"])
        elif wallet == "generic_nfc":
            result = integrator.provision_generic_nfc(artifacts=artifacts, device_metadata=metadata["generic_nfc"])
        elif wallet == "transit_rfid":
            result = integrator.provision_transit_rfid(artifacts=artifacts, device_metadata=metadata["transit_rfid"])
        else:  # pragma: no cover - CLI choices should prevent this
            continue
        results.append(
            {
                "wallet_type": result.wallet_type,
                "token_reference": result.token_reference,
                "status": result.status,
                "assurance_level": result.assurance_level,
                "metadata": result.metadata,
            }
        )

    pos_result = None
    if args.simulate_pos:
        pos = EmulatorPOSTerminalGateway()
        confirmation = pos.confirm_contactless_transaction(
            payload={
                "transaction_id": f"WLT-{int(time.time())}",
                "amount": args.amount,
                "currency": args.currency,
                "contactless_profile": "EMV" if args.card_type in PAYMENT_CARD_TYPES else "NFC",
                "cdcvm": metadata["cdcvm"],
                "assurance_level": "enhanced" if "apple" in args.wallets or "samsung" in args.wallets else "standard",
            }
        )
        pos_result = {
            "transaction_id": confirmation.transaction_id,
            "amount": confirmation.amount,
            "currency": confirmation.currency,
            "status": confirmation.status,
            "metadata": confirmation.metadata,
        }

    data = {
        "artifacts": {
            "scheme": artifacts["scheme"],
            "pan": artifacts["pan"],
            "issuer": artifacts["issuer"],
            "cardholder_name": artifacts["cardholder_name"],
            "uid": artifacts.get("uid"),
        },
        "token": {
            "identifier": token_result.identifier,
            "scheme": token_result.scheme,
            "expires_at": token_result.expires_at,
            "metadata": token_result.metadata,
        },
        "wireless_support": support_matrix,
        "selected_transport": selected_transport,
        "wallet_results": results,
        "contactless_result": pos_result,
    }
    return CommandResult(True, "Wallet provisioning completed", data=data)


def register_wallet_commands(cli: GreenwireCLI):
    """Register wallet and NFC/RFID provisioning commands."""

    cli.register_command(
        name="wallet-provision",
        func=wallet_provision,
        description="Provision mobile wallet and NFC/RFID emulator targets",
        args=[
            {"name": "--wallets", "nargs": "+", "choices": SUPPORTED_WALLETS, "default": ["google", "apple", "samsung"]},
            {"name": "--card-type", "choices": NFC_CARD_TYPES, "default": "visa"},
            {"name": "--transport", "choices": ["auto", "android", "ios", "acr", "pcsc", "generic"], "default": "auto"},
            {"name": "--pan", "type": str, "help": "Optional PAN for payment-card wallets"},
            {"name": "--amount", "type": float, "default": 12.5, "help": "Optional contactless validation amount"},
            {"name": "--currency", "type": str, "default": "USD", "help": "Validation currency"},
            {"name": "--cdcvm", "choices": ["pin", "biometric", "device"], "default": "biometric"},
            {"name": "--device-account-id", "type": str, "help": "Device account identifier for token wallets"},
            {"name": "--device-account-number", "type": str, "help": "Device account number for Apple Wallet"},
            {"name": "--secure-element-id", "type": str, "help": "Secure element identifier"},
            {"name": "--uid", "type": str, "help": "NFC/RFID UID override"},
            {"name": "--transit-agency", "type": str, "help": "Transit agency label for RFID flows"},
            {"name": "--simulate-pos", "action": "store_true", "help": "Run a contactless POS confirmation"},
        ],
        aliases=["wallet"],
    )
