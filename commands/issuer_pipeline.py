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
from core.pipeline_services import (
    IssuerService,
    MerchantService,
    PaymentGatewayService,
    PersonalizationService,
    PipelineHSMService,
    TransactionService,
)
from core.service_orchestrator import ServiceOrchestrator


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
        parser.add_argument("--cardholder", default="TEST CARDHOLDER", help="Cardholder name")
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

        try:
            parsed = parser.parse_args(args)
        except SystemExit:
            return {"success": True, "message": "Displayed help for card-issue command."}

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
                "cardholder": parsed.cardholder,
                "amount": parsed.amount,
                "mode": parsed.mode,
                "pan_sequence": parsed.pan_sequence,
                "atc": parsed.atc,
                "network": parsed.network,
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
            },
        }


def get_command() -> IssuerPipelineCommand:
    return IssuerPipelineCommand()
