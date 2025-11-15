"""Multithreaded pipeline services for GREENWIRE v5.

Each service is a specialised worker that extends :class:`BaseService` and
communicates via the message bus defined in :mod:`core.pipeline_events`.
The implementations favour determinism and emulator-friendly behaviour so
that the entire flow can execute without physical hardware while leaving
obvious extension points for PKCS#11, PC/SC, or ISO 8583 backends.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Optional

from core.base_service import BaseService, ServiceMessage
from core.pipeline_events import (
    CARD_PERSONALIZED,
    HSM_ARQC_GENERATED,
    HSM_DERIVE_SESSION_KEYS,
    HSM_GENERATE_ARQC,
    ISSUE_CARD_REQUEST,
    ISSUER_CARD_APPROVED,
    MERCHANT_TXN_INITIATED,
    PAYMENT_GATEWAY_COMPLETED,
    PAYMENT_GATEWAY_FAILED,
    PERSONALIZATION_COMPLETED,
    PERSONALIZATION_REQUEST,
    PIPELINE_STATUS_REQUEST,
    PIPELINE_STATUS_RESPONSE,
    SESSION_KEYS_DERIVED,
    SETTLEMENT_COMPLETED,
    SETTLEMENT_FAILED,
    SETTLEMENT_SCHEDULED,
    SALES_LEDGER_UPDATED,
    TOKENIZATION_COMPLETED,
    ATM_CARD_PREPARED,
    ATM_CASH_DISPENSED,
    POS_PURCHASE_COMPLETED,
    PCSC_CARD_PROCESSED,
    MOBILE_WALLET_PROVISIONED,
    TRANSACTION_COMPLETED,
)
from core.pipeline_providers import (
    ATMDeviceInterface,
    CardPersonalizer,
    HSMBackend,
    MobileWalletIntegrator,
    MerchantTerminal,
    PCSCReaderGateway,
    PaymentNetworkGateway,
    PaymentNetworkResult,
    POSTerminalGateway,
    RevenueLedgerConnector,
    RevenueLedgerRecord,
    SalesLedger,
    SalesRecord,
    SessionKeys,
    SettlementEngine,
    SettlementRecord,
    TokenizationProvider,
    TokenizationResult,
)


@dataclass
class IssuerRequestState:
    request_id: str
    pan: str
    pan_sequence: str
    amount: float
    cardholder: str
    mode: str
    atc: int
    network: str = "ach"
    created_at: float = field(default_factory=lambda: time.time())
    session_keys: Optional[SessionKeys] = None


@dataclass
class TransactionState:
    request_id: str
    transaction_id: str
    amount: float
    pan: str
    atc: int
    terminal_data: Dict[str, str]
    network: str
    created_at: float = field(default_factory=lambda: time.time())


class PipelineHSMService(BaseService):
    name = "hsm_pipeline"
    subscriptions = (HSM_DERIVE_SESSION_KEYS, HSM_GENERATE_ARQC, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        providers = self.context.providers
        backend = providers.get("hsm") if providers else None
        if not isinstance(backend, HSMBackend):
            raise RuntimeError("HSM provider not configured or invalid")
        self._backend: HSMBackend = backend
        self._logger = self.context.logger

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == HSM_DERIVE_SESSION_KEYS:
            self._handle_derive_session_keys(message)
        elif message.topic == HSM_GENERATE_ARQC:
            self._handle_generate_arqc(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {
                    "service": self.name,
                    "status": self.status.value,
                    "mode": self.context.orchestrator.mode,
                },
            )

    def _handle_derive_session_keys(self, message: ServiceMessage) -> None:
        payload = message.payload
        request_id = payload.get("request_id")
        pan = payload.get("pan")
        pan_seq = payload.get("pan_sequence", "00")
        atc = int(payload.get("atc", 1))
        if not request_id or not pan:
            self._logger.error("Invalid derive_session_keys payload: %s", payload)
            return

        keys = self._backend.derive_session_keys(pan=pan, pan_sequence=pan_seq, atc=atc)
        self.publish(
            SESSION_KEYS_DERIVED,
            {
                "request_id": request_id,
                "pan": pan,
                "session_keys": {
                    "mac_key": keys.mac_key,
                    "enc_key": keys.enc_key,
                    "dek_key": keys.dek_key,
                    "metadata": keys.metadata,
                },
                "atc": atc,
                "network": payload.get("network", "ach"),
            },
        )

    def _handle_generate_arqc(self, message: ServiceMessage) -> None:
        payload = message.payload
        request_id = payload.get("request_id")
        pan = payload.get("pan")
        atc = int(payload.get("atc", 1))
        token = payload.get("token")
        if not request_id or not pan or token is None:
            self._logger.error("Invalid generate_arqc payload: %s", payload)
            return

        cryptogram = self._backend.generate_arqc(pan=pan, atc=atc, payload=bytes.fromhex(token))
        self.publish(
            HSM_ARQC_GENERATED,
            {
                "request_id": request_id,
                "pan": pan,
                "arqc": cryptogram,
                "atc": atc,
            },
        )


class IssuerService(BaseService):
    name = "issuer_service"
    subscriptions = (ISSUE_CARD_REQUEST, SESSION_KEYS_DERIVED, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        self._requests: Dict[str, IssuerRequestState] = {}
        self._logger = self.context.logger
        self._default_mode = self.context.orchestrator.mode

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == ISSUE_CARD_REQUEST:
            self._handle_issue_request(message)
        elif message.topic == SESSION_KEYS_DERIVED:
            self._handle_session_keys(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {
                    "service": self.name,
                    "status": self.status.value,
                    "requests": len(self._requests),
                },
            )

    def _handle_issue_request(self, message: ServiceMessage) -> None:
        payload = message.payload
        pan = payload.get("pan")
        if not pan:
            self._logger.error("IssuerService received request without PAN")
            return

        request_id = payload.get("request_id") or uuid.uuid4().hex
        pan_sequence = payload.get("pan_sequence", "00")
        amount = float(payload.get("amount", 1.00))
        cardholder = payload.get("cardholder", "TEST CARDHOLDER")
        mode = payload.get("mode", self._default_mode)
        atc = int(payload.get("atc", 1))
        network = (payload.get("network") or "ach").lower()

        state = IssuerRequestState(
            request_id=request_id,
            pan=pan,
            pan_sequence=pan_sequence,
            amount=amount,
            cardholder=cardholder,
            mode=mode,
            atc=atc,
            network=network,
        )
        self._requests[request_id] = state

        self.publish(
            ISSUER_CARD_APPROVED,
            {
                "request_id": request_id,
                "pan": pan,
                "status": "approved",
                "mode": mode,
                "network": network,
            },
        )

        self.publish(
            HSM_DERIVE_SESSION_KEYS,
            {
                "request_id": request_id,
                "pan": pan,
                "pan_sequence": pan_sequence,
                "atc": atc,
                "network": network,
            },
        )

    def _handle_session_keys(self, message: ServiceMessage) -> None:
        payload = message.payload
        request_id = payload.get("request_id")
        if not request_id or request_id not in self._requests:
            self._logger.warning("Session keys for unknown request %s", request_id)
            return

        session_data = payload.get("session_keys", {})
        try:
            keys = SessionKeys(
                mac_key=session_data.get("mac_key", ""),
                enc_key=session_data.get("enc_key", ""),
                dek_key=session_data.get("dek_key", ""),
                metadata=session_data.get("metadata", {}),
            )
        except TypeError:
            self._logger.exception("Invalid session key payload: %s", session_data)
            return

        state = self._requests[request_id]
        state.session_keys = keys

        profile = {
            "request_id": request_id,
            "pan": state.pan,
            "cardholder": state.cardholder,
            "aid": payload.get("aid", "A0000000031010"),
            "atc": state.atc,
            "mode": state.mode,
            "network": state.network,
            "session_keys": {
                "mac_key": keys.mac_key,
                "enc_key": keys.enc_key,
                "dek_key": keys.dek_key,
            },
            "track2": f"{state.pan}D2512201{state.atc:04d}00000000",
        }

        self.publish(
            PERSONALIZATION_REQUEST,
            {
                "request_id": request_id,
                "profile": profile,
                "amount": state.amount,
                "network": state.network,
            },
        )


class PersonalizationService(BaseService):
    name = "personalization_service"
    subscriptions = (PERSONALIZATION_REQUEST, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        providers = self.context.providers
        personalizer = providers.get("personalizer") if providers else None
        if not isinstance(personalizer, CardPersonalizer):
            raise RuntimeError("Personalizer provider not configured or invalid")
        self._personalizer: CardPersonalizer = personalizer
        self._logger = self.context.logger

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == PERSONALIZATION_REQUEST:
            self._handle_personalization(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {"service": self.name, "status": self.status.value},
            )

    def _handle_personalization(self, message: ServiceMessage) -> None:
        payload = message.payload
        request_id = payload.get("request_id")
        profile = payload.get("profile")
        if not request_id or not profile:
            self._logger.error("Personalization payload missing data: %s", payload)
            return

        artifacts = self._personalizer.personalize(
            request_id=request_id,
            profile=profile,
            output_dir=Path(self.context.artifact_dir) / "cards",
        )
        record = {
            "request_id": request_id,
            "profile": profile,
            "artifacts": artifacts,
            "network": payload.get("network", profile.get("network", "ach")),
        }
        (Path(self.context.artifact_dir) / "cards").mkdir(parents=True, exist_ok=True)
        summary_path = Path(self.context.artifact_dir) / "cards" / f"{request_id}_summary.json"
        summary_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

        response = {
            "request_id": request_id,
            "artifacts": artifacts,
            "profile": profile,
            "amount": payload.get("amount", 0.0),
            "network": payload.get("network", profile.get("network", "ach")),
        }
        self.publish(CARD_PERSONALIZED, response)
        self.publish(PERSONALIZATION_COMPLETED, response)


class MerchantService(BaseService):
    name = "merchant_service"
    subscriptions = (CARD_PERSONALIZED, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        providers = self.context.providers
        merchant = providers.get("merchant") if providers else None
        if not isinstance(merchant, MerchantTerminal):
            raise RuntimeError("Merchant provider not configured or invalid")
        self._merchant: MerchantTerminal = merchant
        self._logger = self.context.logger

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == CARD_PERSONALIZED:
            self._handle_card_personalized(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {"service": self.name, "status": self.status.value},
            )

    def _handle_card_personalized(self, message: ServiceMessage) -> None:
        payload = message.payload
        request_id = payload.get("request_id")
        artifacts = payload.get("artifacts") or {}
        if not request_id:
            self._logger.error("Merchant service missing request_id: %s", payload)
            return

        provision = self._merchant.provision_card(card_artifacts=artifacts)
        transaction = self._merchant.initiate_transaction(
            card_artifacts=artifacts,
            amount=float(payload.get("amount", 1.0)),
        )

        response = {
            "request_id": request_id,
            "artifacts": artifacts,
            "provision": provision,
            "transaction": transaction,
            "network": payload.get("network", "ach"),
        }
        self.publish(MERCHANT_TXN_INITIATED, response)


class TokenizationService(BaseService):
    name = "tokenization_service"
    subscriptions = (CARD_PERSONALIZED, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        providers = self.context.providers
        tokenizer = providers.get("tokenizer") if providers else None
        if not isinstance(tokenizer, TokenizationProvider):
            raise RuntimeError("Tokenization provider not configured or invalid")
        self._tokenizer: TokenizationProvider = tokenizer
        self._logger = self.context.logger
        self._tokens: Dict[str, TokenizationResult] = {}

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == CARD_PERSONALIZED:
            self._handle_card_personalized(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {
                    "service": self.name,
                    "status": self.status.value,
                    "tokens": len(self._tokens),
                },
            )

    def _handle_card_personalized(self, message: ServiceMessage) -> None:
        payload = message.payload or {}
        request_id = payload.get("request_id")
        artifacts = payload.get("artifacts") or {}
        if not request_id or not artifacts:
            self._logger.error("Tokenization payload missing data: %s", payload)
            return

        scheme = (payload.get("network") or artifacts.get("scheme") or "ach").lower()
        try:
            token_result = self._tokenizer.generate_tokens(artifacts=artifacts, scheme=scheme)
        except Exception as exc:  # pragma: no cover - provider errors depend on integrations
            self._logger.exception("Tokenization failed for %s", request_id)
            return

        self._tokens[request_id] = token_result
        event_payload = {
            "request_id": request_id,
            "artifacts": artifacts,
            "token": {
                "identifier": token_result.identifier,
                "scheme": token_result.scheme,
                "expires_at": token_result.expires_at,
                "metadata": token_result.metadata,
            },
            "network": scheme,
            "wallet_targets": payload.get("wallet_targets") or ["google", "apple"],
        }
        self.publish(TOKENIZATION_COMPLETED, event_payload)


class MobileWalletService(BaseService):
    name = "mobile_wallet_service"
    subscriptions = (TOKENIZATION_COMPLETED, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        providers = self.context.providers
        integrator = providers.get("wallet") if providers else None
        if not isinstance(integrator, MobileWalletIntegrator):
            raise RuntimeError("Mobile wallet integrator not configured or invalid")
        self._integrator: MobileWalletIntegrator = integrator
        self._logger = self.context.logger
        self._wallet_results: Dict[str, list[dict]] = {}

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == TOKENIZATION_COMPLETED:
            self._handle_tokenized_card(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {
                    "service": self.name,
                    "status": self.status.value,
                    "wallets": len(self._wallet_results),
                },
            )

    def _handle_tokenized_card(self, message: ServiceMessage) -> None:
        payload = message.payload or {}
        request_id = payload.get("request_id")
        artifacts = payload.get("artifacts") or {}
        token_data = payload.get("token") or {}
        if not request_id or not artifacts or not token_data:
            self._logger.error("Wallet provisioning payload missing data: %s", payload)
            return

        device_metadata = payload.get("device_metadata") or {}
        targets = payload.get("wallet_targets") or ["google", "apple"]
        results = []
        for target in targets:
            try:
                if target.lower() == "google":
                    meta = self._metadata_for_target(device_metadata, "google")
                    wallet_result = self._integrator.provision_google_wallet(
                        artifacts=artifacts,
                        device_metadata=meta,
                    )
                elif target.lower() == "apple":
                    meta = self._metadata_for_target(device_metadata, "apple")
                    wallet_result = self._integrator.provision_apple_wallet(
                        artifacts=artifacts,
                        device_metadata=meta,
                    )
                else:
                    self._logger.warning("Unsupported wallet target '%s'", target)
                    continue
            except Exception:  # pragma: no cover - provider specific failures
                self._logger.exception("Wallet provisioning failed for %s", request_id)
                continue

            results.append(asdict(wallet_result))

        if not results:
            self._logger.warning("No wallet provisioning results produced for %s", request_id)
            return

        self._wallet_results[request_id] = results
        event_payload = {
            "request_id": request_id,
            "token": token_data,
            "wallet_results": results,
            "network": payload.get("network"),
        }
        self.publish(MOBILE_WALLET_PROVISIONED, event_payload)

    def _metadata_for_target(self, metadata: Dict[str, object], target: str) -> Dict[str, object]:
        base = metadata.get(target) if isinstance(metadata.get(target), dict) else {}
        defaults = {
            "assurance_level": "L2" if target == "google" else "TAV2",
            "cdcvm": metadata.get("cdcvm", {"type": "pin", "status": "verified"}),
        }
        merged = {**defaults, **(base or {})}
        if target == "google":
            merged.setdefault("device_account_id", "pixel-emulator")
        else:
            merged.setdefault("device_account_number", "ADP-EMU-0001")
            merged.setdefault("secure_element_id", "SE-EMU")
        return merged


class PCSCService(BaseService):
    name = "pcsc_service"
    subscriptions = (CARD_PERSONALIZED, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        providers = self.context.providers
        pcsc = providers.get("pcsc") if providers else None
        if not isinstance(pcsc, PCSCReaderGateway):
            raise RuntimeError("PC/SC reader gateway not configured or invalid")
        self._pcsc: PCSCReaderGateway = pcsc
        self._logger = self.context.logger
        self._processed: Dict[str, Dict[str, object]] = {}

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == CARD_PERSONALIZED:
            self._handle_card_personalized(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {
                    "service": self.name,
                    "status": self.status.value,
                    "processed": len(self._processed),
                },
            )

    def _handle_card_personalized(self, message: ServiceMessage) -> None:
        payload = message.payload or {}
        request_id = payload.get("request_id")
        artifacts = payload.get("artifacts") or {}
        if not request_id or not artifacts:
            self._logger.error("PC/SC service missing artifacts: %s", payload)
            return

        reader_hint = payload.get("reader_hint") or artifacts.get("reader_hint")
        try:
            pcsc_result = self._pcsc.process_card(profile=artifacts, reader_hint=reader_hint)
        except Exception:  # pragma: no cover - hardware failures are environment specific
            self._logger.exception("PC/SC processing failed for %s", request_id)
            return

        record = {
            "request_id": request_id,
            "artifacts": artifacts,
            "pcsc": pcsc_result,
        }
        self._processed[request_id] = record
        self.publish(PCSC_CARD_PROCESSED, record)


class TransactionService(BaseService):
    name = "transaction_service"
    subscriptions = (MERCHANT_TXN_INITIATED, HSM_ARQC_GENERATED, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        self._transactions: Dict[str, TransactionState] = {}
        self._logger = self.context.logger

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == MERCHANT_TXN_INITIATED:
            self._handle_txn_initiated(message)
        elif message.topic == HSM_ARQC_GENERATED:
            self._handle_arqc(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {
                    "service": self.name,
                    "status": self.status.value,
                    "transactions": len(self._transactions),
                },
            )

    def _handle_txn_initiated(self, message: ServiceMessage) -> None:
        payload = message.payload
        request_id = payload.get("request_id")
        transaction = payload.get("transaction") or {}
        if not request_id or "transaction_id" not in transaction:
            self._logger.error("Transaction initiated payload invalid: %s", payload)
            return

        txn_id = transaction["transaction_id"]
        atc = int(transaction.get("atc", 1))
        pan = payload.get("artifacts", {}).get("pan") or transaction.get("pan", "0000000000000000")
        network = (payload.get("network") or transaction.get("network") or "ach").lower()

        state = TransactionState(
            request_id=request_id,
            transaction_id=txn_id,
            amount=float(transaction.get("amount", 1.0)),
            pan=pan,
            atc=atc,
            terminal_data=transaction,
            network=network,
        )
        self._transactions[request_id] = state

        token = transaction.get("track2", pan).encode().hex()
        self.publish(
            HSM_GENERATE_ARQC,
            {
                "request_id": request_id,
                "pan": pan,
                "atc": atc,
                "token": token,
                "network": network,
            },
        )

    def _handle_arqc(self, message: ServiceMessage) -> None:
        payload = message.payload
        request_id = payload.get("request_id")
        arqc = payload.get("arqc")
        if not request_id or request_id not in self._transactions or not arqc:
            self._logger.error("ARQC payload invalid: %s", payload)
            return

        state = self._transactions.pop(request_id)
        result = {
            "request_id": request_id,
            "transaction_id": state.transaction_id,
            "amount": state.amount,
            "pan": state.pan,
            "arqc": arqc,
            "terminal": state.terminal_data,
            "network": state.network,
            "completed_at": time.time(),
        }
        self.publish(TRANSACTION_COMPLETED, result)


class PaymentGatewayService(BaseService):
    name = "payment_gateway_service"
    subscriptions = (TRANSACTION_COMPLETED, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        providers = self.context.providers
        gateway = providers.get("gateway") if providers else None
        if not isinstance(gateway, PaymentNetworkGateway):
            raise RuntimeError("Payment gateway provider not configured or invalid")
        self._gateway: PaymentNetworkGateway = gateway
        self._logger = self.context.logger
        self._settlements: Dict[str, PaymentNetworkResult] = {}

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == TRANSACTION_COMPLETED:
            self._handle_transaction_completed(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {
                    "service": self.name,
                    "status": self.status.value,
                    "settlements": len(self._settlements),
                },
            )

    def _handle_transaction_completed(self, message: ServiceMessage) -> None:
        payload = message.payload or {}
        request_id = payload.get("request_id")
        if not request_id:
            self._logger.error("Payment gateway received payload without request_id: %s", payload)
            return

        network = (payload.get("network") or "ach").lower()
        try:
            result = self._dispatch_to_network(network, payload)
        except Exception as exc:  # pragma: no cover - defensive path
            self._logger.exception("Payment gateway dispatch failed for %s", request_id)
            self.publish(
                PAYMENT_GATEWAY_FAILED,
                {
                    "request_id": request_id,
                    "network": network,
                    "error": str(exc),
                },
            )
            return

        self._settlements[request_id] = result
        result_payload = asdict(result)
        result_payload["network"] = network
        result_payload["request_id"] = request_id
        result_payload["transaction"] = payload

        if network == "ach":
            result_payload["nacha"] = self._gateway.build_nacha_batch(entries=[payload])
        elif network == "sepa":
            result_payload["sepa_xml"] = self._gateway.build_sepa_xml(transaction=payload)
        elif network == "fedwire":
            result_payload["iso_payload"] = self._gateway.build_iso20022_payload(
                message_type="pacs.008.001.08",
                transaction=payload,
            )

        schedule = self._gateway.schedule_settlement(
            network=network,
            window={
                "cutoff": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "timezone": "UTC",
            },
        )
        schedule["request_id"] = request_id
        self.publish(SETTLEMENT_SCHEDULED, schedule)

        self.publish(
            PAYMENT_GATEWAY_COMPLETED,
            result_payload,
        )

    def _dispatch_to_network(self, network: str, transaction: Dict[str, object]) -> PaymentNetworkResult:
        if network == "ach":
            return self._gateway.send_ach_payment(transaction=transaction)
        if network == "fedwire":
            return self._gateway.send_fedwire_payment(transaction=transaction)
        if network == "sepa":
            return self._gateway.send_sepa_payment(transaction=transaction)
        raise ValueError(f"Unsupported payment network '{network}'")


class SettlementService(BaseService):
    name = "settlement_service"
    subscriptions = (PAYMENT_GATEWAY_COMPLETED, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        providers = self.context.providers
        engine = providers.get("settlement") if providers else None
        if not isinstance(engine, SettlementEngine):
            raise RuntimeError("Settlement engine not configured or invalid")
        self._engine: SettlementEngine = engine
        self._logger = self.context.logger
        self._records: Dict[str, SettlementRecord] = {}

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == PAYMENT_GATEWAY_COMPLETED:
            self._handle_gateway_completed(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {
                    "service": self.name,
                    "status": self.status.value,
                    "settlements": len(self._records),
                },
            )

    def _handle_gateway_completed(self, message: ServiceMessage) -> None:
        payload = message.payload or {}
        request_id = payload.get("request_id")
        transaction = payload.get("transaction") or {}
        if not request_id or not transaction:
            self._logger.error("Settlement service missing transaction data: %s", payload)
            return

        payment_result = PaymentNetworkResult(
            network=payload.get("network", transaction.get("network", "ach")),
            reference=payload.get("reference", request_id),
            status=payload.get("status", "accepted"),
            metadata=payload.get("metadata", {}),
        )
        try:
            settlement_record = self._engine.process_settlement(
                transaction=transaction,
                payment_result=payment_result,
            )
        except Exception:  # pragma: no cover - backend integrations vary
            self._logger.exception("Settlement processing failed for %s", request_id)
            self.publish(
                SETTLEMENT_FAILED,
                {"request_id": request_id, "transaction": transaction},
            )
            return

        self._records[request_id] = settlement_record
        event_payload = asdict(settlement_record)
        event_payload["request_id"] = request_id
        event_payload["transaction"] = transaction
        self.publish(SETTLEMENT_COMPLETED, event_payload)


class RevenueLedgerService(BaseService):
    name = "revenue_ledger_service"
    subscriptions = (PAYMENT_GATEWAY_COMPLETED, SETTLEMENT_COMPLETED, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        providers = self.context.providers
        connector = providers.get("accounting") if providers else None
        if not isinstance(connector, RevenueLedgerConnector):
            raise RuntimeError("Revenue ledger connector not configured or invalid")
        self._connector: RevenueLedgerConnector = connector
        self._logger = self.context.logger
        self._entries: Dict[str, RevenueLedgerRecord] = {}

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == PAYMENT_GATEWAY_COMPLETED:
            self._record_authorization(message)
        elif message.topic == SETTLEMENT_COMPLETED:
            self._record_settlement(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {
                    "service": self.name,
                    "status": self.status.value,
                    "entries": len(self._entries),
                },
            )

    def _record_authorization(self, message: ServiceMessage) -> None:
        payload = message.payload or {}
        request_id = payload.get("request_id")
        transaction = payload.get("transaction") or {}
        if not request_id:
            self._logger.error("Authorization payload missing request_id: %s", payload)
            return

        entry = RevenueLedgerRecord(
            reference_id=request_id,
            channel=payload.get("network", transaction.get("network", "ach")),
            amount=float(transaction.get("amount", 0.0)),
            currency=transaction.get("currency", "USD"),
            metadata={
                "terminal": transaction.get("terminal"),
                "merchant_id": transaction.get("merchant_id"),
                "payment_reference": payload.get("reference"),
            },
        )
        try:
            self._connector.record_authorization(entry=entry)
        except Exception:
            self._logger.exception("Failed to record authorization for %s", request_id)
            return
        self._entries[request_id] = entry

    def _record_settlement(self, message: ServiceMessage) -> None:
        payload = message.payload or {}
        request_id = payload.get("request_id")
        if not request_id:
            self._logger.error("Settlement record missing request_id: %s", payload)
            return

        entry = RevenueLedgerRecord(
            reference_id=payload.get("settlement_id", request_id),
            channel=payload.get("network", "ach"),
            amount=float(payload.get("amount", 0.0)),
            currency=payload.get("currency", "USD"),
            metadata={
                "payment_reference": payload.get("reference"),
                "transaction_id": payload.get("transaction", {}).get("transaction_id"),
            },
        )
        try:
            self._connector.record_settlement(entry=entry)
        except Exception:
            self._logger.exception("Failed to record settlement for %s", request_id)
            return


class SalesLedgerService(BaseService):
    name = "sales_ledger_service"
    subscriptions = (SETTLEMENT_COMPLETED, PIPELINE_STATUS_REQUEST)

    def on_start(self) -> None:
        providers = self.context.providers
        sales = providers.get("sales") if providers else None
        if not isinstance(sales, SalesLedger):
            raise RuntimeError("Sales ledger provider not configured or invalid")
        self._sales: SalesLedger = sales
        self._logger = self.context.logger
        self._records: Dict[str, SalesRecord] = {}

    def handle_message(self, message: ServiceMessage) -> None:
        if message.topic == SETTLEMENT_COMPLETED:
            self._record_sale(message)
        elif message.topic == PIPELINE_STATUS_REQUEST:
            self.publish(
                PIPELINE_STATUS_RESPONSE,
                {
                    "service": self.name,
                    "status": self.status.value,
                    "sales": len(self._records),
                },
            )

    def _record_sale(self, message: ServiceMessage) -> None:
        payload = message.payload or {}
        request_id = payload.get("request_id")
        settlement_data = payload.copy()
        transaction = payload.get("transaction") or {}
        if not request_id or not transaction:
            self._logger.error("Sales ledger payload missing identifiers: %s", payload)
            return

        try:
            settlement_record = SettlementRecord(
                settlement_id=payload.get("settlement_id", request_id),
                network=payload.get("network", "ach"),
                reference=payload.get("reference", request_id),
                amount=float(payload.get("amount", 0.0)),
                currency=payload.get("currency", "USD"),
                status=payload.get("status", "settled"),
                processed_at=payload.get("processed_at", time.time()),
                metadata=payload.get("metadata", {}),
            )
            sales_record = self._sales.record_sale(settlement=settlement_record, transaction=transaction)
        except Exception:
            self._logger.exception("Failed to record sale for %s", request_id)
            return

        self._records[request_id] = sales_record
        event_payload = {
            "request_id": request_id,
            "transaction": transaction,
            "settlement": settlement_data,
            "sales_record": asdict(sales_record),
        }
        self.publish(SALES_LEDGER_UPDATED, event_payload)


__all__ = [
    "PipelineHSMService",
    "IssuerService",
    "PersonalizationService",
    "MerchantService",
    "TokenizationService",
    "MobileWalletService",
    "PCSCService",
    "TransactionService",
    "PaymentGatewayService",
    "SettlementService",
    "RevenueLedgerService",
    "SalesLedgerService",
]
