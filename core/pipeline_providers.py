"""Backend provider abstractions for the issuer pipeline.

The pipeline uses lightweight provider interfaces so that hardware and
emulator implementations can plug into the same service contracts.  This
module supplies default emulator-friendly providers that rely on existing
GREENWIRE components while keeping the interface small and testable.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from core.hsm_service import HSMService
from core.logging_system import get_logger

LOGGER = get_logger("pipeline_providers")


@dataclass
class SessionKeys:
    """Container for derived session keys."""

    mac_key: str
    enc_key: str
    dek_key: str
    metadata: Dict[str, str]


class HSMBackend:
    """Interface for HSM operations needed by the pipeline."""

    def derive_session_keys(self, *, pan: str, pan_sequence: str, atc: int) -> SessionKeys:
        raise NotImplementedError

    def generate_arqc(self, *, pan: str, atc: int, payload: bytes) -> str:
        raise NotImplementedError


class EmulatorHSMBackend(HSMBackend):
    """Soft HSM backend using the existing HSMService emulator."""

    def __init__(self, *, store_path: Path | str | None = None) -> None:
        self._store_path = store_path or Path("data/hsm_keystore.json")
        self._service = HSMService(store_path=self._store_path)
        try:
            self._service.generate_default_keyset(overwrite=False)
        except ValueError:
            # Keys already exist, which is fine.
            pass

    def derive_session_keys(self, *, pan: str, pan_sequence: str, atc: int) -> SessionKeys:
        seed = f"{pan}:{pan_sequence}:{atc}".encode()
        digest = hashlib.sha256(seed).hexdigest().upper()
        mac_key = digest[:32]
        enc_key = digest[16:48]
        dek_key = digest[8:40]
        metadata = {"algorithm": "sha256", "source": "emulator"}
        return SessionKeys(mac_key=mac_key, enc_key=enc_key, dek_key=dek_key, metadata=metadata)

    def generate_arqc(self, *, pan: str, atc: int, payload: bytes) -> str:
        if not payload:
            payload = b"\x00" * 8
        data_hex = payload.hex().upper()
        seed = f"{pan}:{atc}:{data_hex}".encode()
        return hashlib.sha256(seed).hexdigest().upper()[:32]


class CardPersonalizer:
    """Interface for card personalization providers."""

    def personalize(self, *, request_id: str, profile: Dict[str, str], output_dir: Path) -> Dict[str, str]:
        raise NotImplementedError


class VirtualCardPersonalizer(CardPersonalizer):
    """Emulator that emits card profile artifacts using JSON/TLV dumps."""

    def personalize(self, *, request_id: str, profile: Dict[str, str], output_dir: Path) -> Dict[str, str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        card_file = output_dir / f"{request_id}_card.json"
        payload = {
            "request_id": request_id,
            "profile": profile,
            "generated_by": "VirtualCardPersonalizer",
        }
        card_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {
            "artifact_path": str(card_file),
            "aid": profile.get("aid", "A0000000031010"),
            "pan": profile.get("pan"),
            "track2": profile.get("track2"),
        }


class MerchantTerminal:
    """Interface representing merchant provisioning terminals."""

    def provision_card(self, *, card_artifacts: Dict[str, str]) -> Dict[str, str]:
        raise NotImplementedError

    def initiate_transaction(self, *, card_artifacts: Dict[str, str], amount: float) -> Dict[str, str]:
        raise NotImplementedError


class EmulatorMerchantTerminal(MerchantTerminal):
    """Simple deterministic POS emulator for pipeline demos."""

    def provision_card(self, *, card_artifacts: Dict[str, str]) -> Dict[str, str]:
        terminal_id = os.getenv("GREENWIRE_EMULATED_TERMINAL", "POS-EMU-01")
        LOGGER.info("Provisioning card %s on terminal %s", card_artifacts.get("pan"), terminal_id)
        return {
            "terminal_id": terminal_id,
            "status": "provisioned",
            "merchant_id": "MERCHANT-0001",
        }

    def initiate_transaction(self, *, card_artifacts: Dict[str, str], amount: float) -> Dict[str, str]:
        track2 = card_artifacts.get("track2", "")
        pan = card_artifacts.get("pan", "0000000000000000")
        txn_id = hashlib.sha1(f"{pan}:{amount}".encode()).hexdigest()[:12].upper()
        return {
            "transaction_id": txn_id,
            "amount": amount,
            "currency": "USD",
            "track2": track2,
            "pan": pan,
            "terminal_country": "840",
            "stan": hashlib.sha1(txn_id.encode()).hexdigest()[:6].upper(),
        }


@dataclass
class PaymentNetworkResult:
    """Normalized result returned by payment network providers."""

    network: str
    reference: str
    status: str
    metadata: Dict[str, object]


class PaymentNetworkGateway:
    """Interface for payment network connectivity."""

    def send_ach_payment(self, *, transaction: Dict[str, object]) -> PaymentNetworkResult:
        raise NotImplementedError

    def send_fedwire_payment(self, *, transaction: Dict[str, object]) -> PaymentNetworkResult:
        raise NotImplementedError

    def send_sepa_payment(self, *, transaction: Dict[str, object]) -> PaymentNetworkResult:
        raise NotImplementedError

    def build_iso20022_payload(self, *, message_type: str, transaction: Dict[str, object]) -> Dict[str, object]:
        """Produce ISO 20022-compliant payload metadata."""
        raise NotImplementedError

    def schedule_settlement(self, *, network: str, window: Dict[str, object]) -> Dict[str, object]:
        """Return settlement scheduling instructions for monitoring."""
        raise NotImplementedError

    def build_nacha_batch(self, *, entries: Sequence[Dict[str, object]], cutoff: Optional[str] = None) -> Dict[str, object]:
        """Construct a Same Day ACH NACHA batch control payload."""
        raise NotImplementedError

    def build_sepa_xml(self, *, transaction: Dict[str, object], schema_version: str = "2025.1") -> str:
        """Serialize a SEPA SCT/SCT Inst XML document for the given transaction."""
        raise NotImplementedError


class EmulatorPaymentGateway(PaymentNetworkGateway):
    """Deterministic payment network emulator for demos and tests."""

    def __init__(self) -> None:
        self._counter = 0

    def _build_result(self, network: str, transaction: Dict[str, object]) -> PaymentNetworkResult:
        self._counter += 1
        reference = f"{network.upper()}-{self._counter:06d}"
        meta = {
            "transaction_id": transaction.get("transaction_id"),
            "amount": transaction.get("amount"),
            "currency": transaction.get("currency", "USD"),
            "pan": transaction.get("pan"),
            "created_at": time.time(),
        }
        return PaymentNetworkResult(network=network, reference=reference, status="accepted", metadata=meta)

    def send_ach_payment(self, *, transaction: Dict[str, object]) -> PaymentNetworkResult:
        return self._build_result("ach", transaction)

    def send_fedwire_payment(self, *, transaction: Dict[str, object]) -> PaymentNetworkResult:
        return self._build_result("fedwire", transaction)

    def send_sepa_payment(self, *, transaction: Dict[str, object]) -> PaymentNetworkResult:
        return self._build_result("sepa", transaction)

    def build_iso20022_payload(self, *, message_type: str, transaction: Dict[str, object]) -> Dict[str, object]:
        payload = {
            "message_type": message_type,
            "business_application_id": f"BAH-{self._counter:06d}",
            "creation_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "transaction": transaction,
        }
        return payload

    def schedule_settlement(self, *, network: str, window: Dict[str, object]) -> Dict[str, object]:
        schedule_id = f"{network.upper()}-SETTLE-{self._counter:06d}"
        return {
            "schedule_id": schedule_id,
            "network": network,
            "window": window,
            "created_at": time.time(),
        }

    def build_nacha_batch(self, *, entries: Sequence[Dict[str, object]], cutoff: Optional[str] = None) -> Dict[str, object]:
        cutoff = cutoff or time.strftime("%Y-%m-%dT%H:%M:%S")
        trace_hash = hashlib.sha1(json.dumps(entries, sort_keys=True).encode()).hexdigest().upper()
        return {
            "cutoff": cutoff,
            "entry_count": len(tuple(entries)),
            "trace": trace_hash[:20],
            "file_control": {
                "priority_code": "01",
                "immediate_destination": "091000019",
                "immediate_origin": "231380104",
                "reference_code": trace_hash[-8:],
            },
        }

    def build_sepa_xml(self, *, transaction: Dict[str, object], schema_version: str = "2025.1") -> str:
        reference = transaction.get("transaction_id") or hashlib.sha1(json.dumps(transaction, sort_keys=True).encode()).hexdigest()[:12]
        template = (
            "<Document xmlns=\"urn:iso:std:iso:20022:tech:xsd:pain.001.%s\">"
            "<CstmrCdtTrfInitn><GrpHdr><MsgId>%s</MsgId><NbOfTxs>1</NbOfTxs>"
            "<InitgPty><Nm>GREENWIRE</Nm></InitgPty></GrpHdr>"
            "<PmtInf><PmtInfId>%s</PmtInfId><PmtMtd>TRF</PmtMtd>"
            "<ReqdExctnDt>%s</ReqdExctnDt>"
            "<CdtTrfTxInf><PmtId><EndToEndId>%s</EndToEndId></PmtId>"
            "<Amt><InstdAmt Ccy=\"%s\">%.2f</InstdAmt></Amt>"
            "</CdtTrfTxInf></PmtInf></CstmrCdtTrfInitn></Document>"
        )
        return template % (
            schema_version,
            reference,
            reference,
            time.strftime("%Y-%m-%d"),
            transaction.get("end_to_end_id", reference),
            transaction.get("currency", "EUR"),
            float(transaction.get("amount", 0.0)),
        )


@dataclass
class PCSCReaderInfo:
    reader_id: str
    name: str
    vendor: str
    model: str
    supports_contactless: bool
    capabilities: Dict[str, object]


class PCSCReaderGateway:
    """Interface for PC/SC reader orchestration (OmniKey or generic)."""

    def list_readers(self) -> List[PCSCReaderInfo]:
        raise NotImplementedError

    def process_card(self, *, profile: Dict[str, object], reader_hint: Optional[str] = None) -> Dict[str, object]:
        raise NotImplementedError


class EmulatorPCSCReaderGateway(PCSCReaderGateway):
    def __init__(self) -> None:
        self._fallback_readers = [
            PCSCReaderInfo(
                reader_id="pcsc_sim_omnikey",
                name="OMNIKEY CardMan (simulated)",
                vendor="OMNIKEY",
                model="CardMan",
                supports_contactless=True,
                capabilities={"iso7816": True, "iso14443": True},
            ),
            PCSCReaderInfo(
                reader_id="pcsc_sim_generic",
                name="Generic PC/SC Reader (simulated)",
                vendor="Generic",
                model="PCSC",
                supports_contactless=True,
                capabilities={"iso7816": True},
            ),
        ]

    def _safe_readers(self):
        try:
            from smartcard.System import readers  # type: ignore

            return readers()
        except Exception:
            return []

    def list_readers(self) -> List[PCSCReaderInfo]:
        discovered = []
        for idx, reader in enumerate(self._safe_readers()):
            name = str(reader)
            vendor, model = self._parse_reader_name(name)
            info = PCSCReaderInfo(
                reader_id=f"pcsc_{idx}",
                name=name,
                vendor=vendor,
                model=model,
                supports_contactless="nfc" in name.lower() or "contactless" in name.lower(),
                capabilities={"iso7816": True, "iso14443": "nfc" in name.lower()},
            )
            discovered.append(info)
        return discovered or list(self._fallback_readers)

    def process_card(self, *, profile: Dict[str, object], reader_hint: Optional[str] = None) -> Dict[str, object]:
        readers = self.list_readers()
        selected = self._select_reader(readers, reader_hint)
        summary = {
            "reader": selected.name,
            "reader_id": selected.reader_id,
            "vendor": selected.vendor,
            "profile_pan": profile.get("pan"),
            "status": "simulated",
        }

        try:
            from smartcard.System import readers as sc_readers  # type: ignore
            from smartcard.Exceptions import CardConnectionException, NoCardException  # type: ignore

            pcsc_list = sc_readers()
            if not pcsc_list:
                return summary

            idx = 0
            if selected.reader_id.startswith("pcsc_") and selected.reader_id[5:].isdigit():
                idx = int(selected.reader_id.split("_")[1])
            if idx >= len(pcsc_list):
                return summary

            reader = pcsc_list[idx]
            connection = reader.createConnection()
            connection.connect()
            try:
                atr_bytes = bytes(connection.getATR())
                summary["atr"] = atr_bytes.hex().upper()
                try:
                    response, sw1, sw2 = connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                    if sw1 == 0x90:
                        summary["card_uid"] = bytes(response).hex().upper()
                except Exception:
                    pass
                summary["status"] = "processed"
            finally:
                try:
                    connection.disconnect()
                except (CardConnectionException, NoCardException):
                    pass
            return summary
        except ImportError:
            return summary
        except Exception as exc:  # pragma: no cover - hardware errors are environment-specific
            summary["status"] = "error"
            summary["error"] = str(exc)
            return summary

    def _select_reader(self, readers: List[PCSCReaderInfo], reader_hint: Optional[str]) -> PCSCReaderInfo:
        if reader_hint:
            for reader in readers:
                if reader_hint.lower() in reader.name.lower():
                    return reader
        # Prefer OmniKey hardware when present
        for reader in readers:
            if "omnikey" in reader.name.lower():
                return reader
        return readers[0]

    def _parse_reader_name(self, reader_name: str) -> tuple[str, str]:
        base = reader_name.split(" 0")[0].strip()
        parts = base.split()
        if not parts:
            return "Unknown", "Reader"
        vendor = parts[0].upper()
        model = " ".join(parts[1:]) or "Reader"
        return vendor, model


@dataclass
class MobileWalletResult:
    wallet_type: str
    token_reference: str
    status: str
    assurance_level: str
    metadata: Dict[str, object]


class MobileWalletIntegrator:
    """Interface for provisioning Google Wallet and Apple Wallet tokens."""

    def provision_google_wallet(self, *, artifacts: Dict[str, str], device_metadata: Dict[str, object]) -> MobileWalletResult:
        raise NotImplementedError

    def provision_apple_wallet(self, *, artifacts: Dict[str, str], device_metadata: Dict[str, object]) -> MobileWalletResult:
        raise NotImplementedError


class EmulatorMobileWalletIntegrator(MobileWalletIntegrator):
    def provision_google_wallet(self, *, artifacts: Dict[str, str], device_metadata: Dict[str, object]) -> MobileWalletResult:
        token = self._build_token("google", artifacts, device_metadata)
        metadata = {
            "device_account_id": device_metadata.get("device_account_id", "pixel"),
            "cdcvm": device_metadata.get("cdcvm"),
        }
        return MobileWalletResult(
            wallet_type="google",
            token_reference=token,
            status="provisioned",
            assurance_level=device_metadata.get("assurance_level", "L2"),
            metadata=metadata,
        )

    def provision_apple_wallet(self, *, artifacts: Dict[str, str], device_metadata: Dict[str, object]) -> MobileWalletResult:
        token = self._build_token("apple", artifacts, device_metadata)
        metadata = {
            "device_account_number": device_metadata.get("device_account_number", "ADP000"),
            "secure_element_id": device_metadata.get("secure_element_id", "SE-EMU"),
        }
        return MobileWalletResult(
            wallet_type="apple",
            token_reference=token,
            status="provisioned",
            assurance_level=device_metadata.get("assurance_level", "TAV2"),
            metadata=metadata,
        )

    def _build_token(self, wallet: str, artifacts: Dict[str, str], device_metadata: Dict[str, object]) -> str:
        pan = artifacts.get("pan", "0000000000000000")
        seed = f"{wallet}:{pan}:{device_metadata.get('device_account_id', '')}:{time.time()}"
        return hashlib.sha256(seed.encode()).hexdigest()[:24].upper()


@dataclass
class ATMDispenseResult:
    request_id: str
    amount: float
    currency: str
    status: str
    metadata: Dict[str, object]


class ATMDeviceInterface:
    """Interface for ATM hardware or emulation flows."""

    def prepare_card(self, *, profile: Dict[str, object]) -> Dict[str, object]:
        raise NotImplementedError

    def dispense_cash(self, *, request: Dict[str, object]) -> ATMDispenseResult:
        raise NotImplementedError


class EmulatorATMDevice(ATMDeviceInterface):
    def __init__(self) -> None:
        self._float_counter = 0

    def prepare_card(self, *, profile: Dict[str, object]) -> Dict[str, object]:
        self._float_counter += 1
        return {
            "atm_id": "ATM-EMU-001",
            "cassette_cycle": self._float_counter,
            "card_pan": profile.get("pan"),
            "prepared_at": time.time(),
        }

    def dispense_cash(self, *, request: Dict[str, object]) -> ATMDispenseResult:
        amount = float(request.get("amount", 0.0))
        currency = request.get("currency", "USD")
        self._float_counter += 1
        metadata = {
            "atm_id": request.get("atm_id", "ATM-EMU-001"),
            "cassette_cycle": self._float_counter,
            "cdcvm": request.get("cdcvm"),
        }
        return ATMDispenseResult(
            request_id=request.get("request_id", "unknown"),
            amount=amount,
            currency=currency,
            status="dispensed",
            metadata=metadata,
        )


@dataclass
class POSTransactionResult:
    transaction_id: str
    amount: float
    currency: str
    status: str
    cdcvm: Optional[Dict[str, object]]
    metadata: Dict[str, object]


class POSTerminalGateway:
    """Interface for point-of-sale operations."""

    def confirm_contactless_transaction(self, *, payload: Dict[str, object]) -> POSTransactionResult:
        raise NotImplementedError


class EmulatorPOSTerminalGateway(POSTerminalGateway):
    def confirm_contactless_transaction(self, *, payload: Dict[str, object]) -> POSTransactionResult:
        txn_id = payload.get("transaction_id") or hashlib.sha1(str(payload).encode()).hexdigest()[:16].upper()
        metadata = {
            "terminal_id": payload.get("terminal_id", "POS-EMU-01"),
            "assurance_level": payload.get("assurance_level", "standard"),
            "contactless_profile": payload.get("contactless_profile", "EMV"),
        }
        cdcvm = payload.get("cdcvm")
        return POSTransactionResult(
            transaction_id=txn_id,
            amount=float(payload.get("amount", 0.0)),
            currency=payload.get("currency", "USD"),
            status="approved",
            cdcvm=cdcvm,
            metadata=metadata,
        )


@dataclass
class RevenueLedgerRecord:
    reference_id: str
    channel: str
    amount: float
    currency: str
    metadata: Dict[str, object]


class RevenueLedgerConnector:
    """Interface for revenue and settlement accounting."""

    def record_authorization(self, *, entry: RevenueLedgerRecord) -> Dict[str, object]:
        raise NotImplementedError

    def record_settlement(self, *, entry: RevenueLedgerRecord) -> Dict[str, object]:
        raise NotImplementedError

    def alert_overdue_settlement(self, *, entry: RevenueLedgerRecord) -> None:
        raise NotImplementedError


class EmulatorRevenueLedgerConnector(RevenueLedgerConnector):
    def __init__(self) -> None:
        self._storage: Dict[str, RevenueLedgerRecord] = {}

    def record_authorization(self, *, entry: RevenueLedgerRecord) -> Dict[str, object]:
        self._storage[entry.reference_id] = entry
        LOGGER.info("Ledger authorization recorded for %s", entry.reference_id)
        return {"status": "recorded", "reference_id": entry.reference_id}

    def record_settlement(self, *, entry: RevenueLedgerRecord) -> Dict[str, object]:
        self._storage[entry.reference_id] = entry
        LOGGER.info("Ledger settlement recorded for %s", entry.reference_id)
        return {"status": "settled", "reference_id": entry.reference_id}

    def alert_overdue_settlement(self, *, entry: RevenueLedgerRecord) -> None:
        LOGGER.warning("Settlement overdue for %s", entry.reference_id)


@dataclass
class TokenizationResult:
    identifier: str
    scheme: str
    expires_at: float
    metadata: Dict[str, object]


class TokenizationProvider:
    """Interface that generates network tokens for card artifacts."""

    def generate_tokens(self, *, artifacts: Dict[str, str], scheme: str) -> TokenizationResult:
        raise NotImplementedError


class EmulatorTokenizationProvider(TokenizationProvider):
    """Generates deterministic but unique-looking tokens for demos."""

    def generate_tokens(self, *, artifacts: Dict[str, str], scheme: str) -> TokenizationResult:
        pan = artifacts.get("pan", "0000000000000000")
        seed = f"{pan}:{scheme}:{time.time()}".encode()
        digest = hashlib.sha512(seed).hexdigest()
        token = digest[:16].upper()
        return TokenizationResult(
            identifier=token,
            scheme=scheme,
            expires_at=time.time() + 86400.0,
            metadata={
                "pan_suffix": pan[-4:],
                "track2_hash": hashlib.sha1(artifacts.get("track2", "").encode()).hexdigest(),
            },
        )


@dataclass
class SettlementRecord:
    settlement_id: str
    network: str
    reference: str
    amount: float
    currency: str
    status: str
    processed_at: float
    metadata: Dict[str, object]


class SettlementEngine:
    """Interface for converting payment gateway results into settlements."""

    def process_settlement(self, *, transaction: Dict[str, object], payment_result: PaymentNetworkResult) -> SettlementRecord:
        raise NotImplementedError


class EmulatorSettlementEngine(SettlementEngine):
    """Generates settlement confirmations using gateway metadata."""

    def process_settlement(self, *, transaction: Dict[str, object], payment_result: PaymentNetworkResult) -> SettlementRecord:
        reference = payment_result.reference
        amount = float(transaction.get("amount", 0.0))
        currency = str(transaction.get("currency", "USD"))
        settlement_id = hashlib.sha1(f"{reference}:{amount}:{currency}".encode()).hexdigest()[:20].upper()
        metadata = {
            "transaction_id": transaction.get("transaction_id"),
            "pan": transaction.get("pan"),
            "network_meta": payment_result.metadata,
        }
        return SettlementRecord(
            settlement_id=settlement_id,
            network=payment_result.network,
            reference=reference,
            amount=amount,
            currency=currency,
            status="settled",
            processed_at=time.time(),
            metadata=metadata,
        )


@dataclass
class SalesRecord:
    entry_id: str
    settlement_id: str
    amount: float
    currency: str
    revenue_share: float
    recorded_at: float
    metadata: Dict[str, object]


class SalesLedger:
    """Interface for recording settlement outcomes in sales reporting."""

    def record_sale(self, *, settlement: SettlementRecord, transaction: Dict[str, object]) -> SalesRecord:
        raise NotImplementedError


class EmulatorSalesLedger(SalesLedger):
    """Writes in-memory sales ledger entries with predictable results."""

    def __init__(self) -> None:
        self._counter = 0

    def record_sale(self, *, settlement: SettlementRecord, transaction: Dict[str, object]) -> SalesRecord:
        self._counter += 1
        share = float(transaction.get("amount", 0.0)) * 0.015
        entry_id = f"SALE-{self._counter:06d}"
        metadata = {
            "network": settlement.network,
            "merchant_id": transaction.get("merchant_id"),
            "terminal_id": transaction.get("terminal", {}).get("terminal_id") if isinstance(transaction.get("terminal"), dict) else transaction.get("terminal_id"),
        }
        return SalesRecord(
            entry_id=entry_id,
            settlement_id=settlement.settlement_id,
            amount=settlement.amount,
            currency=settlement.currency,
            revenue_share=share,
            recorded_at=time.time(),
            metadata=metadata,
        )


# Default factory registrations for emulator mode, including ATM/POS/accounting providers.
PROVIDER_FACTORIES: Dict[str, Dict[str, object]] = {
    "emulator": {
        "hsm": EmulatorHSMBackend,
        "personalizer": VirtualCardPersonalizer,
        "merchant": EmulatorMerchantTerminal,
        "gateway": EmulatorPaymentGateway,
        "atm": EmulatorATMDevice,
        "pos": EmulatorPOSTerminalGateway,
        "pcsc": EmulatorPCSCReaderGateway,
        "wallet": EmulatorMobileWalletIntegrator,
        "tokenizer": EmulatorTokenizationProvider,
        "settlement": EmulatorSettlementEngine,
        "accounting": EmulatorRevenueLedgerConnector,
        "sales": EmulatorSalesLedger,
    }
}


def build_providers(mode: str, overrides: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    """Instantiate providers for the requested mode."""

    mode = mode.lower()
    overrides = overrides or {}
    if mode not in PROVIDER_FACTORIES:
        raise ValueError(f"Unsupported pipeline mode '{mode}'")

    result: Dict[str, object] = {}
    for key, factory in PROVIDER_FACTORIES[mode].items():
        if key in overrides:
            result[key] = overrides[key]
        else:
            result[key] = factory()
    return result


__all__ = [
    "SessionKeys",
    "HSMBackend",
    "EmulatorHSMBackend",
    "CardPersonalizer",
    "VirtualCardPersonalizer",
    "MerchantTerminal",
    "EmulatorMerchantTerminal",
    "PaymentNetworkGateway",
    "EmulatorPaymentGateway",
    "PaymentNetworkResult",
    "PCSCReaderInfo",
    "PCSCReaderGateway",
    "EmulatorPCSCReaderGateway",
    "MobileWalletResult",
    "MobileWalletIntegrator",
    "EmulatorMobileWalletIntegrator",
    "ATMDispenseResult",
    "ATMDeviceInterface",
    "EmulatorATMDevice",
    "POSTransactionResult",
    "POSTerminalGateway",
    "EmulatorPOSTerminalGateway",
    "RevenueLedgerRecord",
    "RevenueLedgerConnector",
    "EmulatorRevenueLedgerConnector",
    "TokenizationProvider",
    "EmulatorTokenizationProvider",
    "TokenizationResult",
    "SettlementEngine",
    "EmulatorSettlementEngine",
    "SettlementRecord",
    "SalesLedger",
    "EmulatorSalesLedger",
    "SalesRecord",
    "build_providers",
]
