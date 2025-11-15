# GREENWIRE v5 Multithreaded Architecture

Updated: 2025-11-15

## 1. Objectives

- Provide a deterministic, multithreaded execution model linking HSM, issuer, personalization, and merchant services.
- Support both **hardware** and **emulator** backends with the same orchestration contract.
- Generate Authorization Request Cryptograms (ARQC) with provable audit trails.
- Offer reusable provider interfaces for cryptographic keys, certificates, and device profiles.
- Surface the entire flow through the modern CLI (`greenwire_modern.py`) and automation APIs.

## 2. High-Level Service Graph

```text
┌─────────┐     ┌────────────┐     ┌────────────────┐     ┌────────────┐     ┌──────────────┐
│  HSM    │ ==> │ Issuer Bus │ ==> │ Personalization│ ==> │ Merchant POS│ ==> │ Txn Processor │
└─────────┘     └────────────┘     └────────────────┘     └────────────┘     └──────────────┘
      ▲                │                   │                     │                    │
      ╰────────────────╋───────────────────╋─────────────────────╋────────────────────╯
                       ▼                   ▼                     ▼
                 Telemetry/Logging   Artifact Writer      CLI / API Adapter
```

Each block maps to a dedicated service derived from `BaseService` (see §3). Services communicate through typed messages on the `ServiceOrchestrator` event loop. Cross-cutting concerns (telemetry, auditing, configuration) are supplied through dependency injection during registration.

## 3. Core Components

### 3.1 ServiceOrchestrator

- Owns the thread pool and life cycle for all registered services.
- Provides a **Mode Registry** (`hardware`, `emulator`, `software-provider`) controlling which backend implementations are activated.
- Persists every inter-service message and ARQC result into SQLite (`artifacts/orchestrator.db`).
- Exposes `start_all()`, `stop_all()`, `switch_mode()` APIs to the CLI.

### 3.2 BaseService Pattern

```python
class BaseService(Thread):
    name: str
    dependencies: set[str]
    def on_start(self, context: ServiceContext) -> None: ...
    def handle_message(self, message: ServiceMessage) -> None: ...
    def on_stop(self) -> None: ...
```

All runtime services extend the base class. `ServiceContext` carries handles for configuration, logging, persistence, key stores, and backend factories. Each service runs on its own thread and interacts solely through messages or context adapters to keep locking minimal.

### 3.3 Backend Providers

| Provider | Hardware Backend | Emulator Backend | Software Provider Mode |
| --- | --- | --- | --- |
| `HSMBackend` | PKCS#11 (Thales/Gemalto) via `pykcs11` | SoftHSMv2 or in-memory CMAC engine | Accepts ARQC key material over REST/gRPC |
| `CardPersonalizer` | Smartcard writers via `pyscard` / `nfcpy` | Virtual card file (`.econ`) builder | Emits personalization bundles for third parties |
| `MerchantTerminal` | ACR122U/PCSC readers | POS emulator with deterministic timing | Exports ISO 8583 frames |
| `NetworkSwitch` | ISO 8583 / SPDH over TCP | Replayable switch harness | None (delegates to external host) |

Providers implement a shared interface; the orchestrator selects the proper implementation based on the active mode.

## 4. Service Responsibilities

### 4.1 HSM Service (`core/hsm_service.py`)

- Maintains secure session with the configured HSM backend.
- Exposes commands for **issuer master key lookup**, **session key derivation**, and **ARQC generation**.
- Caches derived keys per PAN/PSN with automatic expiry.
- Publishes `HSMReady`, `SessionKeysDerived`, and `ARQCGenerated` messages.

### 4.2 Issuer Service (`core/issuer_service.py`)

- Receives card request events from CLI or automation pipelines.
- Validates customer profile against issuer policy (limits, KYC flags).
- Requests session keys from HSM service; stores results in the issuer ledger.
- Sends `IssuerCardApproved` and `PersonalizationRequest` messages downstream.

### 4.3 Personalization Service (`core/personalization_service.py`)

- Consumes personalization requests.
- Applies card profile templates (AID, EMV tags, keys) and interacts with `CardPersonalizer` backend.
- Produces card artifacts: track data, EMV tag files, secure element script.
- Emits `CardPersonalized` and `MerchantProvisioningRequest` messages.

### 4.4 Merchant Service (`core/merchant_service.py`)

- Interfaces with physical POS or emulator to perform card provisioning, activation, and test transactions.
- Generates initial transaction requests routed to the Transaction Processor.
- Reports terminal capabilities, risk parameters, and telemetry.
- Outputs `MerchantTxnInitiated` events.

### 4.5 Transaction Processor (`core/transaction_service.py`)

- Coordinates EMV transactions end to end, including **Generate AC (ARQC)** step.
- Retrieves issuer rules (CVM lists, floor limits) from configuration storage.
- Persists transaction timeline, cryptographic inputs, and ARQC for auditing.
- Notifies orchestrator when **ARQC + metadata** is ready for CLI/APIs.

### 4.6 Telemetry & Artifact Services

- `TelemetryService` aggregates metrics (latency, success rates) and streams them to Prometheus-compatible exporters.
- `ArtifactWriterService` stores card images, transaction logs, and JSON transcripts (signed if HSM available).

## 5. Message Flow (Happy Path)

1. CLI issues `card-issue` command → `IssuerService` receives `IssueCardRequest`.
2. `IssuerService` requests session keys from `HSMService` (`DeriveSessionKeys`).
3. `HSMService` derives keys, returns `SessionKeysDerived`.
4. `IssuerService` generates card profile and emits `PersonalizationRequest`.
5. `PersonalizationService` programs card (hardware) or builds virtual card (emulator) and emits `CardPersonalized`.
6. `MerchantService` executes provisioning, triggers `MerchantTxnInitiated` with terminal data.
7. `TransactionService` processes EMV steps, consults HSM for ARQC (`GenerateAC`).
8. `HSMService` responds with `ARQCGenerated`; `TransactionService` finalizes `TransactionCompleted` event carrying ARQC, TVR, TSI, logs.
9. `CLI Adapter` formats response for user (JSON/YAML/table) and archives metadata.

## 6. Mode Management

| Mode | Description | Activated Providers |
| --- | --- | --- |
| `hardware` | Live hardware (HSM, card writer, POS) | PKCS#11, PC/SC, ISO8583 switch |
| `emulator` | Fully virtual execution | SoftHSM, virtual card, POS emulator, Fake ISO switch |
| `software-provider` | GREENWIRE supplies cryptographic material but does not execute hardware steps | SoftHSM for ARQC, emits personalization payloads for partners |

Modes are changed through `ServiceOrchestrator.switch_mode(target_mode: str)`. Services react by hot-swapping their backend adapters without restart when possible; otherwise they emit `RestartRequired` events that the orchestrator coordinates.

## 7. Persistence & Audit

- **SQLite (`artifacts/orchestrator.db`)**: message bus, service status snapshots, transaction transcripts.
- **Artifact directory (`artifacts/cards/`, `artifacts/transactions/`)**: JSON, TLV dumps, PDF reports.
- **Key provenance**: For each ARQC, store the master key reference, derivation method, and cryptogram inputs hashed with SHA-256 for audit.

## 8. Security Controls

- Secrets provided through `core/config/secrets.yaml` with optional HashiCorp Vault integration.
- HSM credentials loaded via environment variables or PKCS#11 login tokens.
- Emulator mode uses deterministic test keys clearly marked as non-production.
- Role-based access enforced at CLI layer (operator, auditor, developer) with policy file mapping commands to roles.

## 9. CLI Integration

New CLI commands (to be implemented under `commands/issuer_pipeline.py`):

- `card-issue` – Issue and personalize a card end-to-end.
- `card-issue --mode emulator` – Run pipeline without hardware.
- `txn-simulate` – Trigger merchant + transaction workflow for an existing card.
- `arqc-verify` – Request ARQC recomputation and comparison for a stored transaction.
- `pipeline-status` – Show live service status, active mode, and queue depth.

## 10. Implementation Roadmap

1. Implement `core/service_orchestrator.py` and `core/base_service.py` scaffolding (threading, registry, persistence).
2. Build backend provider abstractions and default implementations for hardware/emulator modes.
3. Implement HSM, Issuer, Personalization, Merchant, and Transaction services incrementally with unit tests.
4. Wire new commands into `greenwire_modern.py` via `commands/issuer_pipeline.py`.
5. Update documentation (`CLI_MODERN_DOCUMENTATION.md`, `GREENWIRE_ANALYSIS.md`) once code path is active.
6. Add integration tests covering hardware mocks and emulator mode (use SoftHSM for pipeline verification).

---

This document supersedes the legacy `ARCHITECTURE.md` content for future work on GREENWIRE v5.
