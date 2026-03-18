# GREENWIRE Issuance and Processing Commands

Research date: March 18, 2026

Purpose: document the actual GREENWIRE command surface that matters for issuance, CAP deployment, processing, wallet flows, and emulator-backed testing.

## Scope

This is intentionally repo-specific. It documents commands that exist in this checkout, not a hypothetical future CLI.

Primary entry points:

- [greenwire_modern.py](F:/repo/GREENWIRE/greenwire_modern.py)
- [commands/issuer_pipeline.py](F:/repo/GREENWIRE/commands/issuer_pipeline.py)
- [commands/cap_management.py](F:/repo/GREENWIRE/commands/cap_management.py)
- [commands/wallet_commands.py](F:/repo/GREENWIRE/commands/wallet_commands.py)
- [greenwire/core/smart_vulnerability_card.py](F:/repo/GREENWIRE/greenwire/core/smart_vulnerability_card.py)

## CLI Version

The current modern CLI identifies itself as `GREENWIRE 4.1.0`.

Core categories in the current code:

- Core
- Card
- Crypto
- Emulation
- Fuzzing
- NFC
- Security

Source:

- [greenwire_modern.py](F:/repo/GREENWIRE/greenwire_modern.py)

## Command Inventory Relevant to Issuance and Processing

### 1. Issue and Personalize a Card Through the Pipeline

Command:

```powershell
python greenwire_modern.py card-issue --pan 4003123412341234 --amount 1.25 --network ach
```

What it does:

- dispatches an issuer request
- derives session keys through the emulator HSM backend
- personalizes a virtual card artifact
- provisions the card on the merchant emulator
- initiates a transaction
- routes the transaction through the payment-gateway emulator

Important arguments implemented in code:

- `--pan`
- `--cardholder`
- `--amount`
- `--mode` with `emulator`
- `--pan-sequence`
- `--atc`
- `--network` with `ach`, `fedwire`, `sepa`
- `--timeout`

Source:

- [commands/issuer_pipeline.py](F:/repo/GREENWIRE/commands/issuer_pipeline.py)

Artifacts produced:

- `artifacts/cards/*_card.json`
- `artifacts/cards/*_summary.json`

### 2. Produce or Deploy Java Card CAP Files

Produce all caplet variants:

```powershell
python greenwire_modern.py cap produce-all
```

Deploy a CAP:

```powershell
python greenwire_modern.py cap deploy --cap-file path\to\applet.cap --reader-index 0
```

What it does:

- wraps the CAP production system
- supports CAP deployment to a selected reader index

Source:

- [commands/cap_management.py](F:/repo/GREENWIRE/commands/cap_management.py)

### 3. Provision Wallet and NFC/RFID Targets

Command:

```powershell
python greenwire_modern.py wallet-provision --wallets google apple samsung generic_nfc transit_rfid --card-type visa --simulate-pos
```

Other NFC/RFID profile example:

```powershell
python greenwire_modern.py wallet-provision --wallets generic_nfc transit_rfid --card-type ntag --uid 04AABBCCDD
```

What it does:

- creates synthetic artifacts for the selected card type
- generates emulator tokenization output
- provisions Google, Apple, Samsung, generic NFC, and transit RFID targets
- can optionally simulate a contactless POS confirmation

Source:

- [commands/wallet_commands.py](F:/repo/GREENWIRE/commands/wallet_commands.py)

### 4. Emulate Terminal or Card

Examples exercised in this repo:

```powershell
python greenwire_modern.py emulate-terminal --duration 2 --wireless
python greenwire_modern.py emulate-card --card-type visa --duration 2 --contactless
```

These are useful for:

- transaction smoke testing
- wallet validation
- contactless behavior checks

### 5. Static and Tooling Verification

Java static setup:

```powershell
python tools\verify_java_static_setup.py
```

Static artifact audit:

```powershell
python verify_static.py
```

Markdown/path audit:

```powershell
python tools\check_markdown_paths.py
```

These are not issuance commands, but they are part of keeping the issuance toolchain usable.

## Transaction Mutation and Logging Path

For testing unusual processing behavior, GREENWIRE now supports randomized mutation plans in the smart test-card path.

Capabilities:

- randomized floor-limit variation
- randomized CVM selection
- pattern injection at key transaction phases
- unexpected-mode scenarios
- persistence of mutation observations onto the card object

Relevant code:

- [greenwire/core/smart_vulnerability_card.py](F:/repo/GREENWIRE/greenwire/core/smart_vulnerability_card.py)
- [greenwire/core/configuration_manager.py](F:/repo/GREENWIRE/greenwire/core/configuration_manager.py)

Persisted fields include:

- `transaction_log_records`
- `mutation_log_records`
- `terminal_snapshots`

This is the main repo-supported path for testing floor/CVM anomalies and pattern injections without needing a proprietary terminal kernel binary.

## How These Commands Map to Real Roles

### Issuer / Personalization

Main commands and modules:

- `card-issue`
- `cap produce-all`
- `cap deploy`
- HSM key and GP helper modules

### Merchant / Acceptance

Main commands and modules:

- `emulate-terminal`
- wallet POS confirmation under `wallet-provision`
- merchant emulator and terminal snapshot paths

### HSM / Host

Main modules and paths:

- [core/hsm_service.py](F:/repo/GREENWIRE/core/hsm_service.py)
- [core/pipeline_services.py](F:/repo/GREENWIRE/core/pipeline_services.py)
- [core/pipeline_providers.py](F:/repo/GREENWIRE/core/pipeline_providers.py)

### Wallet / Contactless / NFC

Main commands:

- `wallet-provision`
- `emulate-card`
- `emulate-terminal`

## Relationship to GlobalPlatform and Java Card Commands

GREENWIRE provides repo-native wrappers, but not every action is best done through a wrapper.

Use GREENWIRE-native commands when you want:

- artifact generation
- emulator-backed end-to-end flows
- structured JSON output
- test-card logging and mutation tracking

Use underlying GPPro or Java tooling directly when you want:

- explicit secure-channel debugging
- reader-specific GP diagnostics
- direct CAP load/install troubleshooting
- raw tool behavior without CLI abstraction

## Suggested Operational Sequence

For a new Java Card issuance test:

1. `python tools\verify_java_static_setup.py`
2. `python greenwire_modern.py cap produce-all`
3. `python greenwire_modern.py cap deploy --cap-file ...`
4. `python greenwire_modern.py card-issue --pan ...`
5. `python greenwire_modern.py wallet-provision ... --simulate-pos`
6. inspect artifacts and card mutation logs

For emulator-only transaction studies:

1. `python greenwire_modern.py card-issue --pan ...`
2. `python greenwire_modern.py emulate-terminal ...`
3. use the smart test-card path for randomized floor/CVM/pattern injections

## Sources

- [greenwire_modern.py](F:/repo/GREENWIRE/greenwire_modern.py)
- [commands/issuer_pipeline.py](F:/repo/GREENWIRE/commands/issuer_pipeline.py)
- [commands/cap_management.py](F:/repo/GREENWIRE/commands/cap_management.py)
- [commands/wallet_commands.py](F:/repo/GREENWIRE/commands/wallet_commands.py)
- [GLOBALPLATFORM_AND_JAVACARD_SOFTWARE_GUIDE.md](F:/repo/GREENWIRE/docs/GLOBALPLATFORM_AND_JAVACARD_SOFTWARE_GUIDE.md)
- [EMV_KERNELS_AVAILABLE_AND_OPERATING_MODEL.md](F:/repo/GREENWIRE/docs/EMV_KERNELS_AVAILABLE_AND_OPERATING_MODEL.md)
