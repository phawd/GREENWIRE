# GREENWIRE — EMV, Smartcard, and NFC Security Testing Framework

![CI Tests](https://github.com/phawd/GREENWIRE/actions/workflows/ci.yml/badge.svg?branch=main)

**Mission:** Empower ethical, open research and field testing of smartcard, EMV, and NFC/JCOP technologies.

**License:** GPL v3

---

## Overview

GREENWIRE is a comprehensive, modular security testing framework for EMV, smartcard, NFC, and JavaCard research. It provides:

- Unified Python CLI for smartcard, NFC, and EMV operations
- JavaCard build/deploy pipeline (offline, static, and cross-platform)
- APDU4J Java integration for low-level APDU comms
- Fuzzing, mutation, and vulnerability analysis modules
- Menu-driven and scriptable workflows
- Operator-mode and production safety features

---

## Quick Start

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Use the Modern CLI (Recommended)

```bash
# Create a payment card with EMV data
python greenwire_modern.py card-create --generate-pan --emv-data --crypto-keys

# Run security testing  
python greenwire_modern.py extract-data --attack-type all --iterations 100

# List all available commands
python greenwire_modern.py list commands

# Get help for any command
python greenwire_modern.py <command> --help
```

### 3. Advanced Features (NEW!)

```bash
# Process transaction at Blandy's Flowers POS
python modules/blandys_flowers_pos.py --amount 12.50

# Run smart APDU fuzzing
python modules/smart_apdu_fuzzer.py --mode generate_ac --iterations 100

# Use unified interface (transaction + fuzzing + personalization)
python modules/unified_card_interface.py --workflow tx_fuzz

# Test MAC/CMAC operations
python modules/crypto_mac_engine.py
```

See [ADVANCED_FEATURES.md](docs/ADVANCED_FEATURES.md) for detailed documentation.

### 4. Legacy CLI (backwards compatibility)

```bash
python greenwire.py --menu
python greenwire.py easycard generate random --count 1
python greenwire.py probe-hardware --auto-init
python greenwire.py apdu-fuzz --target emv --iterations 500
```

### 5. Build JavaCard applet (offline)

```powershell
cd javacard/applet
./gradlew convertCap
```

### 6. Create static bundle (no Python required on target)

```bash
python tools/create_static_bundle.py
```

---

## Modern CLI v4.1 (Machine-Friendly)

GREENWIRE v4.1 keeps the rewritten modern CLI and improves day-to-day usability with a better help overview, categorized command catalog, and support for placing global flags before or after subcommands.

### Key Features

- **Structured Output:** JSON, YAML, and table formats for automation
- **Self-Documenting:** Comprehensive help system for every command
- **22 Commands:** Covering card management, security testing, emulation, cryptography, NFC, wallet provisioning, and core operations
- **Machine Integration:** Perfect for CI/CD, automation, and AI workflows

### Quick Examples

```bash
# Create EMV card with crypto keys (JSON output)
python greenwire_modern.py --format json card-create --generate-pan --emv-data --crypto-keys

# Run comprehensive security testing
python greenwire_modern.py extract-data --attack-type all --iterations 100

# List all available commands
python greenwire_modern.py list commands

# Helpful categorized overview
python greenwire_modern.py help

# Global flags also work after the subcommand in v4.1
python greenwire_modern.py list commands --format json

# Get structured help for any command
python greenwire_modern.py <command> --help
```

### Documentation

- **Full Documentation:** [CLI_MODERN_DOCUMENTATION.md](CLI_MODERN_DOCUMENTATION.md)
- **Quick Reference:** [CLI_QUICK_REFERENCE.md](CLI_QUICK_REFERENCE.md)

---

## Architecture & Key Components

- **Modern CLI:** `greenwire_modern.py` (v4.1 machine-friendly interface)
- **Legacy CLI:** `greenwire.py` (backwards compatibility)
- **Menu system:** `menu_handlers.py` (registry), `menu_implementations.py` (logic)
- **Core modules:** `core/` (fuzzers, NFC, EMV, config, dynamic imports)
- **Data manager:** `greenwire/core/data_manager.py` (production datasets)
- **JavaCard build:** `javacard/applet/build.gradle`, `tools/create_static_bundle.py`
- **APDU4J integration:** `apdu4j_data/README.md` (command structure, usage)

See `ARCHITECTURE.md` for a full directory/module breakdown.

---

## Major Features

- **EMV Compliance & Fuzzing:**
  - Full EMVCo protocol validation
  - APDU mutation, stateful and AI-driven fuzzing
  - Vulnerability detection and reporting
- **Smartcard Operations:**
  - JavaCard applet build/deploy (offline, static)
  - CAP file management, GlobalPlatformPro integration
  - Direct APDU comms (APDU4J, PC/SC, Android NFC)
- **NFC Operations:**
  - Tag reading/writing, emulation, and security analysis
  - Android/ADB relay and device management
- **FIDO/WebAuthn:**
  - FIDO2 credential management, PIN, and authentication
- **Operator Mode:**
  - Production safety, idempotent helpers, and non-interactive CI
- **Static Builds:**
  - PyInstaller-based, all dependencies bundled, portable

---

## Example CLI Usage

```bash
# List PC/SC readers
python greenwire.py apdu --list-readers

# Send APDU command
python greenwire.py apdu --command 00A404000E325041592E5359532E444446303100 --verbose

# NFC tag read/write
python greenwire.py nfc read
python greenwire.py nfc write --url https://example.com

# FIDO credential management
python greenwire.py fido list
python greenwire.py fido register --relying-party example.com --pin 123456

# EMV-aware fuzzing
python greenwire.py testing fuzz --iterations 100

# JavaCard build/deploy
cd javacard/applet
./gradlew convertCap
./gradlew deployCap

# Static build
python tools/create_static_bundle.py
```

---

## Configuration & Global Defaults

All persistent config is managed in `global_defaults.json` (see `core/global_defaults.py`).

Change via menu:

1. `python greenwire.py --menu`
2. Choose `11. Configuration Center`

Change via CLI:

```bash
python greenwire.py config-defaults --list
python greenwire.py config-defaults --verbose-default false
python greenwire.py config-defaults --max-payload-default 4096 --artifact-dir-default fuzz_artifacts
python greenwire.py config-defaults --stateful-default true
```

---

## JavaCard: Offline Build & Deploy

1. Place JavaCard SDK jars under `sdk/javacard/lib/` (see `tools/verify_java_static_setup.py`)
2. Build CAP: `cd javacard/applet && ./gradlew convertCap`
3. Deploy CAP: `./gradlew deployCap` (uses local GlobalPlatformPro)
4. See `javacard/applet/build.gradle` for full options

---

## Fuzzing & Vulnerability Analysis

- APDU mutation, stateful and AI-driven fuzzing (`core/apdu_fuzzer.py`)
- JSON artifact output, timing metrics, and dashboard aggregation
- See `APDU_FUZZING.md` for advanced usage

---

## Security & Safety

- Never persist sensitive cardholder data or PINs beyond test scope
- Use only in authorized lab or red team environments
- Immutable logs of all test sequences
- See `SECURITY.md` for policy and best practices

---

## Contribution & Development

- All menu actions: register in `MENU_ACTIONS` in `menu_handlers.py`
- Operator-mode helpers: must be idempotent, non-interactive in CI
- Run tests: `pytest tests/` (see `tests/conftest.py`)
- Lint: `ruff check .` (auto-fix with `ruff --fix`)
- See `CONTRIBUTING.md` for PR workflow

---

## Documentation & References

- Full AI/agent onboarding: `.github/copilot-instructions.md`
- APDU4J integration: `apdu4j_data/README.md`
- JavaCard build: `javacard/applet/build.gradle`
- Fuzzing: `APDU_FUZZING.md`
- Security: `SECURITY.md`
- Architecture: `ARCHITECTURE.md`

---

## License

GPL v3. See `LICENSE` for details.

---

**For AI agent onboarding and full project reference, see `.github/copilot-instructions.md`.**

### Build Customization

**Include Additional Files:**

```bash
pyinstaller --onefile --name greenwire --add-data "ca_keys.json;." --add-data "logs;logs" greenwire.py
```

**Cross-Platform Builds:**

- Build on the target platform for best compatibility
- Use virtual environments to control dependencies

---

## CLI Subcommands & Usage

Run:

```bash
python greenwire.py <subcommand> [options]
```

### Major Subcommands

- `apdu`           : Direct APDU communication with smart cards using apdu4j
- `nfc`            : NFC tag reading, writing, and emulation using nfc4pc
- `fido`           : FIDO/WebAuthn operations using YAFU
- `bg-process`     : Background process management (list, stop, status)
- `testing`        : Comprehensive smartcard testing platform with EMV-aware fuzzing, attack simulation, and automatic vulnerability detection
  - `fuzz`         : EMV-aware fuzzing with transaction flow analysis
  - `dump`         : Dump APDU communications and analyze patterns
  - `attack`       : Simulate known EMV attacks (wedge, CVM downgrade, PIN harvesting)
  - `auto-detect`  : Automatic vulnerability detection and reporting
  - `ai-vuln`      : Heuristic AI-style APDU mutation & anomaly detection (latency & SW pattern heuristics)
- `emulator`       : ISO/EMV emulator (with `--profile`, `--hardware`)
- `crypto`         : Cryptographic verification
- `issuance`       : Simulate card issuance (with `--csv-output`, `--hardware`, `--profile`, `--ca-file`)
- `easycard`       : Easy card operations - CA listing and card number generation
  - `list-ca`      : List available Certificate Authority types
  - `generate`     : Generate card numbers (random/certificate/manual methods) with installation method selection
- `probe-hardware` : Probe and initialize NFC/smartcard hardware (USB, PC/SC, NFC)
- `card-terminal`  : Act as a merchant card processor terminal with non-interactive mode
- `self-test`      : Run a basic self-test of all major features
- `dump-log`       : Dump .cap communication log
- `simulate-positive` : Simulate positive transaction results for a .cap file
- `export-replay`  : Export APDU replay log for a .cap file
- `import-replay`  : Import APDU replay log for a .cap file
- `dump-suspicious`: Dump suspicious events for a .cap file
- `learn-session`  : Update replay/suspicious logs after a positive session
- `seal-logs`      : Seal reserved log area in .cap with hash/signature
- `identitycrisis` : Random AID for each transaction (with optional `--smackdown` mode)
- `stealth`        : Stealth .cap: EMV compliant, minimal logging, random delays
- `replay`         : Replay .cap: EMV compliant, record/replay APDU/response pairs
- `decoy`          : Decoy .cap: EMV compliant, multiple applets (one real, others decoy)
- `audit`          : Audit .cap: EMV compliant, logs all APDUs, only Visa/Mastercard/Amex AIDs
- `install-cap`    : Install a .cap file on a smart card using GlobalPlatformPro or OpenSC

---

## CA Certificate/Key Support for EMV & Field Testing

GREENWIRE supports CA key/certificate management for EMV/terminal emulation and card issuance. The CA key file is a JSON array of objects with `rid`, `index`, `modulus`, and `exponent` fields, e.g.:

```json
[
  {
    "rid": "A000000003",
    "index": "92",
    "modulus": "C1D2E3F4A5B6C7D8E9F0C1D2E3F4A5B6C7D8E9F0C1D2E3F4A5B6C7D8E9F0C1D2",
    "exponent": "03"
  }
]
```

**To use your own CA key/cert:**

1. Add your CA key/cert to `ca_keys.json` in the above format.

2. Use the `--ca-file ca_keys.json` option with relevant CLI commands (e.g., `issuance`, `emulator`, `install-cap`).

3. For field/production use, ensure your CA key matches the card/AID you are issuing or testing.

### Example: Card Issuance with Custom CA Key

```bash
python greenwire.py issuance --csv-output cards.csv --hardware --profile pcsc --ca-file ca_keys.json
```

### Example: Install .cap File with Custom AID and CA Cert

```bash
python greenwire.py install-cap --cap-file myapplet.cap --tool gpp --aid A0000000031010 --ca-file ca_keys.json
```

**To validate a CA key/cert:**

- Check that the `rid` and `index` match the card/AID you are working with.
- Use the `issuance` or `emulator` subcommands with your CA file and verify successful operation/log output.

---

## Example CLI Usage

**Emulator with Hardware Profile:**

```bash
python greenwire.py emulator --cap-file mytest.cap --profile nfc --hardware
```

**Easy Card Operations:**

```bash
# List available Certificate Authorities
python greenwire.py easycard list-ca

# Generate random card numbers
python greenwire.py easycard generate random --count 5

# Generate card numbers based on CA certificates
python greenwire.py easycard generate certificate --count 3 --ca-file ca_keys.json

# Generate card numbers with custom prefix
python greenwire.py easycard generate manual --prefix 411111111111 --count 2

# Generate card numbers with installation method selection
python greenwire.py easycard generate random --count 3 --install-method globalplatform
```

**Hardware Probing:**

```bash
# Probe for available NFC/smartcard hardware
python greenwire.py probe-hardware
```

**Merchant Card Terminal:**

```bash
# Act as a card terminal with specified amount and bank code
python greenwire.py card-terminal --amount 25.99 --bank-code 123456

# Run card terminal in non-interactive mode for testing
python greenwire.py card-terminal --amount 10.00 --bank-code 123456 --non-interactive
```

**Background Process Management:**

```bash
# List all running background processes
python greenwire.py bg-process list

# Stop a specific background process by PID
python greenwire.py bg-process stop --pid 12345

# Check status of background processes
python greenwire.py bg-process status
```

**APDU Communication:**

```bash
# List available PC/SC readers
python greenwire.py apdu --list-readers

# Send APDU command to smart card
python greenwire.py apdu --command 00A404000E325041592E5359532E444446303100 --verbose

# Execute APDU commands from script file
python greenwire.py apdu --script my_commands.txt --reader "OMNIKEY CardMan 5x21 0"
```

**NFC Operations:**

```bash
# Read NFC tag
python greenwire.py nfc read

# Write URL to NFC tag
python greenwire.py nfc write --url https://example.com

# Write text to NFC tag
python greenwire.py nfc write --text "Hello World"

# Continuous NFC scanning
python greenwire.py nfc scan --continuous

# Emulate NFC tag with URL
python greenwire.py nfc emulate --url https://myapp.com
```

**FIDO/WebAuthn Operations:**

```bash
# List FIDO credentials
python greenwire.py fido list

# Register new credential
python greenwire.py fido register --relying-party example.com --pin 123456

# Authenticate with credential
python greenwire.py fido authenticate --relying-party example.com --credential-id <credential-id> --pin 123456

# Delete credential
python greenwire.py fido delete --credential-id <credential-id>

# Get FIDO device info
python greenwire.py fido info --transport usb
```

**Comprehensive Testing Platform:**

```bash
# EMV-aware fuzzing with transaction flow analysis
python greenwire.py testing fuzz --cap-file mytest.cap --transaction-flow

# Dump APDU communications and analyze patterns
python greenwire.py testing dump --cap-file mytest.cap --analyze

# Simulate known EMV attacks (wedge, CVM downgrade, PIN harvesting)
python greenwire.py testing attack --cap-file mytest.cap --attack-type wedge

# Automatic vulnerability detection and reporting
python greenwire.py testing auto-detect --cap-file mytest.cap --report
```

**Replay Mode:**

```bash
python greenwire.py replay --cap-file mytest.cap
```

**Audit Mode:**

```bash
python greenwire.py audit --cap-file mytest.cap
```

**Install .cap File (GlobalPlatformPro):**

```bash
python greenwire.py install-cap --cap-file myapplet.cap --tool gpp --aid A0000000031010
```

---

## Configuration Center & Global Defaults

GREENWIRE provides a unified persistent configuration layer that feeds multiple subsystems (fuzzers, reporting, menu tooling). Settings are stored in `global_defaults.json` (auto-created) managed by `core/global_defaults.py`.

### Managed Keys

| Key | Type | Purpose |
|-----|------|---------|
| verbose_default | bool | Default verbosity when a tool flag not explicitly set |
| max_payload_default | int | Upper bound for generated APDU/data payloads (protect hardware) |
| stateful_default | bool | Enable secondary ordered stateful phase for APDU fuzzing |
| artifact_dir_default | str | Base directory for reports, dashboards, JSON artifacts |

### Change via Menu

1. `python greenwire.py --menu`
2. Choose `11. Configuration Center`
3. Adjust values; changes persist immediately.

### Change via CLI

```bash
python greenwire.py config-defaults --list
python greenwire.py config-defaults --verbose-default false
python greenwire.py config-defaults --max-payload-default 4096 --artifact-dir-default fuzz_artifacts
python greenwire.py config-defaults --stateful-default true
```

Tools fall back to these defaults only when the corresponding runtime flags are omitted (e.g., `apdu-fuzz` uses `artifact_dir_default` if `--report-dir` not specified).

See: `APDU_FUZZING.md` (section "Configuration Center & Global Defaults") for deeper integration details.

---

## Module & Dependency Index

### Core Python Packages (External)

- pyscard (PC/SC smartcard I/O)
- nfcpy (NFC tag interaction)
- cryptography (crypto primitives, cert/key handling)
- pyudev (Linux USB device events, optional)
- base standard library: argparse, subprocess, threading, json, time, random, pathlib

### Integrated Upstream Toolchains

- apdu4j (APDU transport, Java; invoked through subprocess or wrappers)
- GlobalPlatformPro (CAP install / GP card management)
- nfc4pc (NFC operations, external tooling)
- YAFU (FIDO/WebAuthn operations)
- JavaCard toolchain (ant-javacard + SDK under `ant-javacard/`)

### Internal Core Modules (Selected)

| Module | Purpose |
|--------|---------|
| core/config.py | Global runtime configuration abstraction |
| core/logging_system.py | Unified logging, tagging, error wrappers |
| core/imports.py | Dynamic/conditional module resolution |
| core/menu_system.py | Interactive menu framework |
| core/nfc_manager.py | NFC device abstraction & scanning |
| core/apdu_fuzzer.py | Modular APDU fuzzing engine & reporting |
| core/global_defaults.py | Persistent cross-feature defaults |
| core/file_fuzzer.py | File/image/binary fuzzing helpers |
| core/real_world_card_issuer.py | Realistic EMV card generation |
| core/nfc_emv.py | EMV over NFC processing logic |
| core/crypto/* (if present) | Crypto fuzzing / key management |

### Fuzzing / Analysis Artifacts

- native_apdu_fuzz_report_*.md – Per-run APDU fuzzing summaries
- native_apdu_fuzz_session_*.json – Structured session metrics & vulnerabilities
- fuzz_dashboard_summary.md – Aggregated multi-run trends

### Build / Tooling Dependencies

- Java (for apdu4j, GlobalPlatformPro, JavaCard builds)
- Ant / ant-javacard plugin
- Gradle (Java subprojects if present)

### Optional / Conditional

- adb (Android NFC device verification & HCE scenarios)
- PyInstaller (static distribution generation)
- pcsc-lite (Linux smartcard backend)

### Environment Variables (Recognized)

| Variable | Effect |
|----------|--------|
| GREENWIRE_STATIC | Forces static import mode |
| JAVA_HOME (indirect) | Java toolchain resolution for GP/JC builds |

---

## Cross-References

- APDU fuzzing details & config integration: `APDU_FUZZING.md`
- JavaCard build pipeline: `ant-javacard/README.md`

---

## Contribution Notes (Config Layer)

When adding new global behaviors that should persist across sessions:

1. Add a key + sensible default in `core/global_defaults.py` `_DEFAULTS`.
2. Access via `load_defaults()` in feature module.
3. Provide override flag in CLI; only fall back when flag omitted.
4. Update README section above & any feature doc referencing it.

---

## Offline Java toolchain (JavaCard/GlobalPlatform)

GREENWIRE supports an offline JavaCard workflow when the required local JARs are populated in-repo.

- lib/GlobalPlatformPro.jar — GlobalPlatformPro fat JAR
- static/java/ant-javacard.jar — ant-javacard helper
- sdk/javacard/lib — Local JavaCard SDK location for converter API stubs/tools

Quick audit:

```bash
python tools/verify_java_static_setup.py
```

Gradle (offline) tasks:

- Root: `gradle listTools` (prints presence of local JARs)
- Applet: `cd javacard/applet` then `gradle buildCap` (prints offline CAP build guidance)

Notes:

- CAP conversion requires a local JavaCard SDK; the verifier shows optional missing SDK jars.
- Deployment can be done with local GlobalPlatformPro: `java -jar lib/GlobalPlatformPro.jar --help`.

(End of appended sections.)

---

## JavaCard: Offline .cap Build and Deploy (Gradle)

GREENWIRE supports a fully offline JavaCard toolchain once you place the required JavaCard SDK jars under `sdk/javacard/lib`, and place JavaCard API export files under `sdk/javacard/api_export_files` (or `export`/`exp`).

From `javacard/applet`:

```powershell
# Convert to .cap with defaults
./gradlew convertCap

# Deploy the last built .cap
./gradlew deployCap

# Override applet metadata and paths via -P properties
./gradlew convertCap `
  -PappletClass=com.greenwire.applet.PinLogicApplet `
  -PpackageName=com.greenwire.applet `
  -PpackageVersion=1.0 `
  -PappletAID=A0:00:00:06:23:01:47:52:4E:57:52 `
  -PpackageAID=A0:00:00:06:23:01:47:52:4E:57:50 `
  -PexportPath=../../sdk/javacard/api_export_files `
  -PclassesDir=build/classes/java/main

# Deploy a specific .cap
./gradlew deployCap -PcapFile=build/cap/com/greenwire/applet/javacard/applet.cap
```

Notes:

- Export files are part of the JavaCard SDK; place them in one of the discovered folders above or pass `-PexportPath`.
- `deployCap` uses the local `GlobalPlatformPro.jar` under `lib/`.
- You can also use the convenience wrappers from the project root or lib folder:
  - `gp.ps1` (PowerShell) or `gp.cmd` (CMD)

## Centralized Menu Action Registry (MENU_ACTIONS)

Interactive menu actions are now resolved exclusively via a single authoritative registry in `menu_handlers.py`:

```text
from menu_handlers import MENU_ACTIONS
```

Benefits:

- Eliminates fragile dynamic attribute introspection
- Guarantees every visible menu entry maps to an implementation
- Simplifies auditing & testing (iterate `MENU_ACTIONS.keys()`)
- Enables future permission / capability gating at a single choke point

If you add a new interactive feature:

1. Implement the function in `menu_handlers.py` (or import a working impl from `menu_implementations.py`).
2. Add an entry to `MENU_ACTIONS` mapping `action_key -> function`.
3. Reference `handler_function` (or `id`) in the menu config so the core menu system resolves it immediately.

---

## AI Vulnerability Heuristic Testing (`testing ai-vuln`)

This module performs rapid, heuristic APDU mutation modeled after lightweight AI / evolutionary strategies to surface anomalous terminal or card behaviors without requiring a full protocol grammar.

Key Capabilities:

- Multiple mutation strategies: `bitflip`, `nibble`, `ga` (genetic‑style growth), `mixed` (round‑robin)
- Optional live execution through PC/SC or (future) Android relay; dry operation when hardware absent
- Latency statistics (avg, p50, p90, p99) and status word distribution
- Simple anomaly heuristics: unexpected SW, slow responses, custom whitelist
- JSON artifact for reproducibility / trend dashboards

Example Dry Run:

```bash
python greenwire.py testing ai-vuln --iterations 200 --strategy mixed --summary --seed 1337
```

Full Artifact with Custom Seeds & Slow Response Flagging:

```bash
python greenwire.py testing ai-vuln \
  --iterations 500 \
  --strategy ga \
  --pcsc \
  --seed-file seeds.json \
  --sw-whitelist 9000,6A82,6A83 \
  --min-latency-ms 120 \
  --json-out ai_vuln_run.json
```

Seed File Format (`seeds.json`):

```json
["00A4040007A0000002471001", "80CA9F1700"]
```

Artifact Structure (abridged):

```json
{
  "meta": {"started_at": 173223..., "duration_ms": 2543, "params": {"iterations": 500, ...}},
  "stats": {"count": 120, "avg_ms": 14, "p90_ms": 21, "distinct_sw": 1, "sw_counts": {"9000": 120}},
  "anomalies": [ {"type": "unexpected-sw", "apdu": "...", "sw": "6A82"} ],
  "mutations": [ {"apdu": "00A404...", "strategy": "bitflip", "status": "executed", ...} ]
}
```

Design Goal: Provide early signal on terminal/card edge behavior before heavier stateful fuzzing cycles are scheduled.

---

## Merchant Processor Exploitation / Vulnerability Test Sequences

GREENWIRE includes an interactive merchant exploitation simulator (`merchant_exploit_interactive`) and supports crafting APDU sequences to probe terminal defenses. Below are structured *research-grade* (not production) sequences you can adapt when legally authorized. Always obtain explicit permission and never test on live payment infrastructure without contractually defined scope.

### 1. Baseline Transaction (Reference Flow)

| Step | Purpose | APDU |
|------|---------|------|
| 1 | Select PPSE | `00A404000E325041592E5359532E444446303100` |
| 2 | Select App (e.g. Visa) | `00A4040007A0000000031010` |
| 3 | GPO (minimal PDOL) | `80A8000002830000` (Example PDOL: Tag 9F66 omitted) |
| 4 | Read AFL Records | `00B2010C00`, `00B2020C00`, etc. |
| 5 | Generate AC #1 | `80AE80002B` + 0x23 bytes CDOL1 data + `00` |
| 6 | (Optionally) Generate AC #2 | `80AE40002B...` |

### 2. Floor-Limit Bypass Probe

Goal: Observe terminal handling of crafted *below-floor* vs *just-above-floor* amounts and TVR bit setting.

Crafted GPO (PDOL includes amount + terminal country + transaction date):

```text
80 A8 00 00 0B 83 09 00 00 00 50 00 00 12 34 01 00
```

- Amount Authorized (Tag 9F02) = 00 00 00 50 00 (0.50) – deliberately tiny
- Terminal Country (9F1A) = 0x1234
- Transaction Date (9A) = YYMMDD (example 01 00 ?? placeholder)

Variant just over floor (simulate threshold crossing):

```text
80 A8 00 00 0B 83 09 00 00 01 F5 00 00 12 34 01 00   # Amount ~ 5.00
```

Compare TVR bits (especially byte 1 bit 8 – Offline data authentication not performed; byte 4 floor limit related) between both runs.

### 3. CVM Downgrade / CVM List Manipulation

When accessible (records containing CVM list Tag 8E), attempt to present a modified record (in a controlled lab card or emulator) where PIN methods are absent or replaced with signature/no CVM precedence.

Sample CVM List (8E) emphasizing signature then no CVM:

```text
8E 0E 1F 02 02 02 1E 03 03 03 1F 03 1F 03
```

If using a custom applet, respond to READ RECORD with altered 8E and observe terminal acceptance vs fallback prompts.

### 4. Rapid Reversal / Dual Authorization Timing (Logical Simulation)

While not pure APDU, you can emulate an early reversal scenario by:

1. Issuing first GENERATE AC (ARQC) normally.
2. Introducing an artificial delay + returning a second GENERATE AC with inconsistent ATC (if emulator controls it).
3. Observe terminal logging / error handling (some terminals mishandle ATC regression or rapid successive ARQCs).

### 5. Unexpected SW Pattern Injection

Return non-standard but syntactically valid SW patterns in response to specific APDUs to test terminal error handling and recovery.

Example Sequence:

```text
00A404000E325041592E5359532E444446303100
00A4040007A0000000031010
80A8000002830000
80CA9F1700
80AE80002B0000000000000000000000000000000000000000000000000000000000000000
```

### JavaCard Test Applet Skeleton (Merchant TVR / CVM Probe)

`(Illustrative – place under applets/ and build with ant-javacard)`

```java
package merchantvuln;
import javacard.framework.*;
public class MerchantVulnTester extends Applet {
  private static final byte[] SELECT_OK = {(byte)0x90,0x00};
  private short atc = 0;
  public static void install(byte[] bArray, short bOffset, byte bLength){ new MerchantVulnTester().register(); }
  public void process(APDU apdu){
    byte[] buf = apdu.getBuffer();
    if(selectingApplet()) { Util.arrayCopyNonAtomic(SELECT_OK,(short)0,buf,(short)0,(short)2); apdu.setOutgoingAndSend((short)0,(short)2); return; }
    // GENERATE AC (80 AE) – fabricate TVR/CVM anomalies inside response template (simplified)
    if(buf[ISO7816.OFFSET_CLA]==(byte)0x80 && buf[ISO7816.OFFSET_INS]==(byte)0xAE){
       atc++; // Intentional monotonic counter – could manipulate for tests
       short le = 0;
       // Minimal TLV: 9F36(ATC), 9F27(CID), 9F10(IAD truncated) + SW
       buf[0]=(byte)0x9F; buf[1]=0x36; buf[2]=0x02; buf[3]=(byte)(atc>>8); buf[4]=(byte)atc;
       buf[5]=(byte)0x9F; buf[6]=0x27; buf[7]=0x01; buf[8]=(byte)0x80; // Force TC vs ARQC change
       buf[9]=(byte)0x9F; buf[10]=0x10; buf[11]=0x04; buf[12]=0xE0; buf[13]=0x00; buf[14]=0x00; buf[15]=0x00; // Simplified IAD
       // Append custom SW like 0x9000
       buf[16]=(byte)0x90; buf[17]=0x00;
       apdu.setOutgoingAndSend((short)0,(short)18);
       return;
    }
    // Default SW: Instruction not supported
    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
  }
}
```

Compile & Install (example flow):

```bash
# (Adjust AID / package / applet as needed for your lab environment)
java -jar ant-javacard.jar -noverify -cap merchantvuln.cap -out build/ ./src/merchantvuln/
java -jar gp.jar -install merchantvuln.cap -force
```

> NOTE: The above applet intentionally simplifies EMV data objects; it is not standards-complete. Augment with full CDOL parsing if you need precise terminal reactions.

### Safety & Ethics

- Keep things in-bounds with local rules and whatever agreements you’re working under.
- Log runs if it helps your workflow; no pressure to archive everything forever.
- Handle PAN or track data the way your team is comfortable—mask, trim, or toss as needed.
- Do **not** persist PAN / track data beyond scope requirements.

{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "java",
      "request": "launch",
      "name": "Launch Java Program",
      "mainClass": "${input:mainClass}",
      "projectName": "${input:projectName}"
    }
  ],
  "inputs": [
    {
      "id": "mainClass",
      "type": "promptString",
      "description": "Enter the fully qualified main class to launch (e.g. com.greenwire.Main)"
    },
    {
      "id": "projectName",
      "type": "promptString",
      "description": "Enter the Java project name that contains the main class"
    }
  ]
}
