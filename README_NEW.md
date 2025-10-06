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

### 2. Run the interactive menu
```bash
python greenwire.py --menu
```

### 3. Run a subcommand
```bash
python greenwire.py easycard generate random --count 1
python greenwire.py probe-hardware --auto-init
python greenwire.py apdu-fuzz --target emv --iterations 500
```

### 4. Build JavaCard applet (offline)
```powershell
cd javacard/applet
./gradlew convertCap
```

### 5. Create static bundle (no Python required on target)
```bash
python tools/create_static_bundle.py
```

---

## Architecture & Key Components

- **Entry point:** `greenwire.py` (CLI, menu, subcommand dispatcher)
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
