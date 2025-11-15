# GREENWIRE Project Analysis & Integration Plan

**Version:** 4.0
**Date:** 2025-07-23

## 1. Overview

This document provides a comprehensive analysis of the GREENWIRE repository, focusing on unifying its components under the modern CLI (`greenwire_modern.py`), mapping dependencies, and outlining a clear, modular architecture.

The project has a significant amount of functionality across JavaCard applet production, RFID vulnerability testing, and a legacy CLI. The primary goal of this refactoring is to consolidate these features into a single, maintainable, and extensible user interface.

## 2. Core Architecture

The refactored architecture is designed around the `greenwire_modern.py` CLI, which acts as the central dispatcher. Core logic is encapsulated in modules, and a new `commands` directory serves as a bridge to expose this logic to the CLI.

```text
GREENWIRE/
├── greenwire_modern.py       # Main CLI Entry Point
|
├── commands/                 # Bridge between CLI and core logic
│   ├── __init__.py
│   ├── cap_management.py     # Wraps CapletProductionSystem
│   └── rfid_testing.py       # Wraps RFIDVulnerabilityTester
|
└── modules/                  # Core business logic
    ├── caplet_production_system.py
    └── rfid_vulnerability_tester.py
    ... (other modules)
```

## 3. Dependency Map

### Python Dependencies (from `requirements.txt`)

- `pyscard`: For PC/SC smart card communication.
- `pycryptodome`: Cryptographic operations.
- `nfcpy`: For NFC communication (optional, used in some modules).
- `pyyaml`: For YAML output format in the CLI.
- `requests`: For potential network operations (e.g., key harvesting).
- `cryptography`: Core cryptographic library.

### Java/Build Dependencies (for CAP file production)

- **JDK (Java Development Kit)**: Required to compile Java source code.
- **Gradle**: The build system used for compiling applets and creating CAP files.
- **JavaCard SDK**: Contains the necessary APIs (`api_classic.jar`) and converter (`tools.jar`) to produce CAP files. Expected to be in the `sdk/` directory.
- **GlobalPlatformPro**: Used for deploying CAP files to physical cards. The `.jar` is expected in the `lib/` directory.

### Internal Module Dependencies

- `greenwire_modern.py` depends on modules within the `commands/` directory.
- `commands/*.py` modules depend on the logic within the `modules/` directory.
- `modules/caplet_production_system.py` depends on the Gradle wrapper (`gradlew.bat`) and the JavaCard SDK.
- `modules/rfid_vulnerability_tester.py` depends on the `nfcpy` library for hardware interaction.

## 4. Identified Issues & Resolutions

### Issue 1: Disconnected CLI from Core Logic

The `greenwire_modern.py` CLI was designed to be modular but lacked the "glue" code to connect to the `CapletProductionSystem` and `RFIDVulnerabilityTester` modules. It was attempting to import from a non-existent `commands` directory.

**Resolution:**

1. Created the `commands/` directory.
2. Implemented `commands/cap_management.py` to expose `CapletProductionSystem` functionality.
3. Implemented `commands/rfid_testing.py` to expose `RFIDVulnerabilityTester` functionality.
4. Updated `greenwire_modern.py` to correctly load, parse arguments for, and execute these commands.

### Issue 2: Argument Parsing for Sub-commands

The CLI parser was not configured to handle sub-commands and their arguments for the new modules (e.g., `rfid-test all`).

**Resolution:**

- Modified the `_execute_command` method in `greenwire_modern.py` to correctly pass arguments to the command wrappers.
- The command wrappers in the `commands/` directory now parse these arguments and call the underlying modules with the correct parameters.

## 5. Optimization & UI Perspective

From a "single UI perspective," all core functionalities are now accessible via `greenwire_modern.py`.

### Example Usage (Post-Refactor)

**RFID Vulnerability Testing:**

```bash
# Run all RFID vulnerability tests
python greenwire_modern.py rfid-test all
```

**CAP File Production:**

```bash
# Produce all caplet variants
python greenwire_modern.py cap produce-all

# Deploy a specific caplet
python greenwire_modern.py cap deploy --cap-file "path/to/your.cap"
```

This structure makes the tool intuitive. The user interacts with a single CLI, and the underlying complexity is abstracted away.

## 6. Next Steps

1. **Expand Commands**: Add more commands to the `commands` directory to expose other features (e.g., fuzzing, emulation) through the modern CLI.
2. **Configuration**: Integrate a centralized configuration system (e.g., `config.yaml`) that can be used by both the CLI and the underlying modules to manage settings like SDK paths, default timeouts, etc.
3. **Issuer Pipeline**: Implement the multithreaded HSM → Issuer → Personalization → Merchant → Transaction services described in `docs/ARCHITECTURE_V5_MULTITHREADED.md`, and expose them through the modern CLI.
4. **Testing**: Develop a comprehensive test suite that covers:
    - Unit tests for each command in the `commands/` directory.
    - Integration tests that run CLI commands and verify the output.
    - Mocking of hardware dependencies (like `pyscard` and `nfcpy`) to allow for testing in CI environments.
    - Emulator vs hardware parity tests for the new issuer pipeline.

---
