# Operation Greenwire — Swiss army knife of (Not)smartcards and related technologies

**Mission:** Empower ethical, open research into these hidden open source technologies.

**License:** GPL v3

**Dedication:** To MOORE, 101st Airborne, trained Green Beret (1967, Dac To, Silver Star recipient), and all who stand for freedom.



# GREENWIRE: Swiss Army Knife for Smartcard, EMV, JCOP, and .cap File Research

**Mission:** Empower ethical, open research and field testing of smartcard, EMV, and NFC/JCOP technologies.

**License:** GPL v3

**Dedication:** To MOORE, 101st Airborne, trained Green Beret (1967, Dac To, Silver Star recipient), and all who stand for freedom.

---

## Unified CLI: `greenwire.py`

`greenwire.py` is the main command-line tool for EMV card issuing, smartcard fuzzing, JCOP/JavaCard management, logging, replay, and field/production testing. It supports both research and real-world/field use, with robust CA certificate/key support for EMV/terminal emulation and card issuance.

### Key Features
- Modular CLI for card generation, fuzzing, simulation, and hardware/CSV output
- Realistic HSM/terminal simulation (PCSC, NFC, HSM profiles)
- Robust logging, operator feedback, and cryptographic verification
- EMV/JCOP/ISO 7816/JavaCard support
- CA certificate/key support for EMV/field testing

---

## CLI Subcommands & Usage

Run:
```bash
python greenwire.py <subcommand> [options]
```

### Major Subcommands

- `supertouch`     : Fuzzing, brute force, and key extraction (with `--csv-output`, `--hardware`)
- `jcalgtest`      : JCAlgTest simulation
- `integration`    : JCOP integration tests
- `supporttable`   : SupportTable integration
- `jcop`           : JCOP manager (cap gen/test/dump)
- `emulator`       : ISO/EMV emulator (with `--profile`, `--hardware`)
- `crypto`         : Cryptographic verification
- `issuance`       : Simulate card issuance (with `--csv-output`, `--hardware`, `--profile`, `--ca-file`)
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

**Example: Card Issuance with Custom CA Key**
```bash
python greenwire.py issuance --csv-output cards.csv --hardware --profile pcsc --ca-file ca_keys.json
```

**Example: Install .cap File with Custom AID and CA Cert**
```bash
python greenwire.py install-cap --cap-file myapplet.cap --tool gpp --aid A0000000031010 --ca-file ca_keys.json
```

**To validate a CA key/cert:**
- Check that the `rid` and `index` match the card/AID you are working with.
- Use the `issuance` or `emulator` subcommands with your CA file and verify successful operation/log output.

---

## Example CLI Usage

**Fuzzing and Brute Force:**
```bash
python greenwire.py supertouch --cap-files mytest.cap --csv-output results.csv
```

**JCAlgTest Simulation:**
```bash
python greenwire.py jcalgtest --cap-files mytest.cap
```

**Emulator with Hardware Profile:**
```bash
python greenwire.py emulator --cap-file mytest.cap --profile nfc --hardware
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

## Simple Menu Interface

For quick experiments, run the lightweight menu-based wrapper:

```bash
python menu_cli.py
```

This script offers an interactive menu for common tasks built on top of the main `greenwire` toolkit.

---

## Field/Production Notes

- For field testing, always use the `--hardware` and `--profile` options to select the correct terminal/HSM profile (e.g., `pcsc`, `nfc`, `hsm`).
- Ensure your CA key/cert is valid and present in `ca_keys.json` for EMV/issuance operations.
- Use the `--csv-output` option to log results for compliance and audit.
- For contactless/NFC operations, ensure `nfcpy` and compatible hardware are installed.
- For Android-based NFC, connect your device via ADB and use the appropriate profile.

---

## Troubleshooting & FAQ

**Q: My card issuance fails with a CA key error.**
A: Check that your CA key/cert in `ca_keys.json` matches the card/AID. Ensure the modulus and exponent are correct and the file is valid JSON.

**Q: Hardware not detected?**
A: Ensure your PCSC/NFC reader is connected and drivers are installed. For Android, check ADB connection.

**Q: How do I add a new CA key/cert?**
A: Edit `ca_keys.json` and add a new object with the correct `rid`, `index`, `modulus`, and `exponent`.

**Q: How do I verify my CA key is being used?**
A: Run `issuance` or `emulator` with `--ca-file` and check the logs/output for your CA key details.

---

## Supported Standards

- ISO/IEC 7810, 7816, 14443, 18092
- EMV, GlobalPlatform, Card OS, ICAO 9303, NDEF, SNEP, etc.

---

## Development, Testing, and Linting

Install dependencies and run tests:
```bash
pip install -r requirements.txt
pytest -q
```

Lint the code:
```bash
python -m pylint greenwire.py --disable=R,C
```

---

## See Also

- `README_DETAILED.md` for full CLI/subcommand documentation and advanced examples
- `APPLET_OVERVIEW.md` for JavaCard/JCOP applet management and field install
- `setup_instructions.md` for setup and environment details
- `SECURITY.md` for security policy and CA key/cert handling
