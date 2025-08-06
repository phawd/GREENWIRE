
# GREENWIRE: Advanced Smart Card, EMV, and .cap File Research Tool — Detailed CLI & Field Guide

## Dependencies

- Python 3.8+
- argparse, logging, subprocess, os, time, random, hashlib, secrets, json, string (stdlib)
- pyscard, nfcpy, cryptography, pexpect, pillow

---

## CLI Subcommands — Detailed Reference

Each subcommand is designed for both research and field/production use. All support robust logging, operator feedback, and (where relevant) CA certificate/key integration for EMV/field testing.

### `supertouch`
Fuzzes, brute-forces, and attempts key extraction on a .cap file using simulated APDU commands.

**Example:**
```bash
python greenwire.py supertouch --cap-files mytest.cap --csv-output results.csv --hardware
```

### `jcalgtest`
Runs JCAlgTest simulation for JavaCard/JCOP applets.

**Example:**
```bash
python greenwire.py jcalgtest --cap-files mytest.cap
```

### `integration`
Runs JCOP integration tests (fuzzing, cap management, etc).

### `supporttable`
Runs SupportTable integration and algorithm comparison.

### `jcop`
JCOP manager: generate/test/dump cap files, retrieve info, operator feedback.

**Example:**
```bash
python greenwire.py jcop --cap-files mytest.cap --dump
```

### `emulator`
Runs ISO/EMV emulator. Supports hardware/NFC/PCSC profiles and CA key/cert.

**Example:**
```bash
python greenwire.py emulator --cap-file mytest.cap --profile nfc --hardware --ca-file ca_keys.json
```

### `crypto`
Runs cryptographic verification (DDA, challenge/response, etc).

### `issuance`
Simulates card issuance, including LUN/BIN personalization and CA key/cert for EMV/field use.

**Example:**
```bash
python greenwire.py issuance --csv-output cards.csv --hardware --profile pcsc --ca-file ca_keys.json
```

### `self-test`
Runs a full self-test of all major features and logs results.

### `dump-log`, `simulate-positive`, `export-replay`, `import-replay`, `dump-suspicious`, `learn-session`, `seal-logs`
Advanced .cap file logging, replay, suspicious event tracking, and log sealing for compliance/field audit.

### `identitycrisis`, `stealth`, `replay`, `decoy`, `audit`
Special .cap categories for advanced EMV compliance, evasion, and field/production scenarios.

### `install-cap`
Install a .cap file on a smart card using GlobalPlatformPro or OpenSC. Supports custom AID and CA key/cert.

**Example:**
```bash
python greenwire.py install-cap --cap-file myapplet.cap --tool gpp --aid A0000000031010 --ca-file ca_keys.json
```

---

## CA Certificate/Key Usage & Validation

- The CA key file (`ca_keys.json`) is a JSON array of objects with `rid`, `index`, `modulus`, and `exponent` fields.
- For field/production use, ensure your CA key/cert matches the card/AID and is referenced with `--ca-file`.
- To add a new CA key/cert, append a new object to `ca_keys.json`.
- To validate, run `issuance` or `emulator` with your CA file and check logs/output for your CA key details.

**Example CA key entry:**
```json
{
	"rid": "A000000003",
	"index": "92",
	"modulus": "...",
	"exponent": "03"
}
```

---

## Field/Production Notes

- Always use `--hardware` and `--profile` for real-world/field testing.
- Use `--ca-file` for EMV/issuance operations requiring CA key/cert.
- Use `--csv-output` for compliance/audit logging.
- For contactless/NFC, ensure `nfcpy` and compatible hardware are installed.
- For Android NFC, connect via ADB and use the correct profile.

---

## Testing & Linting

Run all tests:
```bash
pytest -q
```

Lint the code:
```bash
python -m pylint greenwire.py --disable=R,C
```

---

## Advanced Examples

**Card Issuance with Custom CA Key:**
```bash
python greenwire.py issuance --csv-output cards.csv --hardware --profile pcsc --ca-file ca_keys.json
```

**Install .cap File with Custom AID and CA Cert:**
```bash
python greenwire.py install-cap --cap-file myapplet.cap --tool gpp --aid A0000000031010 --ca-file ca_keys.json
```

**Replay Mode:**
```bash
python greenwire.py replay --cap-file mytest.cap
```

**Audit Mode:**
```bash
python greenwire.py audit --cap-file mytest.cap
```

---

## Notes

- All AIDs for EMV operations are Visa, Mastercard, or Amex compliant where required.
- All .cap categories are EMV compliant except for fuzzing/research.
- See inline docstrings and this file for further technical details.
