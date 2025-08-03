# GREENWIRE: Advanced Smart Card .cap File Research and EMV Tool

## Dependencies
- Python 3.8+
- argparse (standard library)
- logging (standard library)
- subprocess (standard library)
- os, time, random, hashlib, secrets, json, string (standard library)

## CLI Overview

This tool provides a unified CLI for advanced .cap file research, EMV compliance, fuzzing, logging, replay, and operator feedback. It supports multiple .cap categories, each with unique evasion, compliance, or research features. All major card brands (Visa, Mastercard, Amex) are supported for EMV AIDs.

### CLI Subcommands

- `supertouch`: Run SUPERTOUCH fuzzing and brute force
- `jcalgtest`: Run JCAlgTest simulation
- `integration`: Run JCOP integration tests
- `supporttable`: Run SupportTable integration
- `jcop`: Run JCOP manager (cap gen/test/dump)
- `emulator`: Run ISO/EMV emulator
- `crypto`: Run cryptographic verification
- `issuance`: Simulate card issuance
- `self-test`: Run a basic self-test of all major features
- `dump-log`: Dump .cap communication log
- `simulate-positive`: Simulate positive transaction results for a .cap file
- `export-replay`: Export APDU replay log for a .cap file
- `import-replay`: Import APDU replay log for a .cap file
- `dump-suspicious`: Dump suspicious events for a .cap file
- `learn-session`: Update replay/suspicious logs after a positive session
- `seal-logs`: Seal reserved log area in .cap with hash/signature
- `identitycrisis`: Enable IdentityCrisis mode: random AID for each transaction, with optional smackdown mode
- `stealth`: Stealth .cap: EMV compliant, minimal logging, random delays
- `replay`: Replay .cap: EMV compliant, record/replay APDU/response pairs
- `decoy`: Decoy .cap: EMV compliant, multiple applets (one real, others decoy)
- `audit`: Audit .cap: EMV compliant, logs all APDUs, only Visa/Mastercard/Amex AIDs

## Function Documentation

All major classes and functions in `greenwire.py` are documented inline with docstrings. See the top of each class/function for detailed descriptions, arguments, and return values.

- `CapFileLogger`: Handles all logging, suspicious event tracking, and log persistence for .cap file operations. Logs are stored in the .cap file (appended as JSON lines for demo purposes).
- `GreenwireSuperTouch`: Fuzzes, brute-forces, and attempts key extraction on a .cap file using simulated APDU commands.
- `GreenwireJCAlgTest`: Simulates JCAlgTest operations and logs results.
- `GreenwireIntegration`: Integrates JCOP functions and runs all tests.
- `GreenwireSupportTableIntegration`: Integrates SupportTable and compares supported algorithms.
- `GreenwireJCOPManager`: Manages JCOP functionality, including generating and testing CAP files, retrieving CAP file information, and providing operator feedback.
- `GreenwireEmulator`: Simulates various terminal environments and runs emulations based on ISO specifications.
- `GreenwireCrypto`: Handles cryptographic operations and verification to ensure that the underlying crypto functions are working before attempting DDA or encryption.
- `GreenwireCardIssuance`: Simulates a standard card issuance process, including generating LUNs and using major card BINs for personalization.

## Testing

Each CLI function can be tested by running:

```
python greenwire.py <subcommand> [options]
```

Example:
```
python greenwire.py stealth --cap-file test_stealth.cap
python greenwire.py replay --cap-file test_replay.cap
python greenwire.py decoy --cap-file test_decoy.cap
python greenwire.py audit --cap-file test_audit.cap
python greenwire.py identitycrisis --cap-file test_identitycrisis.cap --smackdown
```

## Linting

To lint the code, run:
```
python -m pylint greenwire.py --disable=R,C
```

## Notes
- All AIDs for EMV operations are Visa, Mastercard, or Amex compliant where required.
- All .cap categories are EMV compliant except for fuzzing/research.
- See inline docstrings for further technical details.
