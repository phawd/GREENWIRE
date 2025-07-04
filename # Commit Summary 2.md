# Commit Summary

> Generated by Gemini 2.0 Flash

## Add EMV test framework with attack scenarios and vulnerability correlation (f1f3580)

Add EMV test framework with attack scenarios and vulnerability correlation.

This commit introduces a Python-based EMV test framework (`greenwire/core/fuzzer.py`) that simulates attack scenarios against EMV cards. It includes vulnerability detection and correlation capabilities, along with logging and database functionalities for tracking test results.

### Changes
- Created `greenwire/core/fuzzer.py`, a new file containing the EMV test framework.
- Implemented attack scenario simulations (e.g., SDA downgrade, PIN bypass) based on EMV standards.
- Integrated vulnerability detection and correlation logic to identify related weaknesses.
- Added database (SQLite) support for logging commands, vulnerabilities, keys, and timing analysis.
- Configured detailed logging with multiple handlers for different data types (vulnerabilities, keys, timing).
- Updated `README.md` to include usage examples for the Python CLI.

### Impact
- Introduces a new testing capability for EMV card security.
- Adds dependencies on smartcard, database, and logging libraries.
- Provides a framework for simulating attacks and identifying vulnerabilities, but requires configuration and tuning for specific environments.
- The database component will create a file named `greenwire.db` in the current directory.