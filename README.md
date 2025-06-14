# Operation Greenwire — Swiss army knife of (Not)smartcards and related technologies

**Mission:** Empower ethical, open research into these hidden open source technologies.

**License:** GPL v3

**Dedication:** To MOORE, 101st Airborne, trained Green Beret (1967, Dac To, Silver Star recipient), and all who stand for freedom.

---
I ditched the perl version for python, for now.
---

### Python Unified CLI: greenwire.py

`greenwire.py` is a unified command-line tool for both EMV card issuing and SMS PDU building. It wraps the Python EMV issuer and the Perl SMS CLI.
There will be other features and programs added. 

GREENWIRE CLI Interface

Advanced EMV and smartcard security testing tool implementing EMVCo specified
attack methodologies and industry standard test requirements.

Attack Capabilities:
- Timing Analysis (EMVCo Book 4 §2.4)
  - PIN verification timing
  - Cryptographic operation analysis
  - Memory access patterns
  
- Power Analysis (EMVCo CAST §5.4)  
  - Simple Power Analysis (SPA)
  - Differential Power Analysis (DPA)
  - Correlation Power Analysis (CPA)
  
- Clock Glitch (EMVCo CAST §4.2)
  - Instruction skip attacks
  - Data corruption
  - Crypto fault injection
  
- Combined Channel Attacks
  - Timing + power analysis
  - Protocol + timing vulnerabilities
  - Cross-interface attacks

Standards Compliance:
- EMVCo Books 1-4
- Mastercard CQM
- Visa PTP 
- Amex AEIPS
- NIST FIPS 140-3
- Common Criteria EAL4+

Usage:
  greenwire-brute.py [options] --mode <mode> [--type <type>] [--count N]

Modes:
  standard     Basic EMV protocol testing
  simulate     Transaction simulation with fuzzing
  fuzz         Dedicated fuzzing mode
  readfuzz     Focus on READ RECORD fuzzing
  extractkeys  Extract and analyze keys
  generatekeys Generate EMV key hierarchy (SDA/DDA)

Attack Options:
  --mode MODE           Testing mode (required)
  --type TYPE           Card type (visa,mc,amex,etc)
  --count N             Number of iterations
  --auth AUTH           Authentication (pin,sig)
  --fuzz FUZZ           Fuzzing strategy

Analysis Options:
  --timing              Enable timing analysis
  --power               Enable power analysis
  --glitch              Enable glitch detection
  --combined            Test combined attacks

Output Options:
  --verbose             Enable detailed logging
  --silent              Suppress non-error output
  --export FILE         Export results to JSON file

CVM Processing:
  The tool supports detailed Cardholder Verification Method (CVM) processing, including:
    - Signature verification (simulated)
    - Plaintext PIN verification by ICC
    - Enciphered PIN verification by ICC
  When running in modes that test CVM, the tool will:
    - Set the CVM list on the card (if supported)
    - Simulate a signature-based transaction
    - Simulate PIN verification (plaintext and enciphered)
    - Output the result of each CVM method to the operator

Examples:
  # Standard protocol test with verbose output
  python greenwire-brute.py --mode standard --type visa --verbose

  # Fuzzing with PIN authentication and export results
  python greenwire-brute.py --mode fuzz --auth pin --export results.json

  # Run detailed CVM processing and see operator output
  python greenwire-brute.py --mode simulate --auth sig --verbose
  --verbose            Enable detailed logging
  --silent             Suppress non-error output
  --export FILE        Export results to JSON
"""

## EMV/NFC Terminal/ATM and Card Emulation

GREENWIRE can now:
- Emulate an EMV/NFC terminal/ATM (send APDUs as a terminal, simulate full EMV transactions)
- Emulate an EMV/NFC card (hardware and platform dependent, requires nfcpy and compatible reader)

### Usage

- To emulate a terminal/ATM:
  ```bash
  python3 greenwire-brute.py --emulate terminal --emv-transaction --emv-aid A0000000031010
  ```
- To emulate a card (NFC/EMV):
  ```bash
  python3 greenwire-brute.py --emulate card
  ```

See CLI help (`-h`) for all options.

#### Notes
- Place your Perl modules and `greenwire-cli.pl` in the same directory or adjust the path.
- For Google Drive upload, ensure `service-account.json` is present.
- All EMV and SMS logic is unified in `greenwire.py` for convenience.
