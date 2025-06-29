# Operation Greenwire — Swiss army knife of (Not)smartcards and related technologies

**Mission:** Empower ethical, open research into these hidden open source technologies.

**License:** GPL v3

**Dedication:** To MOORE, 101st Airborne, trained Green Beret (1967, Dac To, Silver Star recipient), and all who stand for freedom.


### Python Unified CLI: greenwire.py

`greenwire.py` is a unified command-line tool for both EMV card issuing and SMS PDU building. It wraps the Python EMV issuer and the Perl SMS CLI.
Additional features and programs will be added over time.

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
  filefuzz     Fuzz file parsers (images, binaries, unusual text)

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
- Generate sample EMV cards for testing purposes
  - Each card includes a unique 256-bit encryption key
- Perform basic contactless EMV transactions via `--nfc-action` flags
- Handle contactless terminal mode with multiple AIDs and configurable CA keys
- Fuzz contactless transactions with `--contactless-fuzz`
- Use an Android phone via ADB for contactless and EMV operations or an
  Android 13+ emulator

### Using an Android phone
An Android device can serve as the NFC reader when connected via USB with ADB debugging enabled. Make sure the Android SDK tools are installed and the device is authorized. Invoke the CLI with `--reader android` or choose **Android NFC** in the interactive menu.

If you do not have physical hardware, you can use the Android emulator.
Create an Android 13+ virtual device with the SDK tools and start it
with ADB networking enabled. The `AndroidReaderWriter` class will detect
the emulator via the `adb` command.

```bash
python3 greenwire-brute.py --emulate terminal --reader android
```


### Usage

- To emulate a terminal/ATM:
```bash
python3 greenwire-brute.py \
  --emulate terminal \
  --emv-transaction \
  --emv-aids A0000000031010,A0000000041010 \
  --ca-file ca_keys.json \
  --issuer "Test Bank"
```
The CA key file is a JSON array of objects with `rid`, `index`, `modulus`, and
`exponent` fields used for offline data authentication.
- To emulate a card (NFC/EMV):
  ```bash
  python3 greenwire-brute.py --emulate card
  ```
- To generate a test card:
  ```bash
  python3 -m greenwire.core.emv_generator --issuer "Test Bank"
  ```

Generated cards include a unique 256-bit encryption key alongside the PAN and other details.

Terminal emulation supports Dynamic Data Authentication (DDA) and can operate in wireless/contactless mode when requested.

See CLI help (`-h`) for all options.

## HSM/ATM Emulator

GREENWIRE ships with a lightweight HSM emulator inspired by modern
Thales and Futurex devices. The `HSMEmulator` class can generate a
signed EMV applet for testing terminal flows without physical HSM
hardware:

```python
from greenwire import HSMEmulator

hsm = HSMEmulator(issuer="Demo Bank")
applet = hsm.generate_e_applet()
print(applet.card)
```

The returned `EMVApplet` contains the generated card data, the RSA
public modulus, and a signature that proves authenticity of the card
details.

## Contact vs Contactless Cards

Traditional **contact** smartcards follow the ISO 7816 specification and
exchange APDUs over a physical interface. They must be inserted into a reader
where electrical contacts power the chip and facilitate secure data transfer.

**Contactless** cards communicate wirelessly using short-range radio
frequencies, typically ISO 14443. They draw power from the radio field and can
be used for quick "tap" payments. GREENWIRE supports both modes. Terminal
emulation can issue commands over NFC when the `--wireless` flag is passed and
the appropriate reader hardware is available, while the default behavior
assumes a contact interface.

#### Notes
- Place your Perl modules and `greenwire-cli.pl` in the same directory or adjust the path.
- For Google Drive upload, ensure `service-account.json` is present.
- All EMV and SMS logic is unified in `greenwire.py` for convenience.

### Interactive Menu

The `greenwire.menu_cli` module offers a verbose interactive interface
with more than twenty options for fuzzing, scanning and dumping cards.
It now also includes a file parser fuzzer for images and binaries.
Invoke it via:

```bash
python -m greenwire.menu_cli
```

## Supported Standards

The project aims to cover a wide range of card and NFC specifications. The
`Standard` enumeration in `greenwire.core.standards` lists the currently handled
standards:

- ISO/IEC 7810
- ISO/IEC 7816 (including T=0/T=1, ISO 7816-3)
- EMV
- GlobalPlatform
- GlobalPlatform Issuer
- GlobalPlatform Cardholder
- Card OS
- ICAO 9303
- ISO/IEC 18000-x
- ISO/IEC 15693
- EPCglobal
- ISO/IEC 29167
- ISO 14443
- ISO 18092
- NDEF
- LLCP
- RTD
- SNEP

These constants serve as placeholders for future implementations that will
process commands according to each standard. The accompanying
`StandardHandler` class exposes a `check_compliance()` method that returns a
simple confirmation string for any supported standard, ensuring GlobalPlatform
issuer and cardholder requirements as well as Card OS rules are tracked.

## Development and Testing

Install the test dependencies (including `pexpect`) and run the unit test
suite to verify functionality:

```bash
pip install -r requirements.txt
pytest -q
```

Running `python -m py_compile $(git ls-files '*.py')` helps ensure all Python
modules are syntactically valid.
