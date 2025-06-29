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
  Android 13+ emulator. Root access (via ``adb root``) enables additional
  commands; a non-root fallback is also available.

### Using an Android phone
An Android device can serve as the NFC reader when connected via USB with ADB debugging enabled. Make sure the Android SDK tools are installed and the device is authorized. Invoke the CLI with `--reader android` or choose **Android NFC** in the interactive menu.

If you do not have physical hardware, you can use the Android emulator.
Create an Android 13+ virtual device with the SDK tools and start it
with ADB networking enabled. The `AndroidReaderWriter` class will detect
the emulator via the `adb` command.

The interactive menu now provides options to connect to an Android device
with or without root access. Select **Android connect (root)** for rooted
devices or **Android connect (non-root)** when root is unavailable.

### Advanced Fuzzing and HSM Support
GREENWIRE includes experimental attack modes for JCOP card OS fuzzing and
cryptographic HSM operations. NFC delay attacks simulate timing issues in
contactless environments. These features are available via the interactive
menu and tree menu under *General Card Ops*.
The utility function `generate_sle_sda_certificate()` creates a placeholder
SLE SDA certificate for each generated card.
The new `GreenProbeApplet` module provides a simulated card applet that
actively probes any connected terminal using basic EMV commands. The applet
records the terminal identifier and whether the probe succeeded in an internal
transaction log, demonstrating how a real JCOP applet might track terminal
interactions. Once a terminal type is detected, ``fuzz_after_identification``
can generate HSM-backed keys (using the crypto engine) and send mutated APDUs,
logging the outcomes directly on the card.
The ``attack_terminal`` method extends this by running a full sequence of ATM
commands when an ATM is detected. Otherwise it rapidly loops through standard
APDUs for fifty cycles and then issues ``GENERATE_AC`` for fifty additional
cycles before attempting a simple transaction. The results are logged on the
card for later analysis.

### Supported Hardware
GREENWIRE works with most PC/SC readers including **ACR122U**, **PN532**,
and any Android 13+ phone running the helper service over ADB. Emulator
usage is supported through the Android SDK. Ensure ``adb`` is installed
and the device or emulator is authorized for USB debugging.

### Smart Card Manufacturing Overview

Smartcards typically embed a silicon chip into a plastic card body.  For
contact cards, the chip is bonded to gold-plated pads that provide power
and data over the ISO 7816 interface.  Contactless cards laminate a small
antenna coil around the chip so it can draw power from an RF field.  A
final lamination step fuses printed layers and overlays with security
features like holograms.

For contactless cards such as MIFARE Classic, DESFire, FeliCa, or EMV
dual-interface cards, the antenna geometry and chip type vary.  DESFire
cards typically include larger EEPROM for keys and application data,
while EMV dual-interface cards integrate both contact pads and an RF
antenna in a thin module.

### Card Types and Standards

| Type | Standard | Compatibility | Common Uses | Security Notes |
|------|----------|---------------|-------------|----------------|
| **Magstripe** | ISO 7810, ISO 7811 | Works with legacy swipe readers | Early banking, access control | Minimal security, data easily copied |
| **Contact Smartcard** | ISO 7816 | Works with PC/SC readers, ATMs | Banking, SIM, ID | Chip-based security with tamper‑resistant silicon |
| **Contactless (MIFARE)** | ISO 14443 Type A | Compatible with NFC readers | Transit passes, access control | Varies by model (Classic vs DESFire) |
| **Contactless (FeliCa)** | JIS X 6319-4 | Mainly in Japan & Asia | Transit, e-money | Uses its own cryptographic protocol |
| **EMV Dual Interface** | ISO 7816 + ISO 14443 | Works in contact and contactless terminals | Modern payment cards | Supports SDA/DDA, PIN verification |
| **NFC Tags** | ISO 14443/15693 | Broad NFC device support | Inventory, tap-to-launch | Often lacks cryptographic security |

Different card families offer varying memory sizes, crypto algorithms,
and reader compatibility.  Greenwire aims to handle these standards via
its menu-driven CLI and tree menu.

### EMV Card Brands and History

While most current payment cards comply with the EMV specifications,
their underlying operating systems and silicon chips come from different
manufacturers.  Early EMV deployments in the late 1990s relied on
simple "SDA" cards manufactured by **Gemplus** and **Schlumberger**. By
the mid‑2000s dynamic data authentication ("DDA") was introduced with
platforms such as **JCOP** from **NXP** (formerly Philips) and **CardOS**
from **Siemens/Infineon**.  Modern cards generally implement combined
dynamic authentication ("CDA") and often support both contact and
contactless interfaces in a single module.

Major chip families include **Infineon SLE66**, **NXP SmartMX**, and
**STMicroelectronics ST23/ST25**.  The antennas used in dual‑interface
cards may be a thin etched copper coil around the module or a printed
inductive loop laminated into the body.  Contactless terminals typically
use a larger loop antenna connected to an NFC controller such as the
PN532 or a secure POS module.

SDA‑only cards were largely phased out around 2015.  DDA and CDA models
continue to be issued today, with most banks migrating to contactless
dual‑interface cards after 2017.

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
Each run of the interactive menus automatically issues 5-10 sample cards and
prints their details. These cards include a placeholder SLE SDA certificate so
they can be written to either contactless or contact test hardware.

To generate a placeholder JCOP or CardOS applet for testing:
```bash
python3 -m greenwire.core.applet_generator --os JCOP --output sample.cap
```

Terminal emulation supports Dynamic Data Authentication (DDA) and can operate in wireless/contactless mode when requested.

See CLI help (`-h`) for all options.

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

### Tree Menu

`greenwire.tree_menu_cli` automatically builds a menu for each supported
standard with both contact and contactless options. Run it with:

```bash
python -m greenwire.tree_menu_cli
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
