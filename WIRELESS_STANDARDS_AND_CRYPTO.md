# GREENWIRE Wireless Standards & Cryptography Support

## Overview

GREENWIRE provides comprehensive support for wireless ICC (Integrated Circuit Card) standards and cryptographic operations used in RFID, NFC, and smartcard systems.

## Wireless Standards Support

### ISO/IEC 14443 - Contactless Smart Cards

**Type A and Type B proximity cards**

#### ISO 14443-1: Physical Characteristics

- Operating frequency: 13.56 MHz
- Operating distance: Up to 10 cm
- Power supply through RF field

#### ISO 14443-2: Radio Frequency Power and Signal Interface

- Type A: Modified Miller coding, 100% ASK modulation
- Type B: NRZ coding, 10% ASK modulation
- Bit rates: 106, 212, 424, 848 kbit/s

#### ISO 14443-3: Initialization and Anti-collision

- **Type A**:
  - UID: 4, 7, or 10 bytes
  - Anti-collision: Bit-wise anti-collision protocol
  - Command: REQA (Request Type A), WUPA (Wake-Up), SELECT
  
- **Type B**:
  - PUPI: 4 bytes (Pseudo-Unique PICC Identifier)
  - Anti-collision: Slot-based anti-collision
  - Command: REQB (Request Type B), WUPB, ATTRIB

#### ISO 14443-4: Transmission Protocol

- Block protocol for data exchange
- CID (Card IDentifier) support for multiple cards
- NAD (Node ADdress) for multi-application cards
- CRC_A/CRC_B for error detection
- **APDUs**: ISO 7816-4 compliant command structure

#### GREENWIRE Implementation

```python
# Located in: core/nfc_manager.py, core/ui/menu_actions.py
- rfid_scan_devices(): Scans for ISO 14443 Type A/B tags
- rfid_read_tag(): Reads data from ISO 14443 compliant cards
- rfid_write_tag(): Writes data to NTAG, Mifare, ISO 14443 tags
- rfid_analyze_protocol(): Sniffs ISO 14443 communication
```

**Supported Card Types:**

- Mifare Classic (1K, 4K) - ISO 14443A
- Mifare Ultralight/NTAG - ISO 14443A
- Mifare DESFire - ISO 14443A-4
- EMV Contactless (PayPass, payWave, ExpressPay) - ISO 14443A-4
- FeliCa (ISO 18092 compatible)

### ISO/IEC 15693 - Vicinity Cards

**Long-range contactless smart cards**

#### Characteristics

- Operating frequency: 13.56 MHz
- Operating distance: Up to 1 meter (vicinity)
- Data rate: 26.48 kbit/s
- Modulation: 10% or 100% ASK
- Coding: 1 out of 4 pulse position modulation

#### Commands

- Inventory (anti-collision)
- Stay Quiet
- Read Single Block / Multiple Blocks
- Write Single Block / Multiple Blocks
- Lock Block
- Select
- Reset to Ready
- Write AFI (Application Family Identifier)
- Lock AFI
- Write DSFID (Data Storage Format Identifier)
- Lock DSFID
- Get System Information
- Get Multiple Block Security Status

#### GREENWIRE Implementation

```python
# Supported in: greenwire.py, core/nfc_manager.py
args.protocol = 'iso15693'  # In nfc subcommand
rfid_analyze_protocol()  # Supports ISO 15693 sniffing
```

**Supported Tag Types:**

- ICODE SLI/SLI-S/SLI-L
- Tag-it HF-I
- VICINTY family tags

### NFC Forum Standards

**Near Field Communication specifications**

#### NFC Data Exchange Format (NDEF)

- **TNF** (Type Name Format): Well-known, MIME, Absolute URI, External
- **Record Types**:
  - RTD_TEXT: Text records
  - RTD_URI: URI/URL records
  - RTD_SMART_POSTER: Rich content
  - RTD_ALTERNATIVE_CARRIER: Handover
  - RTD_HANDOVER_SELECT/REQUEST: Connection handover

#### NFC Tag Types

- **Type 1**: Topaz (ISO 14443A based, read/write)
- **Type 2**: NTAG, Mifare Ultralight (ISO 14443A based, read/write)
- **Type 3**: FeliCa (ISO 18092 based, read/write)
- **Type 4**: ISO 14443-4 compliant (read/write)
- **Type 5**: ISO 15693 vicinity (read/write)

#### NFC Operating Modes

- **Card Emulation Mode**: Emulate contactless smartcard
- **Reader/Writer Mode**: Read/write NFC tags
- **Peer-to-Peer Mode**: Data exchange between devices

#### GREENWIRE Implementation

```python
# Located in: core/nfc_manager.py, greenwire.py
rfid_emulate_card()  # NFC card emulation mode
emv_emulate_terminal()  # NFC reader/writer mode with --wireless flag
args.wireless = True  # Enable NFC/wireless mode in EMV operations
```

---

## Cryptographic Standards & Algorithms

### Symmetric Cryptography

#### DES (Data Encryption Standard)

- **Block size**: 64 bits
- **Key size**: 56 bits (64 bits with parity)
- **Modes**: ECB, CBC
- **Usage**: Legacy EMV MAC, PIN block encryption (deprecated)
- **GREENWIRE**: Used in legacy EMV transaction cryptograms

#### 3DES (Triple DES)

- **Variants**:
  - 3DES-EDE2 (2-key, 112-bit effective security)
  - 3DES-EDE3 (3-key, 168-bit effective security)
- **Block size**: 64 bits
- **Modes**: ECB, CBC
- **Usage**: EMV MAC generation, PIN block encryption, Session key derivation
- **GREENWIRE**: Used in ATM/HSM operations, EMV cryptograms
  
**EMV Application:**

```
ARQC (Authorization Request Cryptogram) = MAC(3DES-CBC, Transaction Data)
Key Derivation: Session Key = 3DES(Master Key, PAN + Sequence)
```

#### AES (Advanced Encryption Standard)

- **Block size**: 128 bits
- **Key sizes**: 128, 192, 256 bits
- **Modes**: ECB, CBC, CTR, GCM, CCM
- **Usage**: Modern EMV, JavaCard applets, secure channels
- **GREENWIRE**:
  - JavaCard applet encryption
  - Secure channel protocols (GlobalPlatform SCP03)
  - EMV contactless (AES CMAC)

**AES-CMAC (Cipher-based MAC):**

- Used in EMV contactless for MAC generation
- Key size: 128/192/256 bits
- Output: 64-bit or 128-bit MAC

### Asymmetric Cryptography

#### RSA (Rivest-Shamir-Adleman)

- **Key sizes**: 1024, 2048, 4096 bits
- **Padding schemes**:
  - PKCS#1 v1.5 (legacy)
  - RSA-OAEP (Optimal Asymmetric Encryption Padding)
  - RSA-PSS (Probabilistic Signature Scheme)
- **Usage**:
  - EMV Dynamic Data Authentication (DDA)
  - EMV Combined DDA/AC (CDA)
  - Certificate verification
  - PIN encryption (transport key)
- **GREENWIRE**:
  - DDA implementation in `greenwire.py` (`args.dda = True`)
  - RSA key generation in HSM module
  - Certificate chain validation

**EMV DDA Flow:**

```
1. Terminal requests ICC Public Key Certificate
2. Terminal validates certificate using CA Public Key
3. Terminal sends INTERNAL AUTHENTICATE challenge
4. ICC signs challenge with ICC Private Key
5. Terminal verifies signature with ICC Public Key
```

#### Elliptic Curve Cryptography (ECC)

- **Curves**:
  - P-256 (secp256r1) - NIST standard
  - P-384 (secp384r1)
  - P-521 (secp521r1)
  - Curve25519 (X25519 for key exchange, Ed25519 for signing)
- **Usage**:
  - Modern payment cards (ECDSA for DDA)
  - JavaCard applets
  - Secure Element authentication
- **GREENWIRE**: Experimental support in crypto fuzzer

### Hash Functions

#### SHA-1 (Secure Hash Algorithm 1)

- **Output**: 160 bits
- **Usage**: Legacy EMV (being phased out)
- **Status**: Deprecated due to collision attacks

#### SHA-2 Family

- **Variants**: SHA-224, SHA-256, SHA-384, SHA-512
- **Output**: 224, 256, 384, 512 bits
- **Usage**:
  - EMV certificate signatures
  - Transaction hashing
  - HMAC construction
  - Key derivation (PBKDF2)
- **GREENWIRE**: Used in HSM key generation, EMV transaction validation

#### SHA-3 (Keccak)

- **Variants**: SHA3-224, SHA3-256, SHA3-384, SHA3-512
- **Usage**: Future-proof hash function, not yet in EMV

### Message Authentication Codes (MAC)

#### HMAC (Hash-based MAC)

- **Construction**: HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
- **Usage**: API message integrity, key derivation
- **GREENWIRE**: Used in HSM command validation

#### CMAC (Cipher-based MAC)

- **Construction**: Based on block cipher (AES, 3DES)
- **Usage**:
  - EMV MAC (3DES-CMAC, AES-CMAC)
  - GlobalPlatform Secure Channel Protocol
- **GREENWIRE**: Used in EMV transaction authorization

#### Retail MAC (ISO 9797-1 Algorithm 3)

- **Construction**: MAC = 3DES-Encrypt(DES-Encrypt(... DES-Encrypt(data)))
- **Usage**: EMV legacy MAC generation
- **GREENWIRE**: Implemented in EMV emulation

---

## Cryptographic Operations in GREENWIRE

### HSM Operations (`core/ui/menu_actions.py`, `greenwire.py`)

#### Key Generation

```python
crypto_generate_keys()  # Generates RSA/AES/3DES keys
hsm_generate_keys()     # ATM/HSM specific key generation

Supported key types:
- RSA 2048/4096 bits
- AES 128/192/256 bits
- 3DES 112/168 bits
- ECC P-256/P-384
```

#### PIN Operations

```python
hsm_pin_translate()  # Translate PIN from one key to another
# PIN Block Formats: ISO-0, ISO-1, ISO-3 (ANSI X9.8)
# Encryption: 3DES, AES
```

#### CVV/CVC Generation

```python
hsm_cvv_generate()  # Generate CVV/CVC/CVC3 using EMV algorithm
# CVV1: Magnetic stripe CVV
# CVV2: Printed CVV
# iCVV: Chip CVV (dynamic)
# CVC3: Contactless CVC
```

### Cryptographic Fuzzing (`modules/greenwire_crypto_fuzzer.py`)

```python
crypto_fuzzing()  # Fuzz crypto implementations

Fuzzing targets:
- RSA padding oracle attacks (Bleichenbacher)
- AES/DES timing attacks
- CBC padding oracle attacks
- ECB oracle attacks
- Weak key detection
- Side-channel analysis simulation
```

**Crypto Vulnerabilities Tested:**

- PKCS#1 v1.5 padding oracle (Bleichenbacher attack)
- CBC padding oracle (POODLE, Lucky13)
- ECB mode pattern detection
- Weak IV detection
- Key reuse detection
- Timing attack simulation

### EMV Cryptographic Operations

#### Application Cryptogram (AC) Generation

```
ARQC = MAC(Session Key, Transaction Data)
- Algorithm: 3DES-CMAC or AES-CMAC
- Key: Derived from Master Key using PAN and ATC
```

#### Dynamic Data Authentication (DDA)

```
Signature = RSA_Sign(ICC Private Key, Terminal Challenge + Static Data)
- Key size: 1024, 2048, or 4096 bits
- Hash: SHA-1, SHA-256
```

#### Combined DDA/Application Cryptogram (CDA)

```
Signature = RSA_Sign(ICC Private Key, Transaction Data + ARQC)
- Single signature covers both authentication and authorization
```

---

## Wireless ICC Protocol Support Matrix

| Standard       | Frequency | Range    | Speed       | GREENWIRE Support |
|----------------|-----------|----------|-------------|-------------------|
| ISO 14443A     | 13.56 MHz | 0-10 cm  | Up to 848 kbps | ✅ Full        |
| ISO 14443B     | 13.56 MHz | 0-10 cm  | Up to 848 kbps | ✅ Full        |
| ISO 15693      | 13.56 MHz | 0-100 cm | 26.48 kbps    | ✅ Full        |
| NFC Type 1     | 13.56 MHz | 0-10 cm  | 106 kbps      | ✅ Supported   |
| NFC Type 2     | 13.56 MHz | 0-10 cm  | 106 kbps      | ✅ Full        |
| NFC Type 3     | 13.56 MHz | 0-10 cm  | 212/424 kbps  | ⚠️ Experimental|
| NFC Type 4     | 13.56 MHz | 0-10 cm  | Up to 848 kbps | ✅ Full        |
| NFC Type 5     | 13.56 MHz | 0-100 cm | 26.48 kbps    | ✅ Full        |
| FeliCa         | 13.56 MHz | 0-10 cm  | 212/424 kbps  | ⚠️ Experimental|
| ISO 18092 (NFCIP-1) | 13.56 MHz | 0-10 cm | Up to 424 kbps | ⚠️ Experimental|

---

## Crypto Algorithm Support Matrix

| Algorithm    | Key Sizes      | Modes        | GREENWIRE Support | Use Case            |
|--------------|----------------|--------------|-------------------|---------------------|
| DES          | 56-bit         | ECB, CBC     | ✅ Full          | Legacy EMV          |
| 3DES         | 112/168-bit    | ECB, CBC     | ✅ Full          | EMV MAC, PIN        |
| AES          | 128/192/256-bit| ECB, CBC, CTR, GCM | ✅ Full  | Modern EMV, JavaCard|
| RSA          | 1024/2048/4096 | PKCS#1, OAEP, PSS | ✅ Full  | DDA, CDA, Certs    |
| ECC/ECDSA    | P-256/384/521  | -            | ⚠️ Experimental  | Modern cards        |
| SHA-1        | -              | -            | ✅ Full          | Legacy              |
| SHA-2        | -              | -            | ✅ Full          | Modern EMV          |
| SHA-3        | -              | -            | ⚠️ Experimental  | Future-proof        |
| HMAC         | Variable       | -            | ✅ Full          | HSM, API auth       |
| CMAC         | 128/192/256-bit| -            | ✅ Full          | EMV MAC             |

---

## Proprietary Standards

### Mifare Classic (NXP)

- **Crypto**: CRYPTO1 (proprietary, 48-bit key, **broken**)
- **GREENWIRE Support**: ✅ Full (read, write, clone, crack)
- **Notes**: Known vulnerabilities, easily cloned

### Mifare DESFire (NXP)

- **Crypto**: 3DES, AES-128
- **GREENWIRE Support**: ✅ Full
- **Features**: Multiple applications, secure messaging

### Mifare Plus (NXP)

- **Security Levels**:
  - SL0: Mifare Classic compatible
  - SL1: Basic AES security
  - SL2: Enhanced AES security
  - SL3: Full AES security with AES-CMAC
- **GREENWIRE Support**: ✅ SL1-SL3

### LEGIC (LEGIC Identsystems)

- **Crypto**: Proprietary
- **GREENWIRE Support**: ⚠️ Limited (read-only, reverse-engineered protocols)

### HID iCLASS (HID Global)

- **Crypto**: Proprietary (some variants use 3DES)
- **GREENWIRE Support**: ⚠️ Experimental

### FeliCa (Sony)

- **Crypto**: Proprietary (3DES based)
- **GREENWIRE Support**: ⚠️ Experimental
- **Usage**: Japan transit, e-money

---

## Testing Crypto Engine

### Run Crypto Tests

```bash
cd GREENWIRE
python greenwire.py --menu

# Select: Cryptography Menu
# Options:
# 1. Generate Keys (HSM) - Test RSA/AES/3DES key generation
# 2. HSM Operations - Test background HSM services
# 3. Cryptographic Fuzzing - Fuzz crypto implementations
# 4. Key Harvesting - Extract keys from memory/transactions
```

### Run Wireless Standards Tests

```bash
# Test ISO 14443
python greenwire.py nfc scan --protocol iso14443a
python greenwire.py nfc scan --protocol iso14443b

# Test ISO 15693
python greenwire.py nfc scan --protocol iso15693

# Test NFC emulation
python greenwire.py emulate --mode card --wireless
python greenwire.py emulate --mode terminal --wireless
```

---

## References

### Standards Documents

- ISO/IEC 7816-4: Interindustry commands for interchange
- ISO/IEC 14443-1/2/3/4: Contactless integrated circuit cards
- ISO/IEC 15693-1/2/3: Vicinity cards
- ISO/IEC 18092: Near Field Communication Interface and Protocol (NFCIP-1)
- EMVCo Book 2: Security and Key Management
- EMVCo Book 3: Application Specification
- EMVCo Contactless Specifications
- GlobalPlatform Card Specification v2.3.1
- NIST FIPS 197: AES
- NIST FIPS 180-4: SHA-2
- PKCS #1 v2.2: RSA Cryptography Standard

### Tools Integration

- **GlobalPlatformPro**: JavaCard applet deployment
- **APDU4J**: Low-level APDU communication
- **PC/SC**: Smartcard reader interface
- **libnfc**: NFC hardware abstraction
- **Crypto**: Python cryptography library

---

**Last Updated**: 2025-01-XX  
**GREENWIRE Version**: 2.0+  
**Author**: GREENWIRE Development Team
