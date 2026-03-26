# GREENWIRE Engineering Manual

**Version:** 2025 | **Classification:** Internal Lab Reference  
**Audience:** Software Engineers, Security Researchers, EMV Specialists

---

## Table of Contents

1. System Architecture Overview  
2. Key Types and Taxonomy  
3. Luhn Algorithm  
4. BIN / IIN Structure  
5. EMV Transaction Flow (12 Steps)  
6. ARQC Deep Dive  
7. GlobalPlatform Key Management  
8. HCE vs Physical Card  
9. TSP Integration (VTS and MDES)  
10. JCOP Platform Reference  
11. HSM Integration  
12. ATM Emulator  
13. POS Terminal Emulator  
14. Android HCE Bridge  
15. Python HCE Emulator  
16. Crypto Primitives Reference  
17. Testing Guide  
18. Troubleshooting  
19. Glossary  
20. References  

---

## 1. System Architecture Overview

### 1.1 What GREENWIRE Does

GREENWIRE is an EMV and GlobalPlatform lab framework.  It provides a unified Python CLI (`greenwire.py`) and interactive menu for:

- Sending arbitrary APDU commands to physical smart cards via PC/SC readers
- Emulating EMV card behaviour in software (HCE emulator)
- Deriving and verifying all payment cryptographic keys (GP, EMV, SCP02/03, HCE LUK)
- Operating simulated ATM and POS terminals for end-to-end transaction testing
- Fuzzing card applets with mutation-based APDU generators
- Bridging Android NFC devices via ADB for remote card emulation

### 1.2 Component Diagram (ASCII Art)

```
 ┌──────────────────────────────────────────────────────────────┐
 │                    greenwire.py (CLI/Menu)                    │
 └──────────────────┬───────────────────────────────────────────┘
                    │ dispatches to
        ┌───────────┼──────────────────────────────┐
        ▼           ▼                              ▼
 ┌──────────┐ ┌──────────────┐           ┌─────────────────────┐
 │  core/   │ │  modules/    │           │  apdu4j_data/       │
 │  ──────  │ │  ─────────   │           │  ─────────────────  │
 │  key_gen │ │  nfc/        │           │  apdu4j_integration │
 │  card_v  │ │  atm_emu     │           │  (ISO 7816-4 J/W)   │
 │  emv_p   │ │  pos_term    │           └─────────────────────┘
 │  nfc_mgr │ │  banking_sys │
 │  hsm     │ │  hce_bridge  │           ┌─────────────────────┐
 └──────────┘ └──────────────┘           │  javacard/applet/   │
        │           │                    │  (Gradle / .cap)    │
        ▼           ▼                    └─────────────────────┘
 ┌──────────────────────────┐
 │  Hardware / Emulated     │
 │  ─────────────────────── │
 │  PC/SC Reader (USB)      │
 │  Android NFC via ADB     │
 │  Thales HSM Emulator     │
 │  JavaCard JCOP Simulator │
 └──────────────────────────┘
```

### 1.3 Module Dependency Map

```
greenwire.py
  ├── core.key_generators        ← cryptography (AES, 3DES)
  ├── core.card_validator        ← stdlib only
  ├── core.synthetic_identity    ← stdlib only
  ├── core.pan_registry          ← stdlib only (JSON file)
  ├── core.emv_processor         ← TLV parsing
  ├── core.nfc_manager           ← pyscard (PC/SC)
  ├── core.android_manager       ← subprocess (adb)
  ├── modules.nfc.protocols      ← APDU dataclasses
  ├── modules.enhanced_atm_emulator
  ├── modules.enhanced_pos_terminal
  ├── modules.banking_system_integration
  └── apdu4j_data.apdu4j_integration  ← Java subprocess (gp.jar)
```

---

## 2. Key Types and Taxonomy

This section is the foundation for understanding every cryptographic operation in GREENWIRE.  Read it before touching any key derivation code.

### 2.1 Master Keys (MK, IMK, IK)

**What they are:**  
A Master Key (also called an Issuer Master Key, IMK, or simply IK depending on context) is the root secret from which all card-level keys are derived.  There is typically one IMK per application (e.g. one for ARQC derivation, one for PIN encryption, one for SMI/SMC messaging).

**Where they live:**  
Master keys never leave the Hardware Security Module (HSM) in production.  In the lab, GREENWIRE simulates the HSM using software 3DES/AES implementations.  The lab master key is hardcoded as `JCOP_DEFAULT_LAB_KEY = 404142434445464748494A4B4C4D4E4F`.

**Who holds them:**  
In production, the card issuer (bank) holds IMKs.  Only the HSM operator and security officer roles can access them, under dual-control ceremony.  In the lab, treat them as non-secret test data — they are published in every JCOP evaluation kit.

**Key sizes:** 16 bytes (3DES-112), occasionally 24 bytes (3DES-168) or 16 bytes (AES-128 for SCP03).

### 2.2 Session Keys (SK_ENC, SK_MAC, SK_DEK)

**What they are:**  
Session keys are ephemeral keys derived fresh for every card transaction or every GlobalPlatform secure channel.  They protect a single exchange and are never stored.

| Key | Purpose |
|-----|---------|
| SK_ENC | Encrypts sensitive data (e.g. PIN blocks in the command stream) |
| SK_MAC | Authenticates commands and responses (CMAC or Retail-MAC) |
| SK_DEK | Encrypts other keys during transport (key wrapping) |

**Derivation:**  
For EMV: `SK = 3DES(IMK, ATC_padded_diversification_data)`.  
For SCP02: `SK = 3DES(static_key, derivation_constant || sequence_counter)`.  
For SCP03: `SK = AES-CMAC(static_key, label || context)`.

**Never stored:**  Session keys are re-derived every transaction from the persistent IMK and the per-transaction ATC.

### 2.3 Secure Channel Keys (SCP02 vs SCP03)

**SCP02 (3DES, GP 2.1.1+):**

| Key Name | Derivation Constant | Algorithm |
|----------|-------------------|-----------|
| S-ENC    | 0x0182            | 3DES-CBC  |
| S-MAC    | 0x0101            | Retail-MAC (ISO 9797-1 Alg 3) |
| S-DEK    | 0x0181            | 3DES-ECB  |
| R-MAC    | 0x0102            | Retail-MAC |

**SCP03 (AES, GP 2.2 Amendment D+):**

| Key Name | KDF Label | Algorithm |
|----------|-----------|-----------|
| S-ENC    | 0x04      | AES-CBC   |
| S-MAC    | 0x06      | AES-CMAC  |
| S-RMAC   | 0x07      | AES-CMAC  |
| S-DEK    | 0x08      | AES-ECB   |

The critical difference: SCP02 uses 3DES and the sequence counter as diversification input.  SCP03 uses AES and fresh random nonces (host_challenge XOR card_challenge as context), providing forward secrecy per session.

### 2.4 Card Keys (ICC_MK, ICC_PIN_MK)

**ICC Master Key (ICC_MK):**  
The ICC_MK is the card-individualised master key derived during personalisation.  It is stored inside the secure element and never exported.

Derivation: `ICC_MK = 3DES(IMK, PAN[right-12] || PAN_SeqNo || padding)`.

**ICC PIN Master Key (ICC_PIN_MK):**  
Used to derive the PIN verification value or the offline PIN encryption key.  Derived similarly from a separate IMK dedicated to PIN operations.

In GREENWIRE: `EMV_DynamicSessionKeys.derive_icc_mk(pan, psn)` computes ICC_MK from the lab IMK.

### 2.5 Token Keys (LUK = SK_ENC ‖ SK_MAC)

**What they are:**  
Limited-Use Keys (LUKs) are pre-computed session keys used by Android HCE wallets instead of a physical chip.  Because a software wallet cannot resist key extraction the way a chip can, LUKs are time-limited and single-use.

**Structure:**  
`LUK = SK_ENC(16 bytes) || SK_MAC(16 bytes) = 32 bytes total`.  
Each LUK is bound to a specific ATC value and expires after one transaction.

**Lifecycle:**  
The Token Service Provider (TSP) derives a batch of LUKs and pushes them to the device wallet over HTTPS.  When the batch is exhausted, the wallet requests replenishment before the next tap.

In GREENWIRE: `HCE_TokenKeyGenerator.generate_token(..., luk_batch_size=N)` creates a batch for testing.

### 2.6 PIN Keys (ZPK, TPK)

**Zone PIN Key (ZPK):**  
A symmetric key (usually 3DES-112 or 3DES-168) used to encrypt PIN blocks between the terminal and the acquirer host.  ZPKs are exchanged between HSMs under a Zone Master Key (ZMK).

**Terminal PIN Key (TPK):**  
The key loaded into an ATM's EPP (Encrypting PIN Pad) to encrypt PINs at entry.  The TPK is injected by a key loading device under strict dual-control procedures.

**HSM roles:**  
The HSM translates PIN blocks from one key to another (e.g. TPK → ZPK) without exposing the cleartext PIN.  GREENWIRE's Thales emulator supports this translate operation.

### 2.7 Transport Keys (ZMK, TMK)

**Zone Master Key (ZMK):**  
A key-encryption key used to securely transfer working keys (ZPK, CVK, etc.) between HSMs at different institutions.  ZMKs are never used for data encryption.

**Terminal Master Key (TMK):**  
The root key from which terminal working keys (ZPK, TPK) are derived.  Injected into the terminal at manufacture or commissioning.

**Format:**  
Both ZMK and TMK are 16-byte 3DES-112 keys, typically conveyed as two 8-byte key components under dual control (two separate custodians, never present simultaneously).

### 2.8 CA/Issuer/ICC RSA Keys

EMV offline authentication (SDA, DDA, CDA) uses a certificate chain:

```
CA Public Key (2048-bit RSA, stored in terminal)
    └── Issuer Public Key Certificate (signed by CA)
            └── ICC Public Key Certificate (signed by issuer)
                    └── ICC Private Key (stored in card chip)
```

**CA Key:**  Registered with EMVCo.  Each scheme (Visa, Mastercard) has its own CA keys per region.  The terminal stores the public modulus indexed by RID + CA Public Key Index.

**Issuer Key:**  The issuer generates an RSA key pair.  The issuer public key is certified by the CA using `RSA-PKCS1-v1.5` with SHA-1.

**ICC Key:**  Each card has a unique RSA key pair.  The private key is generated on-chip during personalisation and never exported.  The public key is certified by the issuer.

**DDA/CDA:**  Dynamic Data Authentication has the card sign a nonce (DDOL data) with the ICC private key to prove the chip is genuine.  CDA (Combined DDA/AC) links the ARQC generation to the DDA signature.

### 2.9 Key Hierarchy Diagram

```
                  ┌──────────────────┐
                  │  Issuer Master   │
                  │  Key (IMK)       │ ← Lives in HSM only
                  │  16 bytes 3DES   │
                  └────────┬─────────┘
                           │ 3DES diversification
                           │ using PAN + PSN
                           ▼
                  ┌──────────────────┐
                  │  ICC Master Key  │
                  │  (ICC_MK)        │ ← Personalised into chip
                  │  16 bytes 3DES   │
                  └────────┬─────────┘
                           │ 3DES diversification
                           │ using ATC
                           ▼
              ┌────────────┴────────────┐
              ▼                         ▼
   ┌──────────────────┐      ┌──────────────────┐
   │  SK_ENC          │      │  SK_MAC          │
   │ (Session Encrypt)│      │ (Session Auth)   │
   │  16 bytes 3DES   │      │  16 bytes 3DES   │
   └────────┬─────────┘      └────────┬─────────┘
            │                          │
            └──────────┬───────────────┘
                       ▼
              ┌──────────────────┐
              │  ARQC            │
              │  8 bytes (trunc) │ ← Sent to acquirer host
              └──────────────────┘
```

### 2.10 GP ENC/MAC/DEK vs EMV Session Keys — Critical Difference

This is the most commonly misunderstood distinction in the codebase.

| Property | GP SCP02 Session Keys | EMV Transaction Session Keys |
|----------|-----------------------|------------------------------|
| Purpose | Protect card management APDU stream (PUT KEY, INSTALL, etc.) | Compute transaction cryptograms (ARQC, ARPC, TC) |
| Root key | ISD Static Keys (ENC, MAC, DEK) | Issuer Master Key (IMK) |
| Diversification input | Sequence counter + INITIALIZE UPDATE nonces | PAN + PSN → ICC_MK, then ATC → SK |
| Algorithm | 3DES-CBC (SCP02) / AES-CMAC (SCP03) | 3DES-ECB for derivation, 3DES-CBC for ARQC |
| Key scope | One secure channel session | One EMV transaction |
| Stored in card? | Static keys yes; session keys no | ICC_MK yes; SK no |
| GREENWIRE class | `GP_StaticDiversification` → `SCP03_AESKeyDerivation` | `EMV_DynamicSessionKeys` |

**GP keys protect the card OS** (applet loading, key management).  
**EMV keys protect the transaction** (authorisation, PIN).  
They use different root keys, different diversification algorithms, and serve different protocol layers.

---

## 3. Luhn Algorithm

### 3.1 What It Is

The Luhn algorithm (ISO/IEC 7812-1 Annex B) is a simple checksum formula applied to the last digit of a Primary Account Number (PAN).  It exists to catch accidental single-digit transcription errors, not to prevent fraud.

### 3.2 Full Algorithm Walkthrough

Given PAN `4111111111111111`:

1. **Starting from the rightmost digit (the check digit), move left.**  
2. **Double every second digit** (i.e. the 2nd, 4th, 6th… from the right, not counting the check digit).  
3. **If doubling produces a number ≥ 10, subtract 9.**  
4. **Sum all digits** (including the undoubled ones and the check digit).  
5. **The PAN is valid if the total mod 10 = 0.**

```
PAN:     4  1  1  1  1  1  1  1  1  1  1  1  1  1  1  1
Step:    D  -  D  -  D  -  D  -  D  -  D  -  D  -  D  -
         ↑ start from right-most, mark every other

Position (right-to-left):  16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1
Double positions:           16 -- 14 -- 12 -- 10 --  8 --  6 --  4 --  2 --

Digit:    4   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1
Double?   Y   N   Y   N   Y   N   Y   N   Y   N   Y   N   Y   N   Y   N
Doubled:  8   1   2   1   2   1   2   1   2   1   2   1   2   1   2   1
Sum: 8+1+2+1+2+1+2+1+2+1+2+1+2+1+2+1 = 30
30 mod 10 = 0 → VALID ✓
```

### 3.3 Why Luhn is NOT Security

Luhn detects:
- Any single transposed digit
- Most adjacent transpositions

Luhn does NOT detect:
- Deliberate fraud (an attacker can compute a valid check digit)
- Double-digit errors
- Systematic transpositions

**Luhn is an integrity check, not an authentication mechanism.**  Every GREENWIRE test tool that generates PANs appends a correct Luhn check digit with `luhn_append()`.

---

## 4. BIN / IIN Structure

### 4.1 ISO 7812-1 Structure

A PAN has the following field structure:

```
 PAN = IIN (6–8 digits) + Account Number + Check Digit
       └─────────────────────────────────────────────┘
                    up to 19 digits total
```

| Field | Length | Description |
|-------|--------|-------------|
| MII   | 1 digit | Major Industry Identifier (first digit of IIN) |
| IIN/BIN | 6–8 digits | Issuer Identification Number |
| Account number | variable | Issuer-defined account identifier |
| Check digit | 1 digit | Luhn check digit |

### 4.2 Major Industry Identifier (MII)

| MII | Industry |
|-----|---------|
| 1, 2 | Airlines |
| 3 | Travel and entertainment (Amex = 34/37, Diners = 36/38) |
| 4 | Banking/financial (Visa) |
| 5 | Banking/financial (Mastercard) |
| 6 | Merchandising/banking (Discover, UnionPay) |
| 7 | Petroleum |
| 8 | Healthcare, telecoms |
| 9 | National assignment |

### 4.3 8-Digit BIN Priority

Since ISO 7812-1:2017, BINs may be 8 digits (previously always 6).  GREENWIRE's `lookup_bin()` function performs longest-prefix matching, checking 8-digit BINs before 6-digit BINs before 4-digit BINs, to ensure more-specific entries win.

### 4.4 Tokenization and BIN Changes

When a PAN is tokenized (FPAN → DPAN), the token uses a BIN range **reserved by the TSP**, not the original issuer BIN.

- **Visa Token Service (VTS):** BINs in the 489537xx range
- **Mastercard Digital Enablement Service (MDES):** BINs in the 5204xx / 5204xx range

This means `is_token=True` in a `CardProfile` comes from detecting the DPAN BIN, not from any flag in the PAN itself.  A physical card and its token look identical structurally; only the BIN prefix reveals the token nature.

---

## 5. EMV Transaction Flow (12 Steps)

Each step shows the relevant APDU command.

| Step | Name | Terminal → Card APDU | Card Response |
|------|------|---------------------|---------------|
| 1 | **Application Selection** | `00 A4 04 00 07 A0000000031010 00` (SELECT PPSE or AID) | FCI with AID list |
| 2 | **Application Initiation** | `80 A8 00 00 02 8300 00` (GET PROCESSING OPTIONS) | AIP + AFL |
| 3 | **Read Application Data** | `00 B2 xx xx 00` (READ RECORD, per AFL) | Record data (TLV) |
| 4 | **Offline Data Auth** | Internal DDA/CDA verification using RSA certs | No APDU; terminal verifies |
| 5 | **Processing Restrictions** | Terminal checks AIP, app version, usage control | Internal |
| 6 | **Cardholder Verification** | `00 20 00 80 xx [PIN block]` (VERIFY) or signature | SW 9000 or SW 63Cx |
| 7 | **Terminal Risk Management** | Terminal checks floor limits, velocity | Internal |
| 8 | **Terminal Action Analysis** | Terminal decides online/offline/decline | Internal |
| 9 | **Card Action Analysis (1st GENERATE AC)** | `80 AE x0 00 [CDOL1 data]` | ARQC (if online) or TC (approve offline) |
| 10 | **Online Authorisation** | Terminal sends ARQC to acquirer host | Auth response code + ARPC |
| 11 | **Issuer Script Processing** | `86 xx xx xx [script]` (EXTERNAL AUTHENTICATE / issuer script) | SW 9000 |
| 12 | **Card Action Analysis (2nd GENERATE AC)** | `80 AE x0 00 [CDOL2 data]` | TC (commit) or AAC (decline) |

The response cryptogram type in step 9 is encoded in bits 7–6 of the first byte of the response:  
`00` = AAC (decline), `01` = TC (offline approve), `10` = ARQC (go online).

---

## 6. ARQC Deep Dive

### 6.1 What the ARQC Proves

The ARQC (Authorisation Request Cryptogram) is a Message Authentication Code that binds the transaction data to the card's secret ICC_MK.  It proves:
1. The card knows ICC_MK (authenticity)
2. The transaction data is unaltered (integrity)
3. The ATC is unique (replay prevention)

### 6.2 Input Data Construction (CDOL1)

The Card Risk Management Data Object List 1 (CDOL1) specifies which transaction fields are included in ARQC generation.  Typical fields:

| Tag | Name | Length |
|-----|------|--------|
| 9F02 | Amount Authorised | 6 bytes (BCD) |
| 9F03 | Amount Other | 6 bytes (BCD) |
| 9F1A | Terminal Country Code | 2 bytes |
| 95   | Terminal Verification Results | 5 bytes |
| 5F2A | Transaction Currency Code | 2 bytes |
| 9A   | Transaction Date | 3 bytes |
| 9C   | Transaction Type | 1 byte |
| 9F37 | Unpredictable Number | 4 bytes |
| 9F35 | Terminal Type | 1 byte |
| 9F45 | Data Authentication Code | 2 bytes |
| 9F4C | ICC Dynamic Number | 8 bytes (DDA only) |
| 9F34 | CVM Results | 3 bytes |

### 6.3 Session Key Derivation for ARQC

```
Input:  ICC_MK (16 bytes), ATC (2 bytes)

Diversification data = ATC (2 bytes) || 00 00 00 00 00 00 (6 bytes) → 8 bytes
Derive SK_ENC = 3DES(ICC_MK, 8-byte block)
                || 3DES(ICC_MK, 8-byte block XOR FF FF FF FF FF FF FF FF)

SK_MAC derived identically from same ATC with different padding.
```

### 6.4 ARQC Computation (3DES-CBC)

```
Pad CDOL1_data to multiple of 8 bytes using ISO/IEC 9797-1 padding method 2
  (append 0x80, then 0x00 bytes to fill block)
Compute MAC:
  block[0] = 3DES(SK_MAC, IV=0x0000000000000000 XOR padded_data[0])
  block[i] = 3DES(SK_MAC, block[i-1] XOR padded_data[i])
ARQC = block[last] truncated to 8 bytes
```

### 6.5 What the Terminal Does with ARQC

1. Includes ARQC in the authorisation request (ISO 8583 field 55, the ICC data field)
2. The acquirer forwards the message to the issuer host
3. The issuer host's HSM re-derives ICC_MK and SK_MAC, recomputes the ARQC, and compares
4. If valid, the HSM generates an ARPC (Authorisation Response Cryptogram) using the same SK_MAC to authenticate the response
5. The terminal verifies the ARPC in step 11 (EXTERNAL AUTHENTICATE)

---

## 7. GlobalPlatform Key Management

### 7.1 ISD Default Keys

Every JCOP card ships with a factory-default key in the Issuer Security Domain (ISD):

| Environment | Key Hex (ENC = MAC = DEK) |
|-------------|--------------------------|
| JCOP Lab    | `404142434445464748494A4B4C4D4E4F` |
| NXP JCOP4   | `404142434445464748494A4B4C4D4E4F` (same, per evaluation kit) |
| Production  | Diversified per card; injected during manufacturing |

**Never ship a card with the default key in production.**  The GP SELECT on the ISD will succeed without authentication for any tool that knows the default.

### 7.2 SCP02 vs SCP03 Comparison

| Feature | SCP02 | SCP03 |
|---------|-------|-------|
| Algorithm | 3DES-112 | AES-128 |
| MAC Algorithm | Retail-MAC (ISO 9797-1 Alg 3) | AES-CMAC (NIST SP 800-38B) |
| Key Derivation | 3DES(static_key, constant ‖ seq_ctr) | AES-CMAC KDF per GP Amend D |
| Session freshness | Sequence counter (16-bit, can wrap) | Random 8-byte nonces (no wrap) |
| Forward secrecy | No | Yes (fresh nonces per session) |
| Card support | Universal (all GP cards) | GP 2.2 Amendment D+ only |
| Security level | SL1 (MAC), SL3 (ENC+MAC) | SL1, SL3 |
| GREENWIRE class | `GP_StaticDiversification` | `SCP03_AESKeyDerivation` |

### 7.3 Key Derivation Constants

| Key | Constant (SCP02) | KDF Label (SCP03) |
|-----|-----------------|-------------------|
| S-ENC | `0x0182` | `0x04` |
| S-MAC | `0x0101` | `0x06` |
| S-RMAC | `0x0102` | `0x07` |
| S-DEK | `0x0181` | `0x08` |

SCP02 derivation: `3DES(static_key, constant[2] ‖ seq_ctr[2] ‖ 00{12})` using the 2-byte constant in positions 0–1 of the 16-byte block.

SCP03 derivation: `AES-CMAC(static_key, 00{11} ‖ label[1] ‖ 00 ‖ length[1] ‖ context[16])` where context = host_challenge ‖ card_challenge.

### 7.4 Secure Channel Establishment Sequence

```
Terminal                                    Card
   │                                          │
   │── SELECT ISD ──────────────────────────▶ │
   │◀─ FCI (AID, Security Domain info) ──────  │
   │                                          │
   │── INITIALIZE UPDATE (host_challenge[8]) ▶ │
   │◀─ card_challenge[8] + card_cryptogram[8]  │
   │                                          │
   │ (Terminal derives session keys)          │
   │ (Terminal verifies card_cryptogram)      │
   │                                          │
   │── EXTERNAL AUTHENTICATE ────────────────▶ │
   │   (host_cryptogram[8])                   │
   │◀─ SW 9000 (session open)                 │
   │                                          │
   │ Secure channel now open                  │
   │ All subsequent APDUs encrypted/MACed     │
```

### 7.5 Key Ceremony Procedure

A **key ceremony** is the formal process of establishing root keys under dual control.  In the lab:

1. Generate 3 key components (KC1, KC2, KC3) from separate random sources
2. XOR them: `master_key = KC1 XOR KC2 XOR KC3`
3. Load each component using a separate custodian (two-person rule)
4. Verify key check value (KCV): `KCV = 3DES(master_key, 0x000000000000000000000000000000000)[0:3]` — the first 3 bytes after encrypting a zero block
5. Record ceremony in an audit log

---

## 8. HCE vs Physical Card

### 8.1 Architecture Comparison

```
 Physical EMV Card               Android HCE Wallet
 ─────────────────               ──────────────────
 Secure Element (tamper-proof)   Normal Android app process
 ICC_MK stored in SE             DPAN used instead of FPAN
 On-chip RSA key (DDA/CDA)       No RSA private key (SDA only)
 ATC stored in EEPROM            ATC tracked by TSP
 LUK batch: not applicable       LUK batch: pushed by TSP
 Reader energises card           Reader energises NFC antenna
 APDU via ISO 14443-4            APDU via Android HCE API
```

### 8.2 Security Model Differences

The fundamental security difference is **key storage**:
- A physical chip resists key extraction through tamper-evident/resistant hardware.  Even sophisticated attackers with electron microscopes struggle to extract ICC_MK from a modern chip.
- An Android app runs in software.  Even with TrustZone, root access or OS exploits can potentially expose keys.

To compensate, HCE uses:
1. **Token PANs (DPAN):** If the token is stolen, only the token is compromised — not the real PAN.
2. **Limited-Use Keys (LUKs):** Each key is valid for one transaction and one ATC value.  A stolen LUK cannot be used to generate a second transaction.
3. **Replenishment throttling:** The TSP detects abnormal LUK consumption and can suspend the token.

### 8.3 Token Lifecycle

```
Enrolment: FPAN → TSP → DPAN assigned → LUK batch generated
                                              ↓
Device: [LUK1, ATC1] [LUK2, ATC2] ... [LUKN, ATCN] (batch of N)
                                              ↓
Transaction 1: Use LUK1 + ATC1 → ARQC → acquirer → issuer → authorised
Transaction 2: Use LUK2 + ATC2 → ARQC → acquirer → issuer → authorised
...
Batch exhausted → Wallet requests replenishment → TSP delivers new batch
```

---

## 9. TSP Integration (VTS and MDES)

### 9.1 Token Provisioning Flow

```
User adds card to wallet app
        │
        ▼
Wallet SDK → TSP HTTPS API: /provision
  Body: { fpan, expiry, cvv, device_id, wallet_id }
        │
        ▼
TSP → Issuer: /verify (check FPAN valid, active, not blocked)
        │
        ▼
TSP generates: dpan, icc_mk = f(imk, dpan, psn)
               luk_batch = [derive_luk(icc_mk, atc) for atc in range(N)]
        │
        ▼
TSP → Wallet: { dpan, expiry, luk_batch, token_ref }
        │
        ▼
Wallet stores DPAN + LUK batch in secure storage (Keystore/SE)
```

### 9.2 LUK Derivation

`LUK(ATC) = 3DES(ICC_MK, ATC_diversification_data)` — same algorithm as EMV session key derivation, with the ATC encoded in positions 0–1 of the 8-byte diversification block.

In GREENWIRE: `HCE_TokenKeyGenerator.get_luk(token, atc=N)` returns the pre-computed LUK for ATC N from the batch.

### 9.3 Sandbox vs Production

| Environment | Endpoint | Key Material |
|-------------|----------|-------------|
| Sandbox | developer.visa.com/sandbox or sandbox.api.mastercard.com | Test master keys; no real funds |
| Production | api.visa.com / api.mastercard.com | HSM-backed IMKs; real transactions |

GREENWIRE operates in sandbox / lab mode only.  `JCOP_DEFAULT_LAB_KEY` is a published test key and must never be used as a production IMK.

---

## 10. JCOP Platform Reference

### 10.1 JCOP Generations Comparison

| Generation | Chip Family | JavaCard API | GP Version | Key Sizes | Notable Features |
|------------|-------------|-------------|------------|-----------|-----------------|
| JCOP 3 P60 | NXP P60     | JC 3.0.4    | GP 2.2.1   | 3DES, AES-128 | SCP02 + SCP03 |
| JCOP 4 P71 | NXP P71     | JC 3.0.5    | GP 2.3     | AES-128/256 | SCP11, LSCP |
| JCOP 4 SE050 | NXP SE050 | JC 3.0.5    | GP 2.3     | AES-256, RSA-4096, ECC-521 | IoT/embedded |
| JCOP 5 P71 | NXP P71     | JC 3.1.0    | GP 2.3.1   | Post-quantum ready | CV2 support |

### 10.2 Default Lab Key

```
JCOP_DEFAULT_LAB_KEY = 404142434445464748494A4B4C4D4E4F
```
This is the factory ISD key shipped on every JCOP evaluation card.  All three GP key slots (ENC, MAC, DEK) default to this same value at key version 0xFF, key index 01/02/03.

### 10.3 AID Structure

```
AID = RID (5 bytes) || PIX (variable, up to 11 bytes)

RID examples:
  A0 00 00 00 03  — Visa
  A0 00 00 00 04  — MasterCard
  A0 00 00 00 65  — JCB
  A0 00 00 06 23  — GREENWIRE Lab (reserved for testing)

PIX structure (Visa example):
  A0 00 00 00 03 | 10 10 — Visa Credit/Debit
  A0 00 00 00 03 | 20 10 — Visa Electron
  A0 00 00 00 03 | 80 02 — Visa PLUS (ATM)
```

---

## 11. HSM Integration

### 11.1 Thales Emulator Architecture

GREENWIRE includes a software emulation of a Thales payShield 9000/10k HSM.  The emulator accepts the same TCP command format as the real HSM, allowing existing host applications to work without modification.

The emulator lives in `hsm/` and exposes a socket server on port 1500 (configurable).

### 11.2 Key Types Stored in the (Emulated) HSM

| Key Type | Purpose | Format |
|----------|---------|--------|
| ZMK | Zone Master Key — protects other keys in transit | 3DES-112 LMK-encrypted |
| ZPK | Zone PIN Key — encrypts PIN blocks between hosts | 3DES-112 ZMK-encrypted |
| TPK | Terminal PIN Key — encrypts PIN at the ATM EPP | 3DES-112 TMK-encrypted |
| CVK | Card Verification Key — generates/verifies CVV | 3DES-112 LMK-encrypted |
| IMK | Issuer Master Key — root for ICC_MK derivation | 3DES-112 LMK-encrypted |

All keys stored under the Local Master Key (LMK), a 3-component 3DES-168 key that never leaves the HSM hardware.

### 11.3 PIN Block Formats (ISO 9564)

| Format | Hex Prefix | Description |
|--------|-----------|-------------|
| Format 0 (ISO F0) | `0x0N...` | PAN-XOR, most common in banking |
| Format 1 (ISO F1) | `0x1N...` | No PAN needed; transaction-unique data |
| Format 3 (ISO F3) | `0x3N...` | Random padding; requires PAN for decryption |
| Format 4 (ISO F4) | AES block  | AES-based; for next-gen terminals |

Format 0 construction:
```
PIN_block = format_field(0x0, PIN_len, PIN_digits) XOR PAN_block
PAN_block = 0x0000 || PAN[3..14] (right-justified, excluding check digit)
```

### 11.4 HSM Command Reference (Selected)

| Command | Code | Function |
|---------|------|----------|
| Generate Key | CA | Generate random 3DES or AES key under LMK |
| Translate PIN Block | CC | Re-encrypt PIN block from one key to another |
| Verify PIN | DA | Verify PIN against PVV or offset stored on card |
| Generate CVV | CW | Compute 3-digit CVV from PAN + expiry + service code |
| Verify CVV | CY | Verify CVV submitted by cardholder |
| Derive ICC_MK | BW | Derive ICC Master Key from IMK using PAN/PSN |

---

## 12. ATM Emulator

### 12.1 Architecture

`modules/enhanced_atm_emulator.py` implements a realistic ATM including:
- EPP (Encrypting PIN Pad) emulation with Format 0 PIN block generation
- Card reader (contact and contactless)
- HSM interface for PIN verification and key management
- Receipt printer output (text)
- Cash dispenser state machine

### 12.2 ATM Transaction Flow

```
1. IDLE         — Display welcome screen
2. CARD_INSERT  — Card inserted/tapped; read Track 2 or EMV data
3. PIN_ENTRY    — EPP encrypts PIN → PIN block (Format 0)
4. ONLINE_AUTH  — Format ISO 8583 message with ARQC and PIN block; send to host
5. PROCESSING   — Wait for authorisation response
6. DISPENSING   — Dispense cash if approved
7. RECEIPT      — Print transaction receipt
8. EJECT        — Eject card; return to IDLE
```

### 12.3 PIN Verification Process

```
EPP: cleartext_pin → 3DES(TPK, pin_block_F0)
Terminal → HSM: translate(pin_block_F0, TPK, ZPK)  
HSM returns: pin_block_F0_under_ZPK (same PIN, different key)
Terminal → Host: ISO 8583 with pin_block_under_ZPK in field 52
Host HSM: verify_pin(pin_block, ZPK, PVV_or_offset_from_card_data)
```

---

## 13. POS Terminal Emulator

### 13.1 Architecture

`modules/enhanced_pos_terminal.py` implements the full EMV Book 3 contact and contactless terminal flow.  It supports:
- Contact EMV (ISO 7816-4)
- Contactless EMV (ISO 14443 via PC/SC)
- Magnetic stripe fallback
- Signature CVM (capture via console prompt)
- Offline PIN (encrypted and plaintext)

### 13.2 Terminal Verification Results (TVR) Bit Map

The TVR is a 5-byte bitmap built up during the transaction.  Each bit records a specific check outcome.

| Byte | Bit | Meaning when set |
|------|-----|-----------------|
| 1 | 7 | Offline data authentication was not performed |
| 1 | 6 | SDA failed |
| 1 | 5 | ICC data missing |
| 1 | 4 | Card appears on terminal exception file |
| 1 | 3 | DDA failed |
| 1 | 2 | CDA failed |
| 2 | 7 | ICC and terminal have different application versions |
| 2 | 6 | Expired application |
| 2 | 5 | Application not yet effective |
| 2 | 4 | Requested service not allowed for card product |
| 2 | 3 | New card |
| 3 | 7 | Cardholder verification was not successful |
| 3 | 6 | Unrecognised CVM |
| 3 | 5 | PIN Try Limit exceeded |
| 3 | 4 | PIN entry required and PIN pad not present |
| 3 | 3 | PIN entry required, PIN pad present, but PIN was not entered |
| 3 | 2 | Online PIN entered |
| 4 | 7 | Transaction exceeds floor limit |
| 4 | 6 | Lower consecutive offline limit exceeded |
| 4 | 5 | Upper consecutive offline limit exceeded |
| 4 | 4 | Transaction selected randomly for online processing |
| 4 | 3 | Merchant forced transaction online |
| 5 | 7 | Default TDOL used |
| 5 | 6 | Issuer authentication failed |
| 5 | 5 | Script processing failed before final GENERATE AC |
| 5 | 4 | Script processing failed after final GENERATE AC |

### 13.3 Application Interchange Profile (AIP) Bit Map

The AIP is a 2-byte bitmap returned by the card in the GET PROCESSING OPTIONS response.

| Byte | Bit | Meaning when set |
|------|-----|-----------------|
| 1 | 6 | SDA supported |
| 1 | 5 | DDA supported |
| 1 | 4 | Cardholder verification is supported |
| 1 | 3 | Terminal risk management to be performed |
| 1 | 2 | Issuer authentication is supported |
| 1 | 1 | On-device CVM is supported (contactless) |
| 1 | 0 | CDA supported |
| 2 | 7 | Relay resistance protocol supported |

### 13.4 CVM List Processing

The Cardholder Verification Method (CVM) list defines the preferred order of CVM methods.  The terminal iterates the list from top to bottom, attempting each CVM until one succeeds or the list is exhausted.

```
CVM Rule = CVM Code (1 byte) || Condition Code (1 byte)

CVM Codes (selected):
  3F — Fail (no CVM)
  01 — Offline plaintext PIN
  02 — Online encrypted PIN
  1E — Offline encrypted PIN
  1F — Offline plaintext PIN; signature if offline PIN fails
  5E — Signature
  5F — No CVM required

Condition Codes (selected):
  00 — Always
  03 — If terminal supports the CVM
  06 — If not unattended cash
  09 — If application currency matches transaction currency
```

---

## 14. Android HCE Bridge

### 14.1 ADB Relay Protocol

The GREENWIRE Android bridge (`core/android_manager.py`) uses ADB to forward APDU commands from the lab PC to an Android NFC HCE app running on the phone.

```
Lab PC                     ADB USB             Android Phone
──────                     ───────             ─────────────
greenwire.py               adb forward         HCE relay APK
  │                        tcp:7000             │
  ├── socket connect ────────────────────────▶ │
  │                                             │
  ├── APDU hex string ──────────────────────── ▶ │
  │                                             ├── HCE processCommandApdu()
  │◀── Response hex string ─────────────────── │
  │                                             │
```

Command: `python greenwire.py android-bridge --connect --forward-port 7000`

### 14.2 Rooted vs Non-Rooted Paths

| Feature | Rooted Device | Non-Rooted Device |
|---------|--------------|------------------|
| Key injection | Yes — can push keys to secure storage | No |
| APDU relay | Yes | Yes (via HCE APK) |
| Traffic capture | Yes (nfcd hooks) | Limited |
| ARQC verification | Yes (ICC_MK accessible) | No (keys in app only) |

### 14.3 APK Build Instructions

The HCE relay APK source is in `java/hce_relay/`.  Build with:
```
cd java/hce_relay
./gradlew assembleDebug
adb install -r build/outputs/apk/debug/hce_relay-debug.apk
```

---

## 15. Python HCE Emulator

### 15.1 Running the Emulator

```
python greenwire.py hce-emulator --pan 4111111111111111 --atc 1 --port 9000
```

The emulator listens on TCP port 9000 and accepts connections from any client that speaks the GREENWIRE APDU-over-TCP protocol.

### 15.2 TCP Protocol

```
Frame format (binary):
  [2 bytes big-endian length] [N bytes APDU hex ASCII]

Example (SELECT PPSE):
  00 26  (38 bytes follow)
  3030413430343030303045323530313431323932452E5359532E4444463031303000
  (hex of "00A4040007A0000000031010 00" in ASCII)
```

### 15.3 APDU Trace Format

Each transaction generates a JSON trace in `artifacts/`:

```json
{
  "session_id": "20250101T120000-ABC123",
  "pan": "4111111111111111",
  "dpan": "4895370000000001",
  "atc": 1,
  "arqc": "A1B2C3D4E5F60718",
  "steps": [
    {"cmd": "00A404000E325041592E5359532E444446303100", "resp": "6F...9000", "timing_ms": 4},
    {"cmd": "80A8000002830000", "resp": "7710...9000", "timing_ms": 7}
  ]
}
```

---

## 16. Crypto Primitives Reference

### 16.1 3DES Modes Used

| Use Case | Mode | IV | Notes |
|----------|------|----|-------|
| Key derivation (GP SCP02) | ECB | N/A | Encrypt one 8-byte block |
| Key derivation (EMV SK) | ECB | N/A | Two-key 3DES-112 |
| ARQC computation | CBC | 0x0000000000000000 | Full CDOL1 data |
| PIN block encryption | ECB | N/A | Single 8-byte block |
| Secure channel data (SCP02) | CBC | 0x0000000000000000 | With retail-MAC |

**Why ECB for derivation?**  Key derivation inputs are never repeated (each call uses a unique ATC or diversification constant), so ECB's lack of IV is not a security issue in this specific context.  CBC would be equivalent but adds unnecessary complexity.

### 16.2 AES-CMAC (SCP03)

SCP03 uses AES-CMAC as defined in NIST SP 800-38B and RFC 4493.

```
AES-CMAC(key, message):
  1. Generate subkeys K1, K2 from key using AES-ECB(key, 0^128)
  2. Pad message if necessary (ISO/IEC 7816-4 method 2)
  3. XOR last block with K1 (full block) or K2 (padded block)
  4. Compute CBC-MAC with IV=0^128
  Output: 16 bytes
```

In GREENWIRE: `core/key_generators._aes_cmac(key, data)` implements this using the `cryptography` package's `CMAC` primitive.

### 16.3 ISO 9797-1 MAC Algorithm 3 (Retail-MAC)

Used in SCP02 and in some EMV MAC computations.

```
Retail-MAC(key, message):
  Split key into K_L (left 8 bytes) and K_R (right 8 bytes)
  Pad message to multiple of 8 bytes (ISO 9797-1 padding method 2)
  Compute DES-CBC(K_L, IV=0^64, padded_message)  [single DES, not 3DES]
  Apply 3DES(key, last_block_output)  [final block: full 3DES]
  Output: 8 bytes
```

The final block uses full 3DES to prevent meet-in-the-middle attacks against the last block.

---

## 17. Testing Guide

### 17.1 Test Vectors

| Test | Input | Expected Output |
|------|-------|----------------|
| Luhn valid | `4111111111111111` | `True` |
| Luhn invalid | `4111111111111112` | `False` |
| Luhn check digit | body `411111111111111` | digit `1` |
| BIN lookup | `4111...` | scheme=`visa`, bank contains "visa" or "test" |
| GP key diversification | MK=`4041...4E4F`, serial=`01020304...` | deterministic 16-byte keys |
| ARQC length | any valid inputs | exactly 8 bytes |
| LUK batch | `luk_batch_size=7` | list of 7 entries |

### 17.2 How to Run pytest

```bash
# Run all tests
pytest tests/ -v

# Run only key generator tests
pytest tests/test_key_generators.py -v

# Skip tests that require hardware
pytest tests/ -v -m "not hardware"

# Run with coverage
pytest tests/ --cov=core --cov-report=term-missing
```

### 17.3 What Each Test Class Covers

| Class | Module | Coverage Focus |
|-------|--------|---------------|
| `TestLuhnAlgorithm` | card_validator | Luhn formula correctness, edge cases, formatting |
| `TestBINLookup` | card_validator | BIN database, scheme routing, 8 vs 6 digit priority |
| `TestValidatePan` | card_validator | Full profile, expiry, CVV, test/token flags |
| `TestPANRegistry` | pan_registry | JSON persistence, dedup, normalization |
| `TestSyntheticIdentity` | synthetic_identity | Generated PAN validity, prefix correctness |
| `TestKeyGenerators` | key_generators | Determinism, key lengths, ARQC byte count |
| `TestCardValidatorIntegration` | card_validator | Cross-cutting batch, service codes |

---

## 18. Troubleshooting

| Error | Cause | Solution |
|-------|-------|---------|
| `SCardEstablishContext failed` | PC/SC daemon not running | `net start SCardSvr` (Windows) or `sudo systemctl start pcscd` (Linux) |
| `No readers found` | USB reader disconnected or driver not installed | Reconnect reader; install CCID driver |
| `SW 6984 — Reference data invalid` | Wrong key version or key not present | Check key version with `python greenwire.py apdu --command 00CA006600` |
| `SW 6300 — Verification failed` | Wrong PIN or PIN try counter at 0 | Use correct PIN; if counter = 0 card is blocked |
| `SW 69 85 — Conditions of use not satisfied` | GENERATE AC called before GET PROCESSING OPTIONS | Follow the 12-step EMV flow in order |
| `ImportError: No module named 'cryptography'` | Python package missing | `pip install cryptography` |
| `ARQC mismatch at issuer host` | Wrong IMK or wrong diversification data | Verify PAN, PSN (PAN Sequence Number), and ATC in the test vector |
| `RuntimeError: acquire_unique_pan exhausted` | Registry collision; all generated PANs taken | Clear `data/generated_pans.json` or use a different BIN range |
| `adb: device not found` | Phone not authorised for debugging | Accept RSA fingerprint on phone; re-run `adb devices` |
| `JavaCard build failed` | SDK not installed or wrong version | Check `sdk/javacard/lib/api_classic.jar` exists; see `docs/JAVACARD_OFFLINE_SETUP.md` |

---

## 19. Glossary

| Term | Definition |
|------|-----------|
| **AAC** | Application Authentication Cryptogram — card declines offline |
| **AFL** | Application File Locator — tells terminal which records to read |
| **AID** | Application Identifier — identifies a card application (e.g. Visa Credit) |
| **AIP** | Application Interchange Profile — 2-byte bitmap of card capabilities |
| **APDU** | Application Protocol Data Unit — command/response pair sent to a smart card |
| **ARC** | Authorisation Response Code — 2-character issuer response (00=approved) |
| **ARPC** | Authorisation Response Cryptogram — issuer authenticates response to card |
| **ARQC** | Authorisation Request Cryptogram — card authenticates transaction to issuer |
| **ATC** | Application Transaction Counter — monotonically increasing 2-byte counter in the card |
| **BIN** | Bank Identification Number — first 6–8 digits of a PAN (synonym: IIN) |
| **CA** | Certification Authority — signs issuer public key certificates (Visa, MC) |
| **CDA** | Combined DDA/Application Cryptogram — links RSA signature with ARQC |
| **CDOL** | Card Risk Management Data Object List — defines ARQC input fields |
| **CVM** | Cardholder Verification Method — how the cardholder authenticates (PIN, signature) |
| **DDA** | Dynamic Data Authentication — card signs a nonce with ICC private key |
| **DEK** | Data Encryption Key — wraps other keys during transport |
| **DPAN** | Device PAN — token PAN used in HCE wallets instead of real FPAN |
| **EPP** | Encrypting PIN Pad — tamper-resistant PIN entry device on ATM |
| **FPAN** | Funding PAN — the real card PAN held by the issuer |
| **GP** | GlobalPlatform — smart card management standard for applet loading/management |
| **HCE** | Host Card Emulation — Android feature allowing apps to emulate NFC cards |
| **HSM** | Hardware Security Module — tamper-resistant cryptographic processor |
| **ICC** | Integrated Circuit Card — chip card (the chip is the ICC) |
| **IIN** | Issuer Identification Number — ISO synonym for BIN |
| **IMK** | Issuer Master Key — root key for ICC_MK diversification |
| **ISD** | Issuer Security Domain — the card's management domain (holds GP keys) |
| **JCOP** | JavaCard OpenPlatform — NXP's implementation of JavaCard + GlobalPlatform |
| **KCV** | Key Check Value — 3-byte fingerprint of a key (3DES(key, 0^16)[0:3]) |
| **LMK** | Local Master Key — the HSM's internal root key, never exported |
| **LUK** | Limited-Use Key — single-transaction HCE session key |
| **MDES** | Mastercard Digital Enablement Service — Mastercard's TSP |
| **MII** | Major Industry Identifier — first digit of a PAN/IIN |
| **PAN** | Primary Account Number — the card number |
| **PSN** | PAN Sequence Number — differentiates multiple cards with same PAN |
| **PPSE** | Proximity Payment System Environment — top-level NFC application directory |
| **RID** | Registered Application Provider Identifier — first 5 bytes of an AID |
| **SDA** | Static Data Authentication — simplest card authentication (replayed sig) |
| **SCP02** | Secure Channel Protocol 02 — 3DES GlobalPlatform secure channel |
| **SCP03** | Secure Channel Protocol 03 — AES GlobalPlatform secure channel |
| **SK** | Session Key — ephemeral key derived per transaction or secure channel |
| **TC** | Transaction Certificate — card approves offline transaction |
| **TLV** | Tag-Length-Value — encoding scheme used in EMV data |
| **TMK** | Terminal Master Key — root key for terminal working keys |
| **TPK** | Terminal PIN Key — key loaded in ATM EPP for PIN encryption |
| **TSP** | Token Service Provider — issues and manages payment tokens (VTS, MDES) |
| **TVR** | Terminal Verification Results — 5-byte bitmap of terminal checks |
| **VTS** | Visa Token Service — Visa's TSP |
| **ZMK** | Zone Master Key — key-encryption key between two HSMs |
| **ZPK** | Zone PIN Key — encrypts PIN blocks between acquirer components |

---

## 20. References

### EMVCo Specifications

| Document | Description |
|----------|-------------|
| EMV Book 1 | Application Independent ICC to Terminal Interface Requirements |
| EMV Book 2 | Security and Key Management |
| EMV Book 3 | Application Specification |
| EMV Book 4 | Cardholder, Attendant, and Acquirer Interface Requirements |
| EMV Contactless Book A | Architecture and General Requirements |
| EMV Contactless Book B | Entry Point Specification |
| EMV Contactless Book C-2 | Kernel 2 (Mastercard) Specification |
| EMV Contactless Book C-3 | Kernel 3 (Visa) Specification |
| EMV Contactless Book C-7 | Kernel 7 (Visa) Specification |

### ISO Standards

| Standard | Description |
|----------|-------------|
| ISO/IEC 7816-4 | Interindustry Commands for Interchange |
| ISO/IEC 7812-1 | Financial Services — Identification cards — Numbering system |
| ISO/IEC 14443 | Identification cards — Contactless cards — Proximity cards |
| ISO 9564 | Financial services — Personal Identification Number management |
| ISO 9797-1 | Message authentication codes — Part 1: Mechanisms using block ciphers |
| ISO 8583 | Financial transaction card-originated messages |

### GlobalPlatform Specifications

| Document | Description |
|----------|-------------|
| GP Card Specification v2.3.1 | Core card management standard |
| GP Amendment D | SCP03 (AES secure channel) |
| GP Amendment F | SCP11 (asymmetric secure channel) |
| GP SECSCP v1.0 | Secure Element configuration |

### NIST Publications

| Document | Description |
|----------|-------------|
| NIST SP 800-38A | Recommendation for Block Cipher Modes (CBC, ECB, CTR) |
| NIST SP 800-38B | Recommendation for Block Cipher Modes — CMAC Mode |
| NIST FIPS 46-3 | Data Encryption Standard (3DES) |
| NIST FIPS 197 | Advanced Encryption Standard (AES) |
| NIST SP 800-57 | Recommendation for Key Management |

### Other References

| Document | URL / Location |
|----------|---------------|
| JavaCard 3.1 Specification | oracle.com/java/javacard |
| JCOP 4 Reference Manual | nxp.com (NDA required) |
| apdu4j library | github.com/martinpaljak/apdu4j |
| GlobalPlatformPro (gp.jar) | github.com/martinpaljak/GlobalPlatformPro |
| pyscard (Python PC/SC) | pypi.org/project/pyscard |
| cryptography (Python) | pypi.org/project/cryptography |

---

*End of GREENWIRE Engineering Manual.  For questions contact the lab security engineer or refer to the relevant EMVCo specification.*
