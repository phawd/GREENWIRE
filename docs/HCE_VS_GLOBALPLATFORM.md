# HCE vs GlobalPlatform — Technical Architecture Comparison

*GREENWIRE Security Research Reference*

---

## Overview

GlobalPlatform (GP) and Host Card Emulation (HCE) solve the same problem — secure NFC payment
card functionality — from completely opposite architectural directions. Understanding their
differences is essential for GREENWIRE's testing and emulation capabilities.

---

## Architecture Comparison

```
┌─────────────────────────────────────────────────────────────────────┐
│                    GLOBALPLATFORM (GP)                              │
│                                                                     │
│  NFC Reader ──► ISO 14443 ──► NFC Controller ──► Secure Element    │
│                                                         │           │
│                                              ┌──────────┴────────┐  │
│                                              │   JCOP/JavaCard   │  │
│                                              │  ┌─────────────┐  │  │
│                                              │  │     ISD     │  │  │
│                                              │  │  ENC/MAC/DEK│  │  │
│                                              │  ├─────────────┤  │  │
│                                              │  │  Applets    │  │  │
│                                              │  │ (Visa/MC..) │  │  │
│                                              │  └─────────────┘  │  │
│                                              └───────────────────┘  │
│  Android app ──────────────────────────────► SE API (rarely)        │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    HCE (Host Card Emulation)                        │
│                                                                     │
│  NFC Reader ──► ISO 14443 ──► NFC Controller ──► Host CPU          │
│                                                         │           │
│                                              ┌──────────┴────────┐  │
│                                              │  Android OS       │  │
│                                              │  ┌─────────────┐  │  │
│                                              │  │HostApduSvc  │  │  │
│                                              │  │  (Wallet)   │  │  │
│                                              │  ├─────────────┤  │  │
│                                              │  │  TEE/Cloud  │  │  │
│                                              │  │ (LUK keys)  │  │  │
│                                              │  └─────────────┘  │  │
│                                              └───────────────────┘  │
│  TSP (Visa VTS / MC MDES) ──► OTA ──► Device TEE                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Key Differences

### 1. Key Storage

| Aspect | GlobalPlatform | HCE |
|--------|---------------|-----|
| Location | Dedicated Secure Element (JCOP chip) | Android TEE / StrongBox / Cloud |
| ENC/MAC/DEK | Stored in SE hardware registers | Derived per-session, stored in TEE |
| Physical isolation | Hardware tamper-resistant | Software + TEE (weaker boundary) |
| Key type | Static master keys + SCP sessions | LUK (Limited Use Keys) — ephemeral |
| Extraction risk | Extremely high effort (EAL6+) | Higher — TEE attacks possible |

### 2. AID Routing

**GlobalPlatform:**
```
SELECT AID → GP Card Manager routes to correct applet on SE
AID lives in SE's Application Registry
Loaded via INSTALL [for install] APDU over SCP02/SCP03
```

**HCE:**
```
SELECT AID → Android NFC stack routes to registered HostApduService
AID declared in AndroidManifest.xml / apduservice.xml
System routes by AID group category (CATEGORY_PAYMENT / CATEGORY_OTHER)
```

### 3. ISD vs TSP

| | GP ISD | HCE TSP |
|--|--------|---------|
| What it is | Issuer Security Domain on SE | Token Service Provider in cloud |
| Purpose | Manages applet lifecycle on card | Issues tokens (DPAN), manages LUKs |
| Key hierarchy | MasterKey → SCP sessions → ENC/MAC/DEK | IMK → ICC_MK → Session Keys (LUK) |
| Access | SCP02/SCP03 APDU channel | REST/HTTPS API (Visa VTS / MC MDES) |
| Credential grant | Card issuer installs applets | Issuer registers with payment network |
| Examples | NXP JCOP ISD | Visa VTS, Mastercard MDES, Amex |

### 4. Key Derivation Math

**GP SCP02 (ISD session keys):**
```
S-ENC = 3DES_ECB(MasterKey,  0x0182 || 0x00*12 || SeqCtr)
S-MAC = 3DES_ECB(MasterKey,  0x0101 || 0x00*12 || SeqCtr)
S-DEK = 3DES_ECB(MasterKey,  0x0181 || 0x00*12 || SeqCtr)
```
*Purpose: secure OTA channel for applet management*

**EMV/HCE LUK (per-transaction session keys):**
```
ICC_MK  = 3DES_ECB(ISS_MK, PAN[last16] || PAN[last16] XOR 0xFF)   # Option A
LUK_left  = 3DES_ECB(ICC_MK, ATC || 0x0000 || ATC || 0x0000)[:8]
LUK_right = 3DES_ECB(ICC_MK, ATC || 0xFFFF || ATC || 0xFFFF)[:8]
LUK       = LUK_left || LUK_right
ARQC      = MAC_3DES(LUK, txn_data_padded)[:8]
```
*Purpose: authenticate each individual NFC tap*

**GP SCP03 (AES, Amendment D):**
```
S-ENC  = AES_CMAC(MasterKey, label=0x04 || context)
S-MAC  = AES_CMAC(MasterKey, label=0x06 || context)
S-RMAC = AES_CMAC(MasterKey, label=0x07 || context)
context = HostChallenge(32B) || CardChallenge(8B)
```
*Purpose: secure AES OTA channel (JCOP5/modern cards)*

### 5. Token Flow: Real PAN → DPAN

GP has no concept of tokenization — the real AID and card data lives on the SE.

HCE uses tokenization to protect the real PAN:

```
Real Card (FPAN):  4111 1111 1111 1111
                          │
                   TSP Tokenization
                          │
Device Token (DPAN): 4895 0000 0000 0001   ← different BIN range
Token Key (LUK):     derived from IMK + DPAN + ATC
                          │
              Delivered OTA via HTTPS/SCP03 to device TEE
                          │
NFC Transaction:    DPAN + ARQC(LUK, txn_data)
                          │
               Acquirer → Network → TSP detokenizes → Issuer
```

DPAN is issued by the TSP for a specific device. Even if intercepted, it cannot be used on
another device (device binding via device fingerprint / cryptographic attestation).

### 6. OTA Provisioning Contrast

**GP OTA (applet management):**
```
1. TSM opens SCP02/03 channel to SE ISD
2. INSTALL [for load] → LOAD (CAP chunks) → INSTALL [for install]
3. Applet now lives permanently in SE flash
4. Keys rotated via PUT KEY under secure channel
```

**HCE OTA (token provisioning):**
```
1. User adds card → Wallet calls TSP provisioning API
2. TSP generates DPAN + LUK batch
3. Keys delivered via HTTPS to TEE (Android StrongBox/KeyStore)
4. LUK has limited use count (e.g., 10 taps) — replenished by TSP
5. No persistent card data on device — "cloud card"
```

### 7. Contactless Protocol Stack

Both use ISO 14443 at Layer 1-3, but diverge at Layer 4:

```
Layer      GP (SE-based)                HCE
─────────────────────────────────────────────────────────
Physical   ISO 14443 Type A (13.56MHz)  ISO 14443 Type A
Anti-col   ISO 14443-3 (ATQA/SAK/UID)  ISO 14443-3
Transport  ISO 14443-4 (T=CL)          ISO 14443-4 (T=CL)
App        ISO 7816-4 APDUs            ISO 7816-4 APDUs
           ← SE processes directly      ← HostApduService processes
Crypto     SE hardware                 TEE / software
Key store  SE EEPROM/Flash             TEE KeyStore / cloud
```

---

## GREENWIRE Integration Points

### GP Path (core/scp_crypto.py, core/gp_native.py, greenwire/jcop.py)
```python
from core.gp_native import GPNativeExecutor
from modules.android_nfc_bridge import AndroidNFCBridge

comm  = AndroidNFCBridge()          # ADB → real card reader
gp    = GPNativeExecutor(comm, scp="scp02")
gp.select_isd()
gp.open_secure_channel()
gp.install_cap(cap_bytes, pkg_aid, app_aid)
```

### HCE Path (modules/hce_manager.py, modules/tsp_integration.py)
```python
from modules.tsp_integration import VTSSandboxClient
from modules.hce_manager import HCEManager

tsp  = VTSSandboxClient(api_key="...", api_secret="...")
dpan = tsp.provision_token(fpan="4111111111111111", device_id="android_01")

hce  = HCEManager(device_id="emulator-5554")
hce.deploy()
hce.load_token(dpan)
hce.start_service(aid="A0000000031010")
# Device now responds to NFC taps as a Visa card
```

---

## Security Model Comparison

| Risk | GP (SE) | HCE |
|------|---------|-----|
| Key extraction | EAL6+ hardware resistance | TEE attack surface exists |
| Replay attack | SCP sequence counter | ATC counter + LUK use limit |
| Cloning | Physically impossible | Mitigated by device binding |
| OTA attack | SCP MAC integrity | TLS + token binding |
| Lost/stolen | Card PIN / block ISD | Token lifecycle management via TSP |
| Fuzzing surface | SE APDU parser | HostApduService processCommandApdu() |

---

## TSP Endpoints (Sandbox)

### Visa VTS Sandbox
```
Base URL:  https://sandbox.api.visa.com/vts/
Auth:      mTLS + API key (developer.visa.com)
Tokenize:  POST /v2/enrollments
Lifecycle: PUT  /v2/tokens/{tokenUniqueReference}
Keys:      GET  /v2/tokens/{ref}/keys
```

### Mastercard MDES Sandbox
```
Base URL:  https://sandbox.api.mastercard.com/mdes/
Auth:      OAuth 1.0a (developer.mastercard.com)
Tokenize:  POST /mdes/cloud/1/0/tokenize
Lifecycle: POST /mdes/cloud/1/0/suspend|resume|delete
Keys:      embedded in tokenize response (encryptedPayload)
```

---

## Rooted Android HCE Testing

On a rooted Android device connected via ADB:

1. **NFC must be enabled** — `adb shell svc nfc enable` (requires root for non-UI)
2. **HCE service deployment** — push APK via `adb install -r greenwire-hce.apk`
3. **Default wallet** — set via `adb shell cmd nfc set-default-wallet-role`
4. **APDU relay** — GREENWIRE intercepts APDUs from the HCE service via local socket
5. **Crypto** — GREENWIRE computes ARQC/LUK using `modules/crypto/emv_crypto.py`
6. **Response** — sent back through the relay to HostApduService → NFC reader

See: `modules/android_hce_bridge.py` for the full ADB relay implementation.
