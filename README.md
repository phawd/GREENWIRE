# GREENWIRE 4.x

Google Wallet NFC / EMV card-emulation applet written in Java Card.

## Overview

GREENWIRE is a Java Card applet that implements a subset of the EMV Contactless
(ISO 14443 / EMVCo) protocol to enable NFC-based payment emulation compatible
with Google Wallet and similar contactless payment schemes.

### Key features

- **EMV transaction flow** – SELECT, GET PROCESSING OPTIONS, READ RECORD,
  GENERATE AC, and GET DATA instructions.
- **Cardholder PIN** – `OwnerPIN`-backed PIN verification with configurable
  try-limit and blocking.
- **ATC tracking** – Application Transaction Counter incremented on each
  transaction to prevent replay attacks.
- **Java Card API stubs** – clean-room compilation stubs for
  `javacard.framework`, `javacard.security`, and `javacardx.crypto` so the
  project can be compiled without the proprietary Oracle JCDK on the
  class-path.

## Project layout

```
GREENWIRE/
├── src/
│   ├── javacard/
│   │   ├── framework/       # Java Card API compilation stubs
│   │   │   ├── APDU.java
│   │   │   ├── AID.java
│   │   │   ├── Applet.java
│   │   │   ├── ISO7816.java
│   │   │   ├── ISOException.java
│   │   │   ├── JCSystem.java
│   │   │   ├── OwnerPIN.java
│   │   │   ├── PIN.java
│   │   │   ├── PINException.java
│   │   │   ├── CardException.java
│   │   │   └── CardRuntimeException.java
│   │   └── security/
│   │       ├── CryptoException.java
│   │       └── Key.java
│   ├── javacardx/
│   │   └── crypto/
│   │       └── Cipher.java  # javacardx.crypto.Cipher stub
│   └── com/greenwire/wallet/
│       └── GreenWireApplet.java   # Main applet
├── build.xml                # Ant build file
├── THIRD_PARTY_LICENSES.md # Legal / licensing notes
└── LICENSE                  # GPL-2.0
```

## Building

### Prerequisites

- **Java 8+** (`javac`)
- **Apache Ant** (for the provided `build.xml`)  
  *or* any IDE / build tool that can compile a plain Java source tree.

> For a real Java Card target replace the stubs in `src/javacard/` with
> `api.jar` from the [Oracle Java Card Development Kit][jcdk].

### Compile with Ant

```bash
ant compile        # compile to build/classes/
ant jar            # produce dist/greenwire.jar
ant clean          # remove build artefacts
```

### Compile with javac directly

```bash
javac -sourcepath src -d build/classes \
      src/com/greenwire/wallet/GreenWireApplet.java
```

## Security

- Default PIN is `0000`; **must** be changed via a secure channel before
  deployment.
- The `GENERATE AC` cryptogram in the current stub is a **placeholder** (`0xDEADBEEF00000000`).
  A production implementation must compute a proper 3DES / AES-CMAC
  Application Cryptogram using the issuer application keys.
- Key material must be loaded through a secure Globalplatform-compliant
  channel during card personalisation.

## Legal

See [THIRD_PARTY_LICENSES.md](./THIRD_PARTY_LICENSES.md) for details on
third-party specifications and standards referenced by this project.

GREENWIRE is licensed under the **GNU General Public License v2** – see
[LICENSE](./LICENSE).

[jcdk]: https://www.oracle.com/java/technologies/javacard-downloads.html
