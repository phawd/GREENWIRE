
# Applet Overview

This document explains how the example `JCOPCardManager` applet interface works, its limitations, and how to load or remove applets from a smart card, including CA key/certificate usage for field/production installs.

---

## How it Works

The Java class `JCOPCardManager` provides basic methods to connect to a smart card and issue simple APDU commands. It uses the Java Smart Card I/O API to communicate with a JCOP-based card via PC/SC. The class demonstrates selecting an application, searching for a certificate authority, and disconnecting from the card. When invoked from the command line, it establishes a T=1 connection with the first available terminal:

```java
CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(0);
card = terminal.connect("T=1");
```

---

## Uses

This minimal manager class lets you issue simple APDUs for demonstration purposes. It can be adapted to enroll new smart cards, search for root certificate authorities, or experiment with GlobalPlatform installation sequences before implementing a full-featured loader.

---

## Loading Applets with CA Key/Certificate

In practice, loading an applet onto a Java Card requires GlobalPlatform commands (`INSTALL [for load]`, `INSTALL [for install]`, and `INSTALL [for make selectable]`). For field/production use, you must authenticate with the Card Manager using the correct CA key/certificate.

**CA key/cert file format:** See `ca_keys.json` in the repo. Each entry should include `rid`, `index`, `modulus`, and `exponent` fields matching your card/AID.

**General sequence:**
1. **Load** – transfer the CAP file containing the applet.
2. **Install** – create an instance on the card.
3. **Make selectable** – allow the applet to receive `SELECT` commands.

**Example: Load and install with GlobalPlatformPro and custom CA key**
```bash
java -jar gp.jar --install yourApplet.cap --package A0000000031010 --applet A0000000031010 --priv ca_keys.json
```
Or with GREENWIRE CLI:
```bash
python greenwire.py install-cap --cap-file yourApplet.cap --tool gpp --aid A0000000031010 --ca-file ca_keys.json
```

---

## Unloading Applets

Removing an applet is usually done with the GlobalPlatform `DELETE` command. After authenticating with the Card Manager (using the correct CA key/cert), you can delete the applet instance and optionally the package to reclaim space.

**Example:**
```bash
java -jar gp.jar --delete A0000000031010 --priv ca_keys.json
```

---

## Limitations

- `JCOPCardManager` only shows a minimal connection workflow. It does not authenticate to the Card Manager or issue GlobalPlatform install/delete commands.
- Actual applet management requires knowledge of the card keys and proper security domains. Those details are outside the scope of this repository.
- The demo uses T=1 protocol and assumes a PC/SC reader is available.

---

## Usage Examples

Compile the Java class and run the demo:
```bash
javac JCOPCardManager.java
java JCOPCardManager
```

For real-world applet loading or deletion, use external tools after compiling your applet into a CAP file and ensure your CA key/cert is present and valid:
```bash
# Load and install (example using GlobalPlatformPro and CA key)
java -jar gp.jar --install yourApplet.cap --package A0000000031010 --applet A0000000031010 --priv ca_keys.json

# Delete an applet by AID (with CA key)
java -jar gp.jar --delete A0000000031010 --priv ca_keys.json
```

Or use the GREENWIRE CLI for install:
```bash
python greenwire.py install-cap --cap-file yourApplet.cap --tool gpp --aid A0000000031010 --ca-file ca_keys.json
```

---

This overview should help you understand where the sample code fits in a typical GlobalPlatform workflow, and how to use CA keys/certs for field/production installs.
