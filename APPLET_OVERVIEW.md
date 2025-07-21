# Applet Overview

This document explains how the example `JCOPCardManager` applet interface works,
its limitations, and how to load or remove applets from a smart card.

## How it Works

The Java class `JCOPCardManager` provides basic methods to connect to a smart
card and issue simple APDU commands. It uses the Java Smart Card I/O API to
communicate with a JCOP-based card via PC/SC. The class demonstrates selecting an
application, searching for a certificate authority, and disconnecting from the
card. When invoked from the command line, it establishes a T=1 connection with
the first available terminal:

```
CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(0);
card = terminal.connect("T=1");
```

## Uses

This minimal manager class lets you issue simple APDUs for demonstration
purposes. It can be adapted to enroll new smart cards, search for root
certificate authorities, or experiment with GlobalPlatform installation
sequences before implementing a full-featured loader.

## Loading Applets

In practice, loading an applet onto a Java Card requires GlobalPlatform commands
(`INSTALL [for load]`, `INSTALL [for install]`, and `INSTALL [for make selectable]`).
This repository does not include a full loader, but you would typically use a
tool like `gp.jar` or `GlobalPlatformPro` to send these commands after entering
Card Manager authentication keys. The general sequence is:

1. **Load** – transfer the CAP file containing the applet.
2. **Install** – create an instance on the card.
3. **Make selectable** – allow the applet to receive `SELECT` commands.

## Unloading Applets

Removing an applet is usually done with the GlobalPlatform `DELETE` command.
After authenticating with the Card Manager, you can delete the applet instance
and optionally the package to reclaim space.

## Limitations

- `JCOPCardManager` only shows a minimal connection workflow. It does not
authenticate to the Card Manager or issue GlobalPlatform install/delete
commands.
- Actual applet management requires knowledge of the card keys and proper
security domains. Those details are outside the scope of this repository.
- The demo uses T=1 protocol and assumes a PC/SC reader is available.

## Usage Examples

Compile the Java class and run the demo:

```bash
javac JCOPCardManager.java
java JCOPCardManager
```

For real-world applet loading or deletion, use external tools after compiling
your applet into a CAP file:

```bash
# Load and install (example using GlobalPlatformPro)
java -jar gp.jar --install yourApplet.cap --default

# Delete an applet by AID
java -jar gp.jar --delete A000000003000000
```

This overview should help you understand where the sample code fits in a typical
GlobalPlatform workflow.
