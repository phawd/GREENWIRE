# GREENWIRE Third-Party Licenses

This document lists the third-party specifications, standards, and libraries
that GREENWIRE references or is derived from, together with their licensing
terms.

---

## 1. Java Card API Specification Stubs

**Files:** `src/javacard/framework/*.java`, `src/javacard/security/*.java`,
`src/javacardx/crypto/Cipher.java`

**Description:** These files are *compilation stubs* written from scratch to
reproduce only the public API surface (class names, method signatures, and
public constants) of the Java Card 3.0.5 Classic Edition API, as documented in
the Oracle Java Card specification. No binary or source code from Oracle is
included.

**Specification:** Java Card Platform Specification 3.0.5 Classic Edition
© Oracle and/or its affiliates. All rights reserved.

**Status:** API stubs do not constitute a redistribution of Oracle's
implementation. They are analogous to clean-room header files. GREENWIRE
contributors confirm that these stubs were authored independently without
reference to Oracle's proprietary source code. Users who intend to compile
for a real Java Card target should replace these stubs with the Oracle-supplied
`api.jar` from the Java Card Development Kit (JCDK).

**JCDK Download:** <https://www.oracle.com/java/technologies/javacard-downloads.html>

---

## 2. EMV Specifications

**Description:** GREENWIRE implements a subset of the EMV Contactless
Communication Protocol Specification (CCPS) and the EMV Contactless Kernel
specifications published by EMVCo.

**Specification owner:** EMVCo LLC
**Website:** <https://www.emvco.com>

**License:** EMVCo specifications are publicly available under the EMVCo Terms
of Use. Implementation in a product does not require a licence fee; however,
formal EMVCo Level 1 / Level 2 certification may be required before deployment
in payment infrastructure.

---

## 3. ISO / IEC Standards

| Standard   | Title                                         | Use in GREENWIRE            |
|------------|-----------------------------------------------|-----------------------------|
| ISO 7816-4 | Interindustry commands for interchange        | APDU structure & SW codes   |
| ISO 14443  | Proximity cards – contactless communication   | NFC communication protocol  |
| ISO 9797   | Message authentication codes                  | MAC padding modes in Cipher |

These standards are published by ISO/IEC and are available for purchase from
national standards bodies.

---

## 4. GNU General Public License v2

GREENWIRE itself is distributed under the **GNU General Public License,
version 2 or later** (GPL-2.0-or-later). See [`LICENSE`](./LICENSE) for the
full text.

---

*Last updated: 2026-03-26*
