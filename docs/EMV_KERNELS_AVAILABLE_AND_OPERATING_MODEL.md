# EMV Kernels: Types, Availability, and Operating Model

Research date: March 18, 2026

Purpose: provide a source-backed working guide to the EMV contact and contactless kernel landscape, with specific attention to what GREENWIRE can test locally and what remains scheme-controlled.

## Scope

This note focuses on:

- kernel types and where they sit in transaction processing
- which public kernel materials are actually available
- the practical difference between scheme-managed kernels `C-2` through `C-7` and the shared EMVCo `C-8` kernel effort
- issuer, merchant, and HSM/host implications
- how this maps onto GREENWIRE's local emulators and test assets

Related local material:

- [docs/kernels/README.md](F:/repo/GREENWIRE/docs/kernels/README.md)
- [docs/KERNEL_CARD_WRITING_DIFFERENCES.md](F:/repo/GREENWIRE/docs/KERNEL_CARD_WRITING_DIFFERENCES.md)
- [docs/kernels/C-2_PayPass.md](F:/repo/GREENWIRE/docs/kernels/C-2_PayPass.md)
- [docs/kernels/C-3_VISA.md](F:/repo/GREENWIRE/docs/kernels/C-3_VISA.md)
- [docs/kernels/C-4_AMEX.md](F:/repo/GREENWIRE/docs/kernels/C-4_AMEX.md)
- [docs/kernels/C-5_JCB.md](F:/repo/GREENWIRE/docs/kernels/C-5_JCB.md)
- [docs/kernels/C-6_DISCOVER.md](F:/repo/GREENWIRE/docs/kernels/C-6_DISCOVER.md)
- [docs/kernels/C-7_CUP.md](F:/repo/GREENWIRE/docs/kernels/C-7_CUP.md)
- [docs/EMV-Book-C-8-Test-Cases-v1.1c_251021.pdf](F:/repo/GREENWIRE/docs/EMV-Book-C-8-Test-Cases-v1.1c_251021.pdf)
- [docs/EMV®-Contactless-Kernel-Specification-FAQ.pdf](F:/repo/GREENWIRE/docs/EMV®-Contactless-Kernel-Specification-FAQ.pdf)

## What a Kernel Is

In practice, the kernel is the Level 2 terminal-side transaction logic that interprets EMV application data, runs scheme-specific or EMVCo-defined decision logic, applies terminal risk-management rules, drives CVM behavior, and packages the data needed for online authorization and clearing.

That means:

- the card does not "contain the kernel"
- the merchant acceptance device or terminal software stack contains the kernel
- the issuer and HSM do not execute the kernel, but must understand the data the kernel produces

From an engineering perspective:

- card issuance concerns AIDs, EMV data objects, CVM lists, risk settings, and issuer scripts
- merchant acceptance concerns terminal configuration, TTQ/CTQ handling, CVM rules, TAC/IAC interplay, and online/offline decision logic
- issuer host and HSM concerns ARQC/ARPC processing, key derivation, cryptogram validation, issuer authentication, script handling, and dispute/monitoring visibility into kernel behavior

## Contact vs Contactless

For contact transactions, kernel behavior is embedded in the terminal application stack but is less commonly described using the `Book C-X` labels.

For contactless transactions, EMVCo and the schemes publish process material using the `Book C-X` model:

- `C-2`: PayPass / Mastercard-managed contactless kernel path
- `C-3`: Visa-managed contactless kernel path
- `C-4`: American Express-managed contactless kernel path
- `C-5`: JCB-managed contactless kernel path
- `C-6`: Discover-managed contactless kernel path
- `C-7`: China UnionPay-managed contactless kernel path
- `C-8`: shared EMVCo contactless kernel

Public source anchors:

- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)
- [EMV Contactless Kernel announcement PDF](https://www.emvco.com/wp-content/uploads/2022/11/EMVCo-Publishes-EMV%C2%AE-Contactless-Kernel-Specification.pdf)
- [EMV Contactless Kernel testing press release PDF](https://www.emvco.com/wp-content/uploads/2024/10/ECK-Testing-PR_-FINAL-1.pdf)

## What Is Publicly Available

The public availability line is important because it affects what GREENWIRE can lawfully bundle, emulate, or document.

### Publicly Available or Commonly Accessible

- EMVCo process pages
- EMVCo FAQ and announcement material for the shared kernel initiative
- public ICS and approval-process forms
- public bulletins and testing-process PDFs
- local authorized PDF copies placed in `docs/`
- public scheme or ecosystem guidance documents

### Usually Not Publicly Bundled Here

- proprietary full scheme kernel specifications for `C-2` through `C-7`
- scheme certification packs that require agreements or portal access
- production terminal kernel source code or certified binaries

This is why GREENWIRE maintains:

- source-backed kernel metadata and notes
- emulator/test abstractions
- local inventories of approved/public documents

but does not claim to ship licensed scheme Level 2 kernels.

## Kernel-by-Kernel Operating Differences

### C-2 through C-7

The most important operational point is that `C-2` through `C-7` are not just "six names for the same thing". They differ in:

- transaction selection behavior
- CVM preference and fallback expectations
- terminal parameterization and testing paperwork
- optional data objects and decision branches
- host interpretation of outcomes and issuer monitoring expectations

Those differences matter in three places.

### Issuer View

From issuance, the kernel family changes what must be consistent between:

- AID and application profile
- CVM list and contactless risk thresholds
- issuer action codes and risk profile
- issuer application data structure
- ARQC validation expectations and host routing data

If the issuer side personalizes cards without considering the target acceptance environment, a kernel may still read the card, but the transaction path will not behave as intended.

### Merchant View

From the merchant terminal side, the kernel defines much of the observable behavior:

- whether a contactless path stays in contactless or falls back
- which CVM is requested
- how the terminal interprets limits and capabilities
- which tags are required or optional at decision points
- what test plans and ICS declarations apply

This is the place where GREENWIRE's merchant emulators and terminal snapshots are most useful.

### HSM / Host View

From the HSM and issuer-host side, the kernel differences show up indirectly:

- ARQC and CDOL-derived payload contents
- CVM result patterns
- TVR/TSI and risk-result combinations
- issuer script timing and expectations
- fraud-monitoring patterns, especially for no-CVM and fallback paths

An HSM does not "run kernel C-3", but it absolutely sees the downstream consequences of a `C-3` or `C-8` decision path.

## The Shared C-8 Kernel

The shared `C-8` kernel matters because EMVCo is trying to simplify terminal implementation and testing by reducing duplicated scheme-specific L2 logic.

Public EMVCo material indicates:

- the shared kernel is an EMVCo-led initiative
- approval testing exists for the kernel
- the broader contactless approval process still contains scheme-managed components around it

Practical inference from the public material:

- `C-8` reduces some terminal-side fragmentation
- it does not remove issuer configuration work
- it does not eliminate host/HSM responsibilities
- it does not mean `C-2` through `C-7` cease to matter immediately in deployed estates

That is an inference from the public process material, not a verbatim claim from one line in a specification.

## GREENWIRE Mapping

GREENWIRE currently models the kernel space in three ways.

### 1. Registry / Metadata Layer

- [core/emv_kernel_registry.py](F:/repo/GREENWIRE/core/emv_kernel_registry.py)

This provides a source-backed registry of public kernel identities and their scheme mapping.

### 2. Documentation Layer

- [docs/kernels/README.md](F:/repo/GREENWIRE/docs/kernels/README.md)
- per-kernel notes under `docs/kernels/`

This is the human-readable layer for issuer, merchant, and HSM viewpoints.

### 3. Emulator / Testing Layer

- [modules/emvco_card_personalizer.py](F:/repo/GREENWIRE/modules/emvco_card_personalizer.py)
- [modules/merchant_emulator.py](F:/repo/GREENWIRE/modules/merchant_emulator.py)
- [greenwire/core/smart_vulnerability_card.py](F:/repo/GREENWIRE/greenwire/core/smart_vulnerability_card.py)

This is where GREENWIRE can actually vary:

- floor limits
- CVM behavior
- pattern injection at transaction decision points
- transaction logging back onto the test card object

## Recommended Use Inside GREENWIRE

For local testing:

1. use the kernel notes and registry to choose the transaction family you are targeting
2. issue or create a synthetic test card with the intended scheme profile
3. run merchant or wallet/contactless emulator flows
4. vary floor-limit and CVM behavior through the mutation-capable test-card path
5. inspect terminal snapshots, mutation logs, and gateway results together

For documentation and compliance tracking:

1. keep new authorized PDFs under `docs/`
2. keep machine-readable inventories under `docs/sources/`
3. avoid claiming bundle-level support for proprietary kernel binaries unless the artifacts are actually licensed and present

## Sources

- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)
- [EMV Contactless Kernel announcement PDF](https://www.emvco.com/wp-content/uploads/2022/11/EMVCo-Publishes-EMV%C2%AE-Contactless-Kernel-Specification.pdf)
- [EMV Contactless Kernel testing press release PDF](https://www.emvco.com/wp-content/uploads/2024/10/ECK-Testing-PR_-FINAL-1.pdf)
- [kernel_assets.json](F:/repo/GREENWIRE/docs/sources/kernels/kernel_assets.json)
- local authorized kernel and TTA PDFs already stored in [docs](F:/repo/GREENWIRE/docs)
