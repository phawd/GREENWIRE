# GlobalPlatform, Java Card, and GREENWIRE AI Issuance Research

Purpose: connect source-backed research on normal GlobalPlatform and Java Card issuance with GREENWIRE's own tested emulator flows, so issuance work stays aligned across card, HSM, and merchant paths.

## Scope

This note covers:

- normal GlobalPlatform issuance flow
- normal Java Card / CAP development and deployment flow
- what "type of coding" looks like in practice for applets and deployment scripts
- GREENWIRE-tested examples that already run against the local HSM and merchant/gateway emulator stack
- where AI/learning-assisted issuance fits without pretending emulator artifacts are production certification

Reference inventory:

- [gp_javacard_ai_assets_2026-03-18.json](F:/repo/GREENWIRE/docs/sources/gp_javacard_ai_assets_2026-03-18.json)

## Normal GlobalPlatform Issuance

At a normal operational level, GlobalPlatform issuance is not "write arbitrary bytes to a card". The standard model is:

1. connect to the card manager / issuer security domain
2. open a secure channel, typically SCP02 or SCP03
3. authenticate with issuer or security-domain keys
4. load a package / load file
5. install and make selectable an application instance
6. optionally grant privileges or use delegated management through another security domain

The official GlobalPlatform overview is explicit that:

- applications are loaded as load files
- card management is performed through the card manager / security domain model
- secure communication is required through the secure channel

Source:

- [GlobalPlatform Overview PDF](https://globalplatform.org/uploads/GP_Overview.pdf)

GREENWIRE alignment:

- [core/globalplatform_reference.py](F:/repo/GREENWIRE/core/globalplatform_reference.py) centralizes the public lab keys and diversification metadata
- [core/cap_manager.py](F:/repo/GREENWIRE/core/cap_manager.py) handles CAP validation and GP tool invocation
- [tools/fetch_globalplatform_assets.py](F:/repo/GREENWIRE/tools/fetch_globalplatform_assets.py) records the public GP and Java Card asset locations

## Normal Java Card / CAP Flow

Oracle's Java Card Development Kit Tools User Guide describes the expected development pipeline as:

1. develop Java Card applets in Java
2. compile Java sources
3. convert classes to CAP
4. verify CAP files
5. deploy to simulator or target runtime

The guide also matters for architecture decisions:

- CAP format can be compact or extended
- large applications can be split into application and library packages
- sensitive or exclusive-use logic should remain in applet packages rather than library packages

Source:

- [Java Card Development Kit Tools User Guide](https://docs.oracle.com/en/java/javacard/3.2/jctug/java-card-development-kit-tools-user-guide.pdf)
- [Java Card Development Kit Simulator User Guide](https://docs.oracle.com/en/java/javacard/3.2/jcdksu/java-card-development-kit-simulator-user-guide.pdf)

GREENWIRE alignment:

- [javacard/applet/build.gradle](F:/repo/GREENWIRE/javacard/applet/build.gradle) models the offline compile/convert/deploy path
- [tools/build_javacard_applet.py](F:/repo/GREENWIRE/tools/build_javacard_applet.py) provides a best-effort offline builder and converter path
- [commands/cap_management.py](F:/repo/GREENWIRE/commands/cap_management.py) wraps CAP production and deployment from the modern CLI

## Type of Coding

There are really three code styles involved here.

### 1. Applet Coding

This is standard Java Card applet code:

- package structure under `javacard/applet/src`
- APDU processing via `process(APDU apdu)`
- AID registration and `install(...)`
- separation between applet package logic and any reusable library package logic

### 2. Deployment / Personalization Coding

This is not applet code. It is host-side orchestration:

- GP tool invocations
- CAP install commands
- AID/package metadata
- secure channel key selection and diversification

In GREENWIRE this shows up in:

- [core/cap_manager.py](F:/repo/GREENWIRE/core/cap_manager.py)
- [tools/build_javacard_applet.py](F:/repo/GREENWIRE/tools/build_javacard_applet.py)
- [javacard/applet/build.gradle](F:/repo/GREENWIRE/javacard/applet/build.gradle)

### 3. Issuer / HSM / Merchant Emulation Coding

This is where GREENWIRE is strongest as a testing platform:

- issuer-side synthetic identity and EMV artifact generation
- HSM-emulated key management and cryptogram services
- merchant-side transaction orchestration and gateway settlement emulation

Key modules:

- [core/hsm_service.py](F:/repo/GREENWIRE/core/hsm_service.py)
- [modules/merchant_emulator.py](F:/repo/GREENWIRE/modules/merchant_emulator.py)
- [commands/issuer_pipeline.py](F:/repo/GREENWIRE/commands/issuer_pipeline.py)
- [core/pipeline_services.py](F:/repo/GREENWIRE/core/pipeline_services.py)

## GREENWIRE-Tested Examples

These are not hypothetical notes. They were exercised locally in this repo.

### Example 1: HSM Keyset and Issuer-Crypto Helpers

Executed:

```powershell
python greenwire.py hsm --operation generate-default
```

Observed:

- default TMK/ZMK/ZPK/CVK/IMK/DEK set created
- persistent key store written to `data/hsm_keystore.json`

Then exercised directly through [core/hsm_service.py](F:/repo/GREENWIRE/core/hsm_service.py):

- IMK KCV: `9D0165`
- sample MAC: `D623111ACB94F4DF`
- sample CVV: `740`

Why it matters:

- this is the issuer/HSM side of issuance, not only card personalization
- it proves GREENWIRE can create and use issuer-side key material in its own emulator path

### Example 2: End-to-End Issuer Pipeline Against Local Emulators

Executed via direct command object invocation:

```python
from commands.issuer_pipeline import IssuerPipelineCommand
IssuerPipelineCommand().execute([
    "--pan", "4003123412341234",
    "--amount", "1.25",
    "--network", "ach",
])
```

Observed:

- PAN: `4003123412341234`
- amount: `1.25`
- network: `ach`
- ARQC: `6416060D3EE3235026822B1EA3B736B7`
- merchant terminal id in flow: `POS-EMU-01`
- payment gateway status: `accepted`

Why it matters:

- this runs GREENWIRE's own HSM service, personalization service, merchant service, transaction service, and payment-gateway emulator
- it is the strongest current local example of a "learning test issuance" because the result is not just a card blob; it is an issued-and-exercised transaction path

### Example 3: GP Tool Validation

Executed:

```powershell
java -jar static\java\gp.jar --version
```

Observed:

- GlobalPlatformPro version `v25.10.20`

Why it matters:

- it confirms the repo contains a current working GP binary for lab deployment flows

## AI / Learning Test Issuances

GREENWIRE currently has two AI-adjacent paths:

- heuristic APDU mutation / anomaly testing
  - [core/ai_vuln_testing.py](F:/repo/GREENWIRE/core/ai_vuln_testing.py)
- learning-based pattern capture and test selection
  - [modules/ai_learning_system.py](F:/repo/GREENWIRE/modules/ai_learning_system.py)
  - [modules/ai_test_generator.py](F:/repo/GREENWIRE/modules/ai_test_generator.py)

The correct way to think about AI issuance here is:

- AI does not replace GlobalPlatform or Java Card structure
- AI should tune test profiles, mutation seeds, card variants, and merchant/HSM regression coverage
- the canonical issuance steps still remain GP secure-channel operations plus CAP/app personalization plus issuer-host validation

Practical GREENWIRE use:

1. generate or personalize a card profile
2. run it through the HSM and pipeline services
3. use AI fuzzing or learned test selection to expand issuer/merchant/HSM regression around that issued artifact

That means "learning issuances" in GREENWIRE are best represented as:

- synthetic but scheme-aware issued cards
- replayable HSM-backed authorization artifacts
- merchant/gateway emulator executions
- APDU/kernel-focused mutation or anomaly sessions after issuance

## Current Gaps

Two gaps are worth noting.

### Modern CLI dynamic passthrough

The `greenwire_modern.py` wrappers for commands like `card-issue` and `cap` still require remainder-style bridging and do not cleanly accept direct option flags after the subcommand. The underlying command objects work; the wrapper UX is weaker than it should be.

### Full Java Card SDK redistribution

The repo can record Oracle Java Card asset locations and use local SDK jars when present, but the SDK itself remains licensing-gated and should not be treated as a freely bundled dependency.

## Bottom Line

For normal issuance:

- GlobalPlatform defines the secure operational model
- Java Card defines the applet/CAP packaging and conversion model
- GREENWIRE already supplies the emulator-side HSM, issuer, merchant, and gateway path needed to turn those concepts into replayable test issuances

For AI:

- use AI to expand testing around issued artifacts
- do not collapse issuance into generic fuzzing
- keep issuer, merchant, and HSM validation tied together

## Sources

- [GlobalPlatform Overview PDF](https://globalplatform.org/uploads/GP_Overview.pdf)
- [GlobalPlatformPro Keys Wiki](https://github.com/martinpaljak/GlobalPlatformPro/wiki/Keys)
- [Java Card Development Kit Tools User Guide](https://docs.oracle.com/en/java/javacard/3.2/jctug/java-card-development-kit-tools-user-guide.pdf)
- [Java Card Development Kit Simulator User Guide](https://docs.oracle.com/en/java/javacard/3.2/jcdksu/java-card-development-kit-simulator-user-guide.pdf)
- [EMVCo Contactless Product Approval Process](https://www.emvco.com/processes/contactless-product-approval-process/)
