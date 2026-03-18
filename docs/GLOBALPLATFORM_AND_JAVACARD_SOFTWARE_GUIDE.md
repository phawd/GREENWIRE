# GlobalPlatform and Java Card Software Guide

Research date: March 18, 2026

Purpose: document the major software layers involved in Java Card issuance and post-issuance content management, and relate them to GREENWIRE's offline toolchain and emulator-backed workflows.

## Scope

This guide covers:

- GlobalPlatform operating model and software
- Java Card software and tooling
- the difference between applet code, CAP build tooling, and issuer/deployment orchestration
- practical command patterns for loading, installing, and testing
- where GREENWIRE fits into that stack

Related local files:

- [docs/GLOBALPLATFORM_JAVACARD_AI_RESEARCH.md](F:/repo/GREENWIRE/docs/GLOBALPLATFORM_JAVACARD_AI_RESEARCH.md)
- [docs/JAVACARD_OFFLINE_SETUP.md](F:/repo/GREENWIRE/docs/JAVACARD_OFFLINE_SETUP.md)
- [static/java/globalplatform_assets.json](F:/repo/GREENWIRE/static/java/globalplatform_assets.json)
- [docs/sources/gp_javacard_ai_assets_2026-03-18.json](F:/repo/GREENWIRE/docs/sources/gp_javacard_ai_assets_2026-03-18.json)

## GlobalPlatform: What It Controls

GlobalPlatform is the card content-management and secure-channel model, not the applet language itself.

Public GlobalPlatform overview material shows the core lifecycle clearly:

1. transfer load files to the card
2. install application instances from those load files
3. manage lifecycle state and deletion through the Card Manager
4. open secure channels for authenticated and integrity-protected management
5. optionally support delegated management through security domains

Source:

- [GlobalPlatform Overview PDF](https://globalplatform.org/uploads/GP_Overview.pdf)

Operationally, that means the important software categories are:

- secure-channel and card-management tools
- CAP loading and install wrappers
- card issuer key management
- personalization/orchestration code

## GlobalPlatform Software You Will Actually Encounter

### GlobalPlatformPro

For GREENWIRE, the primary practical GP tool is GlobalPlatformPro.

Public GPPro documentation shows:

- it runs as `java -jar gp.jar` or `gp.exe` on Windows
- it requires Java and a PC/SC reader
- JDK 17 LTS or later is currently required according to the February 12, 2026 wiki revision
- `gp -r` lists readers or selects them
- `-v`, `-d`, and `GP_TRACE=true` increase protocol visibility

Sources:

- [GPPro Getting started](https://github.com/martinpaljak/GlobalPlatformPro/wiki/Getting-started)
- [GPPro Keys](https://github.com/martinpaljak/GlobalPlatformPro/wiki/Keys)
- [gp.jar latest release endpoint](https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar)

Publicly documented GPPro keying notes that matter for lab work:

- the default development key is `404142434445464748494A4B4C4D4E4F`
- diversification templates include `emv`, `visa2`, `visa`, and `kdf3`
- incorrect keys can permanently lock cards

### GPShell / Other GP Stacks

Other tooling exists, including GPShell and C-library-backed GlobalPlatform stacks, but GREENWIRE is presently aligned around GPPro because:

- it is script-friendly
- it matches the repo's static and offline distribution work
- it works cleanly in Windows-oriented environments

Reference:

- [kaoh/globalplatform](https://github.com/kaoh/globalplatform)

## Java Card: What It Controls

Java Card is the applet execution and packaging environment.

Oracle's public documentation and downloads indicate the normal workflow is:

1. write Java Card applet code
2. compile Java sources
3. convert classes to CAP
4. verify CAP packaging and dependencies
5. deploy to simulator or card

Sources:

- [Java Card Development Kit Tools User Guide](https://docs.oracle.com/en/java/javacard/3.2/jctug/java-card-development-kit-tools-user-guide.pdf)
- [Java Card Development Kit Simulator User Guide](https://docs.oracle.com/en/java/javacard/3.2/jcdksu/java-card-development-kit-simulator-user-guide.pdf)
- [Java Card downloads](https://www.oracle.com/java/technologies/javacard-downloads.html)

## Software Layers and Coding Types

There are three different coding layers in this ecosystem.

### 1. Applet Code

This is Java Card application code under a package/AID model.

Typical characteristics:

- `install(...)`
- `process(APDU apdu)`
- constrained Java Card APIs
- APDU parsing and state handling

GREENWIRE examples live under:

- `javacard/applet/src/main/java/...`

### 2. Build and Packaging Code

This is host-side build logic, not applet runtime logic.

Typical characteristics:

- compile
- convert
- CAP packaging
- SDK and toolchain path management

GREENWIRE examples:

- [javacard/applet/build.gradle](F:/repo/GREENWIRE/javacard/applet/build.gradle)
- [tools/build_javacard_applet.py](F:/repo/GREENWIRE/tools/build_javacard_applet.py)
- [commands/cap_management.py](F:/repo/GREENWIRE/commands/cap_management.py)

### 3. Issuance / Deployment / Personalization Code

This is where GlobalPlatform and issuer operations actually meet the card estate.

Typical characteristics:

- secure-channel key selection
- CAP load/install orchestration
- issuer key diversification
- post-personalization tests
- merchant and HSM emulator routing

GREENWIRE examples:

- [core/globalplatform_reference.py](F:/repo/GREENWIRE/core/globalplatform_reference.py)
- [core/cap_manager.py](F:/repo/GREENWIRE/core/cap_manager.py)
- [core/pipeline_services.py](F:/repo/GREENWIRE/core/pipeline_services.py)
- [commands/issuer_pipeline.py](F:/repo/GREENWIRE/commands/issuer_pipeline.py)

## Normal Command Patterns

The commands below are operational examples for lab and emulator work. They are not claims that every production card accepts these exact forms.

### GlobalPlatformPro Patterns

Reader and verbosity:

```powershell
java -jar static\java\gp.jar -r
java -jar static\java\gp.jar -dv --list
```

Default lab key or diversified key:

```powershell
java -jar static\java\gp.jar --list
java -jar static\java\gp.jar -key emv:default --list
java -jar static\java\gp.jar -key visa2:47454D5850524553534F53414D504C45 --list
```

Typical CAP load/install shape:

```powershell
java -jar static\java\gp.jar --load applet.cap
java -jar static\java\gp.jar --install applet.cap
```

Important constraint:

- exact install arguments and privileges depend on the package, instance AID, and card/security-domain policy
- wrong keys can lock cards

The command shapes above are based on GPPro's documented operating model plus common lab usage; they should be treated as starting points, not universal production recipes.

### Java Card Build and Simulator Patterns

Typical GREENWIRE-local patterns:

```powershell
python tools\verify_java_static_setup.py
python tools\build_javacard_applet.py
python greenwire_modern.py cap produce-all
python greenwire_modern.py cap deploy --cap-file path\to\applet.cap
```

These are the repo-supported entry points even when the underlying Java Card SDK or GP tools are swapped.

## GREENWIRE's Current Software Posture

### Bundled / Integrated

- GPPro jar pathing and validation
- offline static Java audit helpers
- CAP production/deploy wrappers
- issuer pipeline services
- HSM, merchant, wallet, and payment-gateway emulators

### Still External or License-Gated

- Oracle Java Card SDK binary downloads
- proprietary scheme kernel implementations
- vendor-specific secure-element and wallet production integrations

## Recommended Workflow in GREENWIRE

For Java Card and GP lab issuance:

1. verify Java/GP static setup
2. build or validate the CAP artifact
3. choose the correct GP key profile for the card under test
4. open the secure channel and load/install using GPPro or the repo wrapper
5. run post-install merchant/HSM test flows using GREENWIRE

For emulator-only development:

1. create or issue a synthetic card profile
2. run merchant, wallet, or pipeline commands
3. inspect artifacts under `artifacts/`
4. use mutation-capable test-card logging for abnormal CVM/floor-limit cases

## Sources

- [GlobalPlatform Overview PDF](https://globalplatform.org/uploads/GP_Overview.pdf)
- [GPPro Getting started](https://github.com/martinpaljak/GlobalPlatformPro/wiki/Getting-started)
- [GPPro Keys](https://github.com/martinpaljak/GlobalPlatformPro/wiki/Keys)
- [Java Card Development Kit Tools User Guide](https://docs.oracle.com/en/java/javacard/3.2/jctug/java-card-development-kit-tools-user-guide.pdf)
- [Java Card Development Kit Simulator User Guide](https://docs.oracle.com/en/java/javacard/3.2/jcdksu/java-card-development-kit-simulator-user-guide.pdf)
- [Java Card downloads](https://www.oracle.com/java/technologies/javacard-downloads.html)
