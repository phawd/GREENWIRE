# GREENWIRE Static Deployment Guide

## Overview
GREENWIRE supports a mostly self-contained static deployment, but some Java and JavaCard artifacts must still be supplied locally because they are not checked into this repository.

## Static Components Included

### Java Environment
- Java runtime staged under `static/java/jdk/` if you provide one locally
- Apache Ant (`static/java/apache-ant-1.10.15/`)
- ant-javacard (`static/java/ant-javacard.jar`)
- GlobalPlatformPro fat JAR (`lib/GlobalPlatformPro.jar`)
- JavaCard SDK jars under `sdk/javacard/lib/`

### Python Libraries
- NFC transport helpers (`static/lib/android_nfc.py`)
- Card emulation core (`static/lib/emulation.py`)
- EMV compliance checks (`static/lib/greenwire_emv_compliance.py`)
- Cryptographic fuzzer (`static/lib/greenwire_crypto_fuzzer.py`)
- Thales emulator (`static/lib/thales_emulator.py`)

### Compiled Java Classes
- All JavaCard applets (merchant probes, EMV testers)
- Standard Java utilities (CommandAPDU)

## Deployment Process

### 1. Mirror Python Modules
```bash
python -m tools.static_distribution prepare-python
```

### 1b. Catalogue Static Assets
```bash
python -m tools.static_distribution inventory
```
This produces `STATIC_DISTRIBUTION_INVENTORY.md` at the repository root with file sizes and roles.

### 2. Verify Static Build
```bash
python verify_static.py
```

### 3. Create Static Build
```bash
build_static.bat
```

### 4. Deploy to Target System
Copy the entire `build/` directory to target system. No additional installations required.

## Usage on Target System

### Compile Additional JavaCard Applets
```bash
cd build
compile_static.bat MyNewApplet.java
```

### Generate CAP Files
```bash
generate_cap.bat MyApplet
```

### Deploy to Smartcard
```bash
deploy_cap.bat MyApplet.cap
```

## Self-Contained Features

### Java Runtime Requirements
- A Java runtime must be available in `PATH` or staged under `static/java/jdk/`
- JavaCard conversion also requires SDK jars under `sdk/javacard/lib/`

### No External Tools Required
- ant-javacard for CAP generation
- GlobalPlatformPro for deployment once `lib/GlobalPlatformPro.jar` is provided
- The repository already contains the Python-side static mirrors and Ant assets

### No Python Dependencies
- All required modules included in static/lib/
- No pip install needed

### Cross-Platform Ready
- Windows batch scripts included
- Linux/macOS shell scripts generated
- Platform-specific runtime artifacts can be staged into the static bundle

## Verification Checklist

- [ ] `python -m tools.static_distribution prepare-python` mirrors the modules
- [ ] `verify_static.py` reports success after required Java artifacts are supplied
- [ ] `build_static.bat` completes without errors
- [ ] `build/` directory contains all dependencies
- [ ] Test compilation works: `build/compile_static.bat`
- [ ] CAP generation works: `build/generate_cap.bat`

## Deployment Size
- **Total size**: ~150MB (including JDK)
- **Core libraries**: ~50MB
- **Compiled classes**: ~5MB

## Security Notes
- All dependencies are pinned to specific versions
- No network access required during operation
- Cryptographic libraries are statically linked
- Audit trail maintained in build logs

## Troubleshooting

### JDK Not Found
If no Java runtime is available, install one locally or stage it under `static/java/jdk/`

### Compilation Errors
Ensure all Java files are using the fixed syntax (no String.getBytes(), proper imports, etc.)

### CAP Generation Issues
Verify the JavaCard SDK jars are accessible under `sdk/javacard/lib/`

## Result
GREENWIRE can be packaged for portable deployment once the required Java runtime, JavaCard SDK, and GlobalPlatform artifacts are present.
