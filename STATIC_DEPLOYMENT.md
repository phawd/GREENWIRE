# GREENWIRE Static Deployment Guide

## Overview
GREENWIRE is now configured for fully static deployment with zero external dependencies.

## Static Components Included

### Java Environment
- Bundled JDK 8 (`static/java/jdk/` or `temurin8.zip`)
- Apache Ant (`static/java/apache-ant-1.10.15/`)
- JavaCard API (`static/java/javacard_lib/api_classic.jar`)
- ant-javacard (`static/java/ant-javacard.jar`)
- GlobalPlatformPro (`static/java/gp.jar`)

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

### No External Java Required
- Bundled JDK 8 handles all compilation
- No JAVA_HOME or PATH dependencies

### No External Tools Required
- ant-javacard for CAP generation
- GlobalPlatformPro for deployment
- All utilities bundled

### No Python Dependencies
- All required modules included in static/lib/
- No pip install needed

### Cross-Platform Ready
- Windows batch scripts included
- Linux/macOS shell scripts generated
- Platform-specific binaries bundled

## Verification Checklist

- [ ] `python -m tools.static_distribution prepare-python` mirrors the modules
- [ ] `verify_static.py` reports success
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
If JDK extraction fails, manually extract `static/java/temurin8.zip` to `static/java/jdk/`

### Compilation Errors
Ensure all Java files are using the fixed syntax (no String.getBytes(), proper imports, etc.)

### CAP Generation Issues
Verify JavaCard API is accessible: `static/java/javacard_lib/api_classic.jar`

## Result
GREENWIRE is now 100% static and self-contained
- Zero external dependencies
- Portable across systems
- Ready for secure deployment
