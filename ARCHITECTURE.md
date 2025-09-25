# GREENWIRE Framework v2.0 - Architecture Documentation

## Overview
GREENWIRE is a comprehensive security research framework designed for smartcard security testing, EMV analysis, NFC/MIFARE exploitation, and cryptographic attack development. This document describes the consolidated v2.0 architecture with streamlined module organization.

## Core Architecture

### Directory Structure (Post-Consolidation)
```
GREENWIRE/
├── core/                    # Core system functionality
│   ├── __init__.py         # Core module initialization
│   ├── config.py           # Configuration management
│   ├── logging_system.py   # Logging infrastructure  
│   ├── menu_system.py      # Interactive menu system
│   ├── nfc_manager.py      # NFC device management
│   ├── imports.py          # Dynamic module importing
│   ├── module_manager.py   # Module lifecycle management
│   ├── fuzzing_engine.py   # Fuzzing framework
│   ├── device_detector.py  # Hardware detection
│   ├── session_manager.py  # Session state management
│   └── utils/              # Core utilities (moved from static/lib/greenwire_utils/)
│       ├── __init__.py
│       ├── hex_utils.py
│       ├── file_utils.py
│       └── crypto_utils.py
├── modules/                 # Specialized functionality modules
│   ├── __init__.py         # Module exports and initialization
│   ├── emulation.py        # Card emulation (from greenwire_emulation.py)
│   ├── crypto/             # Cryptographic modules (from greenwire_crypto/)
│   │   ├── __init__.py
│   │   ├── emv_crypto.py   # EMV cryptographic functions
│   │   ├── mifare_crypto.py # MIFARE attack implementations
│   │   ├── ntag_crypto.py  # NTAG vulnerabilities
│   │   └── key_recovery.py # Key extraction algorithms
│   ├── nfc/                # NFC communication (from greenwire_nfc/)
│   │   ├── __init__.py
│   │   ├── emv_processor.py
│   │   ├── mifare_processor.py
│   │   └── ntag_processor.py
│   ├── ui/                 # User interface modules (from greenwire_ui/)
│   │   ├── __init__.py
│   │   ├── menu_builders.py
│   │   └── display_utils.py
│   ├── testing/            # Testing and fuzzing modules
│   │   ├── __init__.py
│   │   ├── emv_fuzzer.py
│   │   ├── mifare_fuzzer.py
│   │   └── test_vectors.py
│   └── tools/              # Specialized tools
│       ├── __init__.py
│       ├── card_cloner.py
│       ├── key_bruteforce.py
│       └── vulnerability_scanner.py
├── greenwire.py            # Main CLI entry point
├── static/                 # Static resources (reduced scope)
└── docs/                   # Documentation
    ├── ARCHITECTURE.md     # This file
    ├── FUNCTION_TREE.md    # Function hierarchy
    └── CRYPTO_RESEARCH.md  # Cryptographic attack research
```

## System Components

### Core System (`core/`)
The core directory contains foundational components that provide infrastructure for the entire framework:

#### Configuration Management (`core/config.py`)
- Environment-based configuration loading
- Hardware detection settings
- Attack parameters and thresholds
- Debug and logging levels

#### NFC Manager (`core/nfc_manager.py`)
- Unified interface for NFC device communication
- Support for PC/SC, PN532, ACR122U, and other readers
- Device abstraction layer for cross-platform compatibility
- Connection pooling and device state management

#### Module Manager (`core/module_manager.py`)
- Dynamic loading of specialized modules
- Dependency resolution between modules
- Module lifecycle management (load, initialize, cleanup)
- Hot-swapping capabilities for development

#### Fuzzing Engine (`core/fuzzing_engine.py`)
- Generic fuzzing framework for smartcard protocols
- Mutation algorithms for APDU commands
- Response analysis and vulnerability detection
- Crash detection and recovery mechanisms

### Specialized Modules (`modules/`)
The modules directory contains domain-specific functionality organized by security research area:

#### Emulation Module (`modules/emulation.py`)
**Purpose**: Card emulation and simulation capabilities
- **Functions**:
  - `EMVCardEmulator` - EMV payment card simulation
  - `MifareEmulator` - MIFARE Classic/Ultralight emulation
  - `NTAGEmulator` - NTAG213/215/216 simulation
  - `CustomCardEmulator` - User-defined card profiles

#### Cryptographic Modules (`modules/crypto/`)
**Purpose**: Implementation of cryptographic attacks and key recovery

##### EMV Cryptography (`modules/crypto/emv_crypto.py`)
- **Key Derivation Attacks**:
  - `extract_emv_keys()` - Extract application cryptographic keys
  - `derive_session_keys()` - Session key derivation vulnerabilities
  - `crack_diversified_keys()` - Attack diversified key schemes
- **Protocol Attacks**:
  - `sda_bypass()` - Static Data Authentication bypass
  - `dda_manipulation()` - Dynamic Data Authentication attacks
  - `cda_forge()` - Combined Data Authentication forgery
- **Cryptogram Analysis**:
  - `analyze_arqc()` - Authorization Request Cryptogram analysis
  - `forge_arpc()` - Authorization Response Cryptogram forgery
  - `transaction_replay()` - Transaction replay attack implementation

##### MIFARE Cryptography (`modules/crypto/mifare_crypto.py`)
- **Crypto1 Attacks** (based on Proxmark3 research):
  - `darkside_attack()` - Implementation of Darkside attack for key recovery
  - `nested_attack()` - Nested authentication attack
  - `hardnested_attack()` - Hard nested attack for newer cards
  - `static_nested_attack()` - Static encrypted nonce attacks
- **Key Recovery**:
  - `mfkey32()` - 32-bit keystream attack
  - `mfkey64()` - 64-bit keystream attack  
  - `nonce_brute_force()` - Brute force nonce attacks
- **Protocol Vulnerabilities**:
  - `uid_manipulation()` - UID modification techniques
  - `sector_access_bypass()` - Sector access control bypass
  - `anticollision_attacks()` - Anti-collision protocol attacks

##### NTAG Cryptography (`modules/crypto/ntag_crypto.py`)
- **Authentication Attacks**:
  - `pwd_bruteforce()` - Password brute force attacks
  - `pack_manipulation()` - PACK value manipulation
  - `counter_reset()` - Counter manipulation techniques
- **Memory Attacks**:
  - `memory_dump()` - Full memory extraction
  - `protected_area_bypass()` - Protected memory access
  - `signature_bypass()` - Originality signature bypass

##### Key Recovery (`modules/crypto/key_recovery.py`)
- **Generic Algorithms**:
  - `differential_analysis()` - Differential cryptanalysis implementation
  - `timing_attacks()` - Timing-based key recovery
  - `power_analysis()` - Simple/Differential Power Analysis
  - `fault_injection()` - Fault injection attack simulation

#### NFC Communication (`modules/nfc/`)
**Purpose**: Protocol-specific NFC communication handlers

##### EMV Processor (`modules/nfc/emv_processor.py`)
- **Transaction Processing**:
  - `select_application()` - EMV application selection
  - `get_processing_options()` - GPO command handling
  - `read_application_data()` - Read application records
  - `generate_ac()` - Application cryptogram generation
- **Vulnerability Testing**:
  - `test_card_verification()` - CVM bypass testing
  - `offline_pin_bypass()` - Offline PIN verification bypass
  - `amount_manipulation()` - Transaction amount manipulation

##### MIFARE Processor (`modules/nfc/mifare_processor.py`)
- **Authentication**:
  - `authenticate_sector()` - Sector authentication with known keys
  - `key_recovery_session()` - Interactive key recovery
  - `default_key_scan()` - Default key enumeration
- **Data Operations**:
  - `dump_card()` - Full card memory dump
  - `clone_card()` - Card cloning operations
  - `modify_data()` - Selective data modification

##### NTAG Processor (`modules/nfc/ntag_processor.py`)
- **Memory Operations**:
  - `read_memory()` - Memory page reading
  - `write_memory()` - Memory page writing
  - `format_card()` - Card formatting operations
- **Security Testing**:
  - `bypass_protection()` - Protection bypass techniques
  - `password_recovery()` - Password recovery methods

## Function Tree and Dependencies

### Core Dependencies
```
greenwire.py
├── core.config (Configuration loading)
├── core.menu_system (Main menu interface)
├── core.nfc_manager (Device initialization)
├── core.module_manager (Dynamic module loading)
└── core.session_manager (Session state)
```

### Module Dependencies
```
modules.emulation
├── core.nfc_manager (Device communication)
├── modules.crypto.* (Cryptographic functions)
└── core.fuzzing_engine (Testing capabilities)

modules.crypto.*
├── core.utils.crypto_utils (Basic crypto functions)
├── external libraries (pycrypto, cryptography)
└── core.logging_system (Attack logging)

modules.nfc.*
├── core.nfc_manager (Hardware abstraction)
├── modules.crypto.* (Protocol-specific crypto)
└── core.session_manager (Communication state)
```

## Integration with External Tools

### Proxmark3 Integration
- Direct integration with Proxmark3 client libraries
- Support for MIFARE Classic attack implementations
- Hardware-accelerated cryptographic operations
- Real-time key recovery feedback

### EMV Research Libraries
- Integration with `pyemv` for EMV cryptographic operations
- Support for multiple CVN (Cryptogram Version Numbers)
- Key derivation and session key attacks
- Transaction simulation and manipulation

### JavaCard Development
- Integration with `ant-javacard` build system
- Support for custom applet development
- CAP file generation and installation
- GlobalPlatformPro integration for card management

## Security Research Capabilities

### Attack Vectors Implemented
1. **EMV Attacks**:
   - Key extraction from payment cards
   - Transaction manipulation and replay
   - Offline authentication bypass
   - Dynamic application selection attacks

2. **MIFARE Attacks**:
   - Crypto1 stream cipher vulnerabilities
   - Nested authentication attacks
   - Default key exploitation
   - Memory dump and cloning

3. **NTAG Attacks**:
   - Password brute force attacks
   - Memory protection bypass
   - Counter manipulation
   - Signature verification bypass

### Research Areas
- **Cryptographic Vulnerabilities**: Implementation of known academic attacks
- **Protocol Fuzzing**: Automated vulnerability discovery
- **Side-Channel Analysis**: Timing and power analysis simulation
- **Fault Injection**: Software-based fault injection attacks

## Usage Patterns

### Interactive Mode
```bash
python greenwire.py --menu
```
Provides full interactive menu system with guided attack workflows.

### Direct Command Mode
```bash
python greenwire.py emv extract-keys --card-type visa --output keys.json
python greenwire.py mifare darkside --sector 0 --key-type A
python greenwire.py ntag bruteforce --start-pwd 0000 --end-pwd FFFF
```

### Programmatic Usage
```python
from modules.crypto.mifare_crypto import darkside_attack
from modules.nfc.mifare_processor import MifareProcessor
from core.nfc_manager import get_nfc_manager

# Initialize NFC communication
nfc = get_nfc_manager()
processor = MifareProcessor(nfc)

# Execute Darkside attack
key = darkside_attack(processor, sector=0, key_type='A')
print(f"Recovered key: {key.hex()}")
```

## AI Integration Guidelines

### For AI Assistants
This architecture provides clear separation of concerns:
- **Core modules** handle infrastructure and common functionality
- **Specialized modules** implement domain-specific attacks
- **Function tree** shows clear dependencies and data flow
- **Research integration** connects to academic cryptographic research

### Development Workflow
1. Core infrastructure provides stable foundation
2. Modules can be developed independently
3. New attack vectors can be added without core changes
4. Research integration allows rapid implementation of new techniques

## Future Extensions

### Planned Enhancements
- **Machine Learning Integration**: Automated attack pattern recognition
- **Cloud Research**: Distributed key recovery across multiple instances
- **Hardware Extensions**: Support for specialized attack hardware
- **Mobile Integration**: Android NFC attack capabilities

This architecture supports both security research and practical penetration testing while maintaining clear organization and extensibility for future cryptographic attack development.