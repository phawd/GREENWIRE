````instructions
# GREENWIRE - AI Agent Instructions

*Last Updated: September 2025 (Post-Cleanup & Enhancement)*

GREENWIRE is an EMV/smartcard/NFC security testing framework with a unified CLI and interactive menu system.

## Architecture Overview

### Core Structure
- **Entry Point**: `greenwire.py` - Main CLI with ~70 subcommands and interactive menu (`--menu`)
- **Menu System**: Dual implementation via `menu_handlers.py` (actions registry) and `menu_implementations.py` (working code)
- **Configuration**: `core/global_defaults.py` provides persistent config via `global_defaults.json`
- **Production Data**: `greenwire/core/data_manager.py` manages EMV/merchant datasets for card generation
- **Static Distribution**: Enhanced static mode with bundled dependencies in `static/lib/`

### Key Component Patterns

**Menu Action Registry** (`menu_handlers.py`):
- All interactive menu actions resolved via `MENU_ACTIONS` dictionary
- Maps action keys to functions, eliminates dynamic attribute lookup
- Pattern: Add function to file, register in `MENU_ACTIONS`, reference in menu config

**EMV/APDU Processing**:
- `core/emv_processor.py` - TLV parsing, tag interpretation, transaction data
- `modules/nfc/protocols.py` - APDU command structures, EMV protocol classes
- `apdu4j_data/` - Complete APDU4J integration for ISO 7816-4 compliance
- Pattern: EMV ops use standardized APDU classes with automatic case detection

**Hardware Abstraction**:
- `core/nfc_manager.py` - NFC device abstraction layer
- `core/android_manager.py` - ADB-based Android NFC testing
- Multi-interface support: PC/SC readers, Android NFC, hardware emulation

**Production Data Management**:
- `greenwire/core/data_manager.py` - Dataset discovery and loading from `data/production_scrapes/`
- Supports JSON/YAML datasets with EMV tags, merchant info, test scenarios
- Interactive selection via `show_production_data_menu()` and CLI via `prod-data` subcommand
- Pattern: Datasets include scheme, region, merchants[], emv_tags{}, test_scenarios[]

## Essential Development Workflows

### Build & Dependencies
```bash
# Python setup
pip install -r requirements.txt

# Java toolchain (offline/local JARs)
gradle listTools  # Check available offline tools
cd javacard/applet && ./gradlew convertCap  # Build JavaCard applets

# Static distribution
python tools/create_static_bundle.py  # Creates dist/greenwire-static/ with launcher
python dist/greenwire-static/run_greenwire.py --menu  # Run static bundle
```

### Testing Commands
```bash
# Interactive menu (main entry point)
python greenwire.py --menu

# Production data management
python greenwire.py prod-data --list  # List available datasets
python greenwire.py prod-data --show visa_sample  # Show dataset details
python greenwire.py prod-data --generate-cards visa_sample  # Generate cards

# APDU communication testing
python greenwire.py apdu --list-readers
python greenwire.py apdu --command 00A404000E325041592E5359532E444446303100

# EMV fuzzing with session artifacts
python greenwire.py testing fuzz --iterations 500 --report-dir artifacts/

# NFC operations via integrated tools
python greenwire.py nfc read
python greenwire.py fido list
```

### Configuration Management
- Global settings in `global_defaults.json` (auto-created)
- Access via `from core.global_defaults import load_defaults, update_defaults`
- CLI: `python greenwire.py config-defaults --verbose-default true`

## Critical Integration Points

### APDU Communication Chain
1. **Command Creation**: `modules/nfc/protocols.py` - `APDU` dataclass with automatic case detection
2. **EMV Processing**: `core/emv_processor.py` - TLV parsing using standardized tag dictionary
3. **Hardware Interface**: `apdu4j_data/apdu4j_integration.py` - martinpaljak/apdu4j wrapper
4. **Fuzzing Engine**: `core/apdu_fuzzer.py` - `NativeAPDUFuzzer` with EMV-aware mutations

### Menu System Flow
1. **User Input**: Interactive menu in `greenwire.py` 
2. **Action Lookup**: `menu_handlers.MENU_ACTIONS[key]()` - direct function call
3. **Implementation**: Functions in `menu_handlers.py` or imported from `menu_implementations.py`
4. **Fallback**: Working implementations in `menu_implementations.py` for complex operations

### Fuzzing Architecture
- **Native APDU Fuzzer**: `core/apdu_fuzzer.py` - mutation strategies (bitflip, nibble, genetic)
- **Artifact Generation**: JSON session logs, markdown reports to `artifact_dir_default`
- **Hardware Integration**: Optional PC/SC execution via `--pcsc` flag
- **Target Profiles**: EMV, JCOP, NXP with specific command sets

### AI-Driven Fuzzing Extension Patterns

**Extending Mutation Strategies**:
```python
# Add custom AI mutation in core/apdu_fuzzer.py
class NativeAPDUFuzzer:
    def ai_mutation_strategy(self, base_apdu, context_history):
        """AI-driven mutation using response patterns and timing analysis"""
        # Pattern: Use previous responses to guide mutations
        if context_history:
            successful_patterns = [h for h in context_history if h['sw'] == '9000']
            # Mutate based on successful command structures
        return mutated_apdu
    
    def register_ai_strategy(self, strategy_name, strategy_func):
        """Register custom AI fuzzing strategy"""
        self.ai_strategies[strategy_name] = strategy_func
```

**Response Analysis Integration**:
```python
# Pattern: Enhance analyze_response() for AI learning
def analyze_response_with_ai(self, cmd, response, context):
    analysis = {
        'timing_anomaly': response['timing_ms'] > self.baseline_timing * 2,
        'sw_pattern': self.classify_status_word(response['sw']),
        'payload_correlation': self.correlate_payload_response(cmd, response),
        'vulnerability_score': self.ai_vulnerability_scorer(cmd, response, context)
    }
    # Feed back into mutation strategy selection
    return analysis
```

**AI Session Learning**:
```python
# Pattern: Implement learning across fuzzing sessions
class AIFuzzingSession:
    def __init__(self, model_path="fuzz_models/emv_model.pkl"):
        self.mutation_model = self.load_or_create_model(model_path)
        self.response_classifier = ResponseClassifier()
    
    def learn_from_session(self, session_artifacts):
        """Update AI model with session results"""
        features = self.extract_features(session_artifacts)
        self.mutation_model.partial_fit(features)
        self.save_model()
```

## Linux Hardware Integration Patterns

### PC/SC Reader Detection (Linux)
```python
# Pattern: Linux-specific reader enumeration
import subprocess
from core.nfc_manager import NFCManager

class LinuxNFCManager(NFCManager):
    def detect_pcsc_readers(self):
        """Linux pcsc-lite integration"""
        try:
            result = subprocess.run(['pcsc_scan', '-n'], 
                                  capture_output=True, timeout=5)
            readers = self.parse_pcsc_output(result.stdout)
            return readers
        except subprocess.TimeoutExpired:
            return self.fallback_reader_detection()
    
    def setup_udev_rules(self):
        """Generate udev rules for NFC devices"""
        rules = [
            'SUBSYSTEM=="usb", ATTR{idVendor}=="072f", ATTR{idProduct}=="2200", MODE="0664", GROUP="nfc"',
            'SUBSYSTEM=="usb", ATTR{idVendor}=="04e6", ATTR{idProduct}=="5816", MODE="0664", GROUP="nfc"'
        ]
        return rules
```

### Hardware Abstraction Layer
```python
# Pattern: Device-specific implementations
class LinuxHardwareInterface:
    def __init__(self):
        self.interfaces = {
            'pcsc': PCScInterface(),
            'libnfc': LibNFCInterface(), 
            'spi': SPIInterface(),
            'i2c': I2CInterface()
        }
    
    def auto_detect_interface(self, device_path):
        """Auto-detect best interface for device"""
        if '/dev/ttyUSB' in device_path:
            return self.interfaces['pcsc']
        elif '/dev/spidev' in device_path:
            return self.interfaces['spi']
        # Add more detection logic
```

### Device Permission Management
```bash
# Pattern: Setup scripts for Linux deployment
# Add to tools/setup_linux_permissions.sh
sudo usermod -a -G dialout $USER  # Serial devices
sudo usermod -a -G nfc $USER      # NFC devices 
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="072f", MODE="0664", GROUP="nfc"' | \
  sudo tee /etc/udev/rules.d/99-greenwire-nfc.rules
sudo udevadm control --reload-rules
```

## Project-Specific Conventions

### Error Handling
- Use `@handle_errors` decorator from `core.logging_system` 
- Return dictionaries with `success: bool` and `error: str` keys
- Graceful fallbacks for missing hardware (simulation mode)

### APDU Formatting
- Hex strings without spaces: `"00A404000E325041592E5359532E444446303100"`
- Use `APDU` dataclass for command construction, automatically determines ISO cases
- Status words as separate `sw1, sw2` integers (not combined)

### File Organization
- Keep Java JARs in `static/java/` and `lib/` for offline operation
- EMV test data in `data/` with realistic bank/merchant info
- Session artifacts in configurable `artifact_dir_default` directory

### Import Patterns
```python
# Core systems (from core/)
from core.config import get_config
from core.logging_system import get_logger, handle_errors
from core.global_defaults import load_defaults

# EMV/Protocol handling
from modules.nfc.protocols import APDU, EMVProtocol
from core.emv_processor import EMVProcessor

# Hardware interfaces
from apdu4j_data.apdu4j_integration import create_apdu4j_interface

# Production data management
from greenwire.core.data_manager import list_datasets, choose_dataset_interactive, load_dataset
```

### Import Management
- **Consolidated imports**: Standard library imports at top of `greenwire.py`
- **ModuleManager**: Use `core/imports.py` for dynamic imports with static mode support
- **Static mode**: Fallback modules in `static/lib/` for missing dependencies
- **Pattern**: Avoid inline imports except in functions with optional dependencies

### Menu Development
1. Implement function in `menu_handlers.py` or import working version
2. Add to `MENU_ACTIONS` registry: `"key": function_name`
3. Test via `python greenwire.py --menu`
4. For complex operations, use proven implementations from `menu_implementations.py`

## Common Gotchas

- **Static Mode**: Set `GREENWIRE_STATIC=1` for bundled/offline operation
- **ADB Timing**: Android NFC commands cached for 30s, use `adb_cmd()` wrapper  
- **Reader Detection**: PC/SC readers may need restart between operations
- **JavaCard Builds**: Require local SDK in `sdk/javacard/lib/` for CAP conversion
- **Menu Registry**: All menu actions MUST be in `MENU_ACTIONS` - no dynamic lookup
- **Import Consolidation**: Avoid inline imports; use ModuleManager for optional dependencies
- **Production Data**: JSON/YAML files in `data/production_scrapes/` auto-discovered by data_manager

## Recent Enhancements (2025)

### Production Data Management
- **New CLI subcommand**: `prod-data` for dataset management and card generation
- **Interactive menu**: Production dataset selection integrated into main menu system
- **Sample datasets**: Ready-to-use EMV datasets (VISA, MasterCard, AMEX) in `data/production_scrapes/`
- **Dataset format**: JSON/YAML with scheme, merchants, EMV tags, test scenarios
- **CLI examples**: `prod-data --list`, `prod-data --generate-cards visa_sample`

### Enhanced Static Distribution  
- **Improved bundle creator**: `tools/create_static_bundle.py` with comprehensive module copying
- **Fallback modules**: Complete smartcard library stubs in `static/lib/smartcard/`
- **Static launcher**: `run_greenwire.py` for portable execution without Python deps
- **Environment detection**: Automatic static mode via `GREENWIRE_STATIC=1`

### Import Consolidation
- **Centralized imports**: All standard library imports at top of `greenwire.py`
- **ModuleManager enhancements**: Better static mode support and error handling
- **Removed inline imports**: Eliminated scattered imports throughout functions
- **Fallback mechanisms**: Graceful degradation when optional dependencies missing

### JavaCard .cap Compilation & Deployment

**Quick .cap Build Workflow**:
```bash
# Navigate to applet directory
cd javacard/applet

# Option 1: Using Gradle (if available)
gradle convertCap -PappletClass=com.greenwire.fuzz.FuzzingApplet -PpackageName=com.greenwire.fuzz
gradle deployCap

# Option 2: Manual compilation (if Gradle unavailable)
# 1. Compile Java source (requires JavaCard SDK)
javac -cp "../../sdk/javacard/lib/api_classic.jar" -d build/classes src/main/java/com/greenwire/fuzz/FuzzingApplet.java

# 2. Convert to .cap (requires JavaCard SDK tools.jar)
java -cp "../../sdk/javacard/lib/tools.jar" com.sun.javacard.converter.Main \\
  -classdir build/classes \\
  -d build/cap \\
  -exportpath ../../sdk/javacard/api_export_files \\
  -out CAP \\
  -applet A0:00:00:06:23:01:46:55:5A:5A com.greenwire.fuzz.FuzzingApplet \\
  com.greenwire.fuzz A0:00:00:06:23:01:46:55:5A:50 1.0

# 3. Deploy using GlobalPlatformPro
java -jar ../../lib/GlobalPlatformPro.jar \\
  --install build/cap/com/greenwire/fuzz/javacard/fuzz.cap \\
  --verbose

# Option 3: Use ant-javacard (lightweight alternative)
java -jar ../../static/java/ant-javacard.jar \\
  -src src/main/java \\
  -out build/cap \\
  -pkg com.greenwire.fuzz \\
  -aid A0:00:00:06:23:01:46:55:5A:50 \\
  -applet A0:00:00:06:23:01:46:55:5A:5A com.greenwire.fuzz.FuzzingApplet
```

**Custom Applet Development Pattern**:
```java
// Pattern: Fuzzing-ready applet template
package com.greenwire.fuzz;
import javacard.framework.*;

public class FuzzingApplet extends Applet {
    private static final byte[] DEBUG_AID = {(byte)0xA0,0x00,0x00,0x06,0x23,0x01,0x46,0x55,0x5A,0x5A};
    private short counter = 0;
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FuzzingApplet().register();
    }
    
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return; // Return success for SELECT
        }
        
        byte[] buf = apdu.getBuffer();
        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];
        
        // Pattern: Log all commands for fuzzing analysis
        logCommand(cla, ins, buf);
        
        switch (ins) {
            case (byte)0x00: // GET DATA
                handleGetData(apdu);
                break;
            case (byte)0xFF: // Fuzzing command
                handleFuzzingCommand(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    private void handleFuzzingCommand(APDU apdu) {
        // Pattern: Controlled vulnerability for testing
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        
        // Intentional timing variation for fuzzer detection
        for (short i = 0; i < (short)(buf[ISO7816.OFFSET_P1] * 100); i++) {
            counter++; // Artificial delay
        }
        
        // Return counter value for state tracking
        buf[0] = (byte)(counter >> 8);
        buf[1] = (byte)(counter & 0xFF);
        apdu.setOutgoingAndSend((short)0, (short)2);
    }
}
```

**Gradle Build Configuration** (`javacard/applet/build.gradle`):
```gradle
plugins {
    id 'java'
    id 'com.github.martinpaljak.javacard' version '0.7.0'
}

javacard {
    sdkVersion = '3.0.4'
    
    cap {
        packageName = project.findProperty('packageName') ?: 'com.greenwire.applet'
        version = project.findProperty('packageVersion') ?: '1.0'
        aid = project.findProperty('packageAID') ?: 'A0:00:00:06:23:01:47:52:4E:57:50'
        
        applet {
            className = project.findProperty('appletClass') ?: 'com.greenwire.applet.GreenwireApplet'
            aid = project.findProperty('appletAID') ?: 'A0:00:00:06:23:01:47:52:4E:57:52'
        }
    }
}

// Custom task for fuzzing applet
task buildFuzzApplet(type: JavaCardTask) {
    dependsOn classes
    packageName = 'com.greenwire.fuzz'
    aid = 'A0:00:00:06:23:01:46:55:5A:50'
    applets = [
        [className: 'com.greenwire.fuzz.FuzzingApplet', aid: 'A0:00:00:06:23:01:46:55:5A:5A']
    ]
}
```

**Deployment Integration with GREENWIRE**:
```python
# Pattern: Automated .cap deployment in testing workflow
from core.cap_manager import CAPManager

def deploy_fuzzing_applet(card_type="emv"):
    """Deploy custom fuzzing applet for testing"""
    cap_manager = CAPManager()
    
    # Build applet if not exists
    cap_file = cap_manager.ensure_applet_built(
        applet_type="fuzzing",
        build_params={
            "packageName": "com.greenwire.fuzz",
            "appletAID": "A0:00:00:06:23:01:46:55:5A:5A"
        }
    )
    
    # Deploy to detected card
    result = cap_manager.deploy_to_card(cap_file, card_type=card_type)
    return result

# Usage in fuzzing session
def setup_fuzzing_session():
    # Deploy fuzzing applet
    deploy_result = deploy_fuzzing_applet("jcop")
    if not deploy_result['success']:
        logger.error(f"Failed to deploy applet: {deploy_result['error']}")
        return False
    
    # Initialize fuzzer with applet AID
    fuzzer = NativeAPDUFuzzer(target_aid="A000000623014655A5A")
    return fuzzer
```

## .cap Testing & Integration Workflow

### Testing Compiled Applets
```bash
# Pattern: End-to-end .cap testing workflow
cd javacard/applet

# 1. Build the applet
./gradlew convertCap -PappletClass=com.greenwire.test.TestApplet

# 2. Deploy to card/simulator
./gradlew deployCap

# 3. Test with GREENWIRE CLI
python ../../greenwire.py apdu --command 00A4040007A0000006230147 --verbose
python ../../greenwire.py testing fuzz --target-aid A0000006230147 --iterations 100

# 4. Analyze results
python ../../greenwire.py testing dump --cap-file build/cap/*.cap --analyze
```

### Applet Integration Patterns
```python
# Pattern: Custom applet testing integration
class CAPTester:
    def __init__(self, cap_file_path):
        self.cap_path = cap_file_path
        self.aid = self.extract_aid_from_cap(cap_file_path)
        
    def install_and_test(self):
        \"\"\"Install .cap and run comprehensive tests\"\"\"
        # Install applet
        install_result = self.deploy_cap()
        if not install_result['success']:
            return {'error': 'Installation failed'}
            
        # Test basic functionality
        basic_tests = self.run_basic_apdu_tests()
        
        # Run fuzzing session
        fuzz_results = self.run_targeted_fuzzing()
        
        # Analyze timing and responses
        analysis = self.analyze_applet_behavior()
        
        return {
            'installation': install_result,
            'basic_tests': basic_tests,
            'fuzzing': fuzz_results,
            'analysis': analysis
        }
        
    def run_targeted_fuzzing(self):
        \"\"\"Run fuzzing specifically designed for this applet\"\"\"
        fuzzer = NativeAPDUFuzzer()
        fuzzer.set_target_aid(self.aid)
        
        # Custom mutations for JavaCard applets
        mutations = [
            'buffer_overflow',  # Test APDU buffer limits
            'state_confusion',  # Test applet state machine
            'instruction_fuzzing'  # Test unknown INS codes
        ]
        
        return fuzzer.run_session(mutations=mutations)
```

### Development Iteration Pattern
```bash
# Pattern: Rapid development/test cycle
#!/bin/bash
# save as tools/cap_dev_cycle.sh

echo "🔄 Starting .cap development cycle..."

# Build
cd javacard/applet
./gradlew convertCap -q

if [ $? -eq 0 ]; then
    echo "✅ Build successful"
    
    # Deploy
    ./gradlew deployCap -q
    
    if [ $? -eq 0 ]; then
        echo "✅ Deployment successful"
        
        # Test
        cd ../..
        python greenwire.py testing fuzz --target-aid A0000006230147 --iterations 50 --summary
        
        echo "🎯 Testing complete - check artifacts/ for results"
    else
        echo "❌ Deployment failed"
    fi
else
    echo "❌ Build failed"
fi
```

## Key Files for Understanding
- `README.md` - Comprehensive CLI documentation and examples  
- `ARCHITECTURE.md` - Detailed system design and module relationships
- `apdu4j_data/README.md` - APDU4J integration patterns and command reference
- `menu_handlers.py` - Complete menu action registry and implementations
- `CLEANUP_ENHANCEMENT_REPORT.md` - Recent improvements and architectural changes
- `javacard/applet/build.gradle` - JavaCard build configuration and tasks