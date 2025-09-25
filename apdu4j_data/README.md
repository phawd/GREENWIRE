# APDU4J Integration for GREENWIRE

This module provides comprehensive integration of the martinpaljak/apdu4j Java library command structures with GREENWIRE's smartcard testing framework.

## Overview

APDU4J is the definitive Java library for APDU-level smart card communication, providing:
- ISO 7816-4 compliant APDU command structures
- GlobalPlatform management capabilities  
- PC/SC reader integration
- Cross-platform smartcard operations

Source: https://github.com/martinpaljak/apdu4j
License: MIT

## Components

### Core Modules

- **`apdu_commands.py`** - Hardcoded APDU command structures and ISO 7816-4 compliance
- **`gp_commands.py`** - GlobalPlatform management commands for CAP file operations
- **`apdu4j_integration.py`** - Main integration interface with GREENWIRE
- **`test_apdu4j.py`** - Comprehensive test suite

### Command Categories

#### ISO 7816-4 Commands (apdu_commands.py)
- **File System**: SELECT_MF, SELECT_ADF, SELECT_EF, SELECT_DF
- **Data Access**: READ_BINARY, UPDATE_BINARY, READ_RECORD, UPDATE_RECORD, APPEND_RECORD
- **Security**: VERIFY_PIN, CHANGE_PIN, UNBLOCK_PIN, GET_CHALLENGE, INTERNAL_AUTH, EXTERNAL_AUTH
- **Data Objects**: GET_DATA, PUT_DATA

#### PC/SC Commands (apdu_commands.py)
- **Card Access**: PCSC_GET_UID, PCSC_LOAD_KEY, PCSC_AUTH
- **Block Operations**: PCSC_READ_BLOCK, PCSC_WRITE_BLOCK

#### GlobalPlatform Commands (gp_commands.py)
- **Management**: SELECT_CARD_MANAGER, SELECT_ISD, GET_STATUS variants
- **Application Lifecycle**: Install, Load, Delete operations
- **Card Information**: GET_CARD_DATA, GET_APPLICATION_INFO

## Usage Examples

### Basic APDU Operations

```python
from apdu4j_data.apdu4j_integration import create_apdu4j_interface
from apdu_communicator import APDUCommunicator

# Initialize with GREENWIRE communicator
communicator = APDUCommunicator(verbose=True)
apdu4j = create_apdu4j_interface(communicator)

# Connect to card
if communicator.connect_reader():
    # Select Visa application
    result = apdu4j.select_application("A0000000031010")
    if result['success']:
        print("Visa application selected")
        print(f"Response: {result['data']}")
    
    # Verify PIN
    pin_result = apdu4j.verify_pin("1234")
    if pin_result['success']:
        print("PIN verified successfully")
    
    # Get application data
    data_result = apdu4j.get_data_object(0x006E)  # Application info
    if data_result['success']:
        print(f"Application data: {data_result['data']}")
```

### GlobalPlatform Operations

```python
# List installed applications
apps = apdu4j.list_gp_applications()
if apps['success']:
    for app in apps['applications']:
        print(f"AID: {app['aid']}, State: {app['state']}")

# Install CAP file
install_result = apdu4j.install_cap_file(
    "applet.cap",
    package_aid="A000000003000000",
    applet_aid="A00000000300000001",
    instance_aid="A00000000300000001"
)

# Delete application
delete_result = apdu4j.delete_gp_application("A00000000300000001")
```

### Command Discovery and Execution

```python
# List all available commands
commands = apdu4j.get_available_commands()
print(f"Available commands: {len(commands)}")

# Get command information
info = apdu4j.get_command_info('SELECT_ADF')
print(f"Command: {info['name']}")
print(f"Hex: {info['hex']}")
print(f"Description: {info['description']}")

# Execute parameterized command
result = apdu4j.execute_command('SELECT_ADF', aid="A0000000031010")

# Send raw APDU
raw_result = apdu4j.send_raw_apdu(0x00, 0xA4, 0x04, 0x00, 
                                  data=bytes.fromhex("A0000000031010"),
                                  le=256)
```

### Low-level Command Construction

```python
from apdu4j_data.apdu_commands import APDU4JCommand, create_select_aid_command

# Create custom command
cmd = APDU4JCommand(
    cla=0x00,           # ISO class
    ins=0xA4,           # SELECT instruction
    p1=0x04,            # Select by AID
    p2=0x00,            # First occurrence
    data=bytes.fromhex("A0000000031010"),  # Visa AID
    le=256              # Expected response length
)

print(f"Command hex: {cmd.to_hex()}")
print(f"APDU case: {cmd.case}")

# Use convenience functions
select_cmd = create_select_aid_command("A0000000031010")
pin_cmd = create_pin_verify_command("1234")
data_cmd = create_get_data_command(0x006E)
```

## Integration with GREENWIRE CLI

The APDU4J integration is designed to work seamlessly with GREENWIRE's existing command-line interface:

```bash
# Test APDU4J commands via GREENWIRE CLI
python greenwire.py testing apdu4j --list-commands
python greenwire.py testing apdu4j --command SELECT_ADF --aid A0000000031010
python greenwire.py testing apdu4j --raw-apdu 00A404000A0000000031010000

# GlobalPlatform operations  
python greenwire.py gp --list-apps
python greenwire.py gp --install applet.cap --package-aid A000000003000000
python greenwire.py gp --delete A00000000300000001
```

## Command Reference

### ISO 7816-4 APDU Cases

The APDU4JCommand class automatically determines and encodes the correct APDU case:

- **Case 1**: No data, no response expected (CLA INS P1 P2)
- **Case 2S**: No data, short response expected (CLA INS P1 P2 Le)
- **Case 2E**: No data, extended response expected (CLA INS P1 P2 00 Le1 Le2)
- **Case 3S**: Short data, no response (CLA INS P1 P2 Lc Data)
- **Case 3E**: Extended data, no response (CLA INS P1 P2 00 Lc1 Lc2 Data)
- **Case 4S**: Short data, short response (CLA INS P1 P2 Lc Data Le)
- **Case 4E**: Extended data, extended response (CLA INS P1 P2 00 Lc1 Lc2 Data Le1 Le2)

### Status Word Handling

The integration provides automatic status word parsing:

```python
response = parse_apdu_response(response_bytes)
print(f"Success: {response['success']}")
print(f"Status: {response['status']}")
print(f"Data: {response['data'].hex()}")
```

Common status words:
- `0x9000` - Success
- `0x61XX` - More data available (XX bytes)
- `0x6700` - Wrong length
- `0x6982` - Security condition not satisfied
- `0x6A82` - File not found
- `0x6D00` - Instruction not supported

## Testing

Run the comprehensive test suite:

```bash
cd apdu4j_data
python test_apdu4j.py
```

Test categories:
- **Unit Tests**: Command structure, encoding, response parsing
- **Integration Tests**: Interface functionality, command execution
- **Template Tests**: Hardcoded command validation
- **Live Tests**: Hardware compatibility (requires card reader)

## Hardware Testing

The APDU4J integration supports testing with:

### PC/SC Readers
- ACR122U NFC Reader
- Omnikey CardMan series
- SCM Microsystems readers
- Any PC/SC compatible device

### Android NFC via ADB
```bash
# Enable ADB debugging on Android device
python greenwire.py nfc android --device <device_id>
python greenwire.py testing apdu4j --android --command SELECT_ADF --aid A0000000031010
```

### Card Types Supported
- **JavaCard**: JCOP, G&D, Infineon, etc.
- **EMV Payment Cards**: Visa, Mastercard, American Express
- **Government Cards**: PIV, CAC, eID
- **Transport Cards**: Mifare, FeliCa, Calypso
- **Custom Cards**: Any ISO 14443 or ISO 7816 compliant

## Error Handling and Debugging

Enable verbose logging for detailed APDU tracing:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

communicator = APDUCommunicator(verbose=True)
# Will show all APDU exchanges:
# >> 00A404000A0000000031010000
# << 6F1A840E315041592E5359532E444446303187010100
```

Common issues and solutions:

### No Reader Found
- Install PC/SC middleware (Windows: built-in, Linux: pcscd, macOS: built-in)
- Check reader connections and drivers
- Verify with: `python -c "from smartcard.System import readers; print(readers())"`

### Communication Errors
- Check card insertion and contact
- Verify card compatibility (T=0/T=1 protocols)
- Try different readers if available

### Command Failures
- Check APDU syntax and parameters
- Verify application selection before data commands
- Ensure proper security conditions (PIN verification)

## Performance Considerations

### Bulk Operations
For high-volume testing, use batch commands:

```python
# Efficient bulk testing
commands = [
    apdu4j.create_select_aid_command("A0000000031010"),
    apdu4j.create_get_data_command(0x006E),
    apdu4j.create_get_data_command(0x005A)
]

results = []
for cmd in commands:
    result = apdu4j.send_command(cmd)
    results.append(result)
```

### Memory Management
The integration handles large CAP files efficiently:
- Automatic block-based loading for GlobalPlatform
- Streaming response handling for large data objects
- Memory-efficient APDU encoding/decoding

## Security Notes

### PIN Handling
- PINs are handled securely in memory
- No PIN storage or caching
- Support for encrypted PIN blocks

### Key Management
- Integration with GREENWIRE's HSM commands
- Support for secure authentication protocols
- Hardware security module compatibility

### Audit Trail
All APDU operations can be logged for security auditing:

```python
# Enable audit logging
audit_logger = logging.getLogger('apdu4j.audit')
audit_logger.addHandler(logging.FileHandler('apdu_audit.log'))
audit_logger.setLevel(logging.INFO)
```

## Extension Points

### Custom Commands
Add application-specific commands:

```python
from apdu4j_data.apdu_commands import APDU4JCommand

# Define custom commands
CUSTOM_COMMANDS = {
    'MY_APP_SELECT': APDU4JCommand(0x80, 0xA4, 0x04, 0x00),
    'MY_APP_PROCESS': APDU4JCommand(0x80, 0x30, 0x00, 0x00)
}

# Extend integration
apdu4j.commands.update(CUSTOM_COMMANDS)
```

### Protocol Extensions
Support additional protocols:

```python
class CustomProtocolInterface(APDU4JInterface):
    def send_custom_command(self, protocol_data):
        # Implement custom protocol handling
        pass
```

## Future Enhancements

### Planned Features
- **Secure Channel**: GlobalPlatform SCP02/SCP03 support
- **Biometric Integration**: BioAPI command support  
- **Contactless Extensions**: ISO 14443 Type A/B specific commands
- **EMV Kernel**: Level 2 kernel integration
- **Fuzzing Integration**: Automated command fuzzing capabilities

### Performance Optimizations
- **Command Caching**: Intelligent APDU result caching
- **Connection Pooling**: Multi-reader connection management
- **Async Operations**: Non-blocking APDU communication
- **Hardware Acceleration**: Native library integration for performance-critical operations