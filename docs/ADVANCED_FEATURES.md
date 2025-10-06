# GREENWIRE Advanced Features Documentation

## Overview

This document covers the advanced features recently added to GREENWIRE:

- **Cryptographic MAC Engine**: Full MAC/CMAC/Retail MAC implementation
- **Blandy's Flowers POS**: Merchant terminal emulator
- **Smart APDU Fuzzer**: Advanced fuzzing with TLV manipulation
- **Unified Interface**: Single interface for fuzzing and personalization

---

## 1. Cryptographic MAC Engine

**Location**: `modules/crypto_mac_engine.py`

### Purpose

Comprehensive MAC (Message Authentication Code) implementation for EMV operations, JavaCard development, and cryptographic fuzzing.

### Features

#### Supported Algorithms

- **ISO 9797-1 Algorithm 1**: DES CBC-MAC with zero IV (legacy EMV)
- **ISO 9797-1 Algorithm 3**: Retail MAC/EDE (most common EMV MAC)
- **CMAC-AES**: Modern EMV/JavaCard (NIST SP 800-38B)
- **CMAC-3DES**: Legacy secure messaging
- **HMAC-SHA1**: Legacy EMV
- **HMAC-SHA256**: Modern EMV

#### EMV Operations

- **Session Key Derivation**: Derive session keys from master key + ATC/ARQC
- **ARQC Generation**: Generate Authorization Request Cryptograms
- **AC Generation**: Generate Application Cryptograms (ARQC/AAC/TC)
- **KCV Generation**: Generate Key Check Values

#### Fuzzing Functions

- **Bitflip**: Flip single bit in MAC
- **Nibble Mutation**: Replace 4-bit nibble
- **Incremental**: Increment MAC as integer

### Usage Examples

```python
from modules.crypto_mac_engine import MACEngine

# Initialize engine
mac_engine = MACEngine()

# Generate Retail MAC (most common EMV)
key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
data = b"Hello EMV"
mac = mac_engine.mac_iso9797_alg3(key, data)
print(f"Retail MAC: {mac.hex()}")

# Generate ARQC for transaction
master_key = bytes.fromhex("FEDCBA98765432100123456789ABCDEF")
atc = bytes.fromhex("0001")
transaction_data = bytes.fromhex("0000000001000840")

# Derive session key
session_key = mac_engine.emv_mac_session_key(master_key, atc)

# Generate ARQC
arqc = mac_engine.emv_arqc_mac(session_key, transaction_data)
print(f"ARQC: {arqc.hex()}")

# Generate KCV for key verification
kcv = mac_engine.generate_kcv(key)
print(f"KCV: {kcv.hex()}")

# Fuzz MAC for testing
fuzzed = mac_engine.fuzz_mac_bitflip(mac, bit_position=7)
print(f"Fuzzed MAC: {fuzzed.hex()}")
```

### Convenience Functions

```python
from modules.crypto_mac_engine import (
    generate_retail_mac,
    generate_cmac_aes,
    generate_emv_arqc,
    verify_retail_mac
)

# Quick Retail MAC
mac = generate_retail_mac(key, data)

# Quick AES-CMAC
cmac = generate_cmac_aes(key, data, truncate_to=8)

# Quick ARQC generation
arqc = generate_emv_arqc(master_key, atc, transaction_data)

# Quick MAC verification
is_valid = verify_retail_mac(key, data, expected_mac)
```

### Technical Details

#### ISO 9797-1 Algorithm 3 (Retail MAC)

1. Pad data using ISO/IEC 9797-1 Padding Method 2 (0x80 + zeros)
2. Apply DES CBC on all blocks except the last (zero IV)
3. Apply 3DES EDE (Encrypt-Decrypt-Encrypt) on final block
4. Return last 8 bytes

#### EMV Session Key Derivation

```
Session Key = 3DES(Master Key, ATC || ARQC || Padding)
```

#### ARQC Generation

```
ARQC = Retail MAC(Session Key, Transaction Data)
```

---

## 2. Blandy's Flowers POS Terminal

**Location**: `modules/blandys_flowers_pos.py`

### Purpose

Full-featured merchant Point of Sale terminal emulator for card acceptance, fuzzing, and personalization testing.

### Merchant Configuration

- **Name**: Blandy's Flowers
- **Merchant ID**: BF0001234567
- **Terminal ID**: BF000001
- **Category**: 5992 (Florists)
- **Country**: USA (840)
- **Currency**: USD (840)

### Features

#### Normal Transaction Processing

- Card detection (contact/contactless)
- Application selection (PSE or direct AID)
- Get Processing Options (GPO)
- Read application data
- Cardholder verification (PIN)
- Generate Application Cryptogram (ARQC)
- Transaction approval/decline

#### Fuzzing Capabilities

- Transaction flow fuzzing
- APDU parameter fuzzing (P1/P2)
- Amount overflow testing
- TLV structure mutations
- Response anomaly detection

#### Card Personalization

- Uses same reader interface
- Write personalization data
- Issuer authentication
- Key injection

### Usage Examples

```bash
# Normal transaction
python modules/blandys_flowers_pos.py --amount 12.50

# Fuzzing mode
python modules/blandys_flowers_pos.py --fuzz --iterations 100

# Card personalization
python modules/blandys_flowers_pos.py --personalize

# Debug mode
python modules/blandys_flowers_pos.py --debug --amount 25.00
```

```python
from modules.blandys_flowers_pos import BlandysFlowersPOS

# Initialize POS
pos = BlandysFlowersPOS(debug=True)

# Connect to reader
pos.connect_reader()

# Process transaction
transaction = pos.process_transaction(amount_cents=1250)
print(f"Status: {transaction['status']}")
print(f"ARQC: {transaction.get('arqc')}")

# Fuzz transaction flow
results = pos.fuzz_transaction(iterations=50)

# Personalize card
card_data = {
    "PAN": "4111111111111111",
    "Expiry": "12/25",
    "Cardholder": "John Doe"
}
success = pos.personalize_card(card_data)

# Save logs
pos.save_transaction_log("transactions.json")
pos.print_report()
```

### Transaction Flow

```
1. Card Detection      → Wait for card insertion
2. SELECT APPLICATION  → PSE or AID selection
3. GET PROCESSING OPT  → Send GPO with PDOL data
4. READ RECORDS        → Read application data (SFI/records)
5. CARDHOLDER VERIFY   → PIN verification (simulated)
6. GENERATE AC         → Request ARQC cryptogram
7. APPROVAL/DECLINE    → Transaction result
```

---

## 3. Smart APDU Fuzzer

**Location**: `modules/smart_apdu_fuzzer.py`

### Purpose

Advanced APDU fuzzing that uses cryptographic mutations and TLV manipulation to cause unusual card behavior (reboot, unlock, error states).

### Fuzzing Strategies

#### 1. GENERATE AC Mutations

Targets EMV cryptogram generation:

- **Reference Control Fuzzing**: Invalid P1 values (0x01, 0x10, 0x20, etc.)
- **CDOL Data Fuzzing**: Malformed CDOL structures
- **CVN Fuzzing**: Invalid Cryptogram Version Numbers
- **Amount Overflow**: BCD overflow values (0xFFFFFFFFFFFF)
- **Country Code Fuzzing**: Reserved/invalid country codes
- **Reserved Bits**: Set reserved bits in P2

#### 2. TLV Structure Fuzzing

Targets TLV parsers:

- **Length Overflow**: Set TLV length to 0xFF or long-form encoding
- **Length Underflow**: Claim less data than provided
- **Nested Bombs**: Create deeply nested TLV structures
- **Invalid Class**: Use reserved tag class bits
- **Long Form Abuse**: Unnecessary long-form length encoding
- **Truncated Values**: Length claims more than available

#### 3. P1/P2 Parameter Fuzzing

Systematically test all parameter combinations:

- All bits set (0xFF, 0xFF)
- All bits clear (0x00, 0x00)
- Random values
- Alternating bits (0xAA, 0x55)
- MSB only (0x80, 0x00)

#### 4. State Machine Fuzzing

Send commands in unexpected order:

- Random command sequences
- Skip mandatory commands
- Repeat commands
- Send commands out of context

#### 5. Timing Attack Fuzzing

Test race conditions:

- Vary command delays (0ms to 2s)
- Detect timing anomalies
- Rapid command bursts

### Usage Examples

```bash
# GENERATE AC fuzzing
python modules/smart_apdu_fuzzer.py --mode generate_ac --iterations 100

# TLV fuzzing
python modules/smart_apdu_fuzzer.py --mode tlv --iterations 100

# P1/P2 fuzzing
python modules/smart_apdu_fuzzer.py --mode p1p2 --iterations 100

# State machine fuzzing
python modules/smart_apdu_fuzzer.py --mode sequence --iterations 50

# Timing attack fuzzing
python modules/smart_apdu_fuzzer.py --mode timing --iterations 50

# Debug mode
python modules/smart_apdu_fuzzer.py --debug --mode generate_ac
```

```python
from modules.smart_apdu_fuzzer import SmartAPDUFuzzer

# Initialize fuzzer
fuzzer = SmartAPDUFuzzer(debug=True)

# Connect to card
fuzzer.connect()

# Fuzz GENERATE AC
results = fuzzer.fuzz_generate_ac_mutations(iterations=100)

# Fuzz TLV structures
base_tlv = bytes([0x83, 0x00])
results = fuzzer.fuzz_tlv_structures(base_tlv, iterations=100)

# Fuzz P1/P2 parameters
base_cmd = [0x80, 0xA8]  # GPO
results = fuzzer.fuzz_p1_p2_parameters(base_cmd, iterations=100)

# Fuzz command sequence
results = fuzzer.fuzz_command_sequence(iterations=50)

# Fuzz timing
cmd = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00]
results = fuzzer.fuzz_timing_attacks(cmd, iterations=50)

# Print summary
fuzzer.print_summary()

# Save results
fuzzer.save_results("fuzz_results.json")
```

### Expected Unusual Behaviors

The fuzzer is designed to trigger:

- **Card Reboots**: Sending malformed TLV or overflow data
- **Unlock States**: Invalid reference control bytes
- **Error States**: Reserved bits, invalid CVN
- **Timing Anomalies**: Race conditions in state machine
- **Parser Crashes**: Nested TLV bombs, truncated data

---

## 4. Unified Card Interface

**Location**: `modules/unified_card_interface.py`

### Purpose

Single unified interface for all card operations: transactions, fuzzing, personalization, and testing. Same reader connection, seamless mode switching.

### Operation Modes

```python
class OperationMode(Enum):
    TRANSACTION = "transaction"
    FUZZING = "fuzzing"
    PERSONALIZATION = "personalization"
    TESTING = "testing"
```

### Features

- **Shared Connection**: All modes use same reader/card connection
- **Mode Switching**: Seamlessly switch between modes
- **Integrated MAC**: Built-in MAC engine for all crypto operations
- **Operation Logging**: Track all operations with timestamps
- **Predefined Workflows**: Common operation sequences

### Usage Examples

```bash
# Transaction mode
python modules/unified_card_interface.py --mode transaction --amount 25.00

# Fuzzing mode
python modules/unified_card_interface.py --mode fuzzing --iterations 100

# Testing mode
python modules/unified_card_interface.py --mode testing

# Predefined workflows
python modules/unified_card_interface.py --workflow tx_fuzz --amount 12.50 --iterations 50
python modules/unified_card_interface.py --workflow personalize_test

# Debug mode
python modules/unified_card_interface.py --debug --mode transaction
```

```python
from modules.unified_card_interface import UnifiedCardInterface, OperationMode

# Initialize interface
interface = UnifiedCardInterface(debug=True)

# Connect to card (shared across all modes)
interface.connect()

# Mode 1: Process transaction
interface.set_mode(OperationMode.TRANSACTION)
tx_result = interface.process_transaction(amount_cents=1250)

# Mode 2: Fuzz card
interface.set_mode(OperationMode.FUZZING)
fuzz_results = interface.fuzz_card("generate_ac", iterations=100)

# Mode 3: Personalize card
interface.set_mode(OperationMode.PERSONALIZATION)
card_data = {
    "PAN": "4111111111111111",
    "Expiry": "12/25",
    "Cardholder": "Test Card"
}
success = interface.personalize_card(card_data)

# Mode 4: Test compliance
interface.set_mode(OperationMode.TESTING)
compliance = interface.test_card_compliance()

# Generate cryptographic keys
master_key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
keys = interface.generate_card_keys(master_key, "4111111111111111")
print(f"KCV: {keys['kcv'].hex()}")

# Save logs
interface.save_operation_log("operations.json")
interface.print_summary()
```

### Predefined Workflows

#### Workflow 1: Transaction → Fuzzing

```python
interface.workflow_transaction_then_fuzz(amount_cents=1250, fuzz_iterations=50)
```

Sequence:

1. Process normal transaction
2. Fuzz card with GENERATE AC mutations
3. Test card compliance after fuzzing
4. Report results

#### Workflow 2: Personalize → Test

```python
card_data = {"PAN": "4111111111111111", "Expiry": "12/25", "Cardholder": "Test"}
interface.workflow_personalize_then_test(card_data)
```

Sequence:

1. Personalize card with issuer data
2. Generate cryptographic keys
3. Run compliance tests
4. Test transaction processing
5. Report results

### Operation Logging

All operations are logged:

```json
{
  "mode": "transaction",
  "operations": [
    {
      "action": "mode_switch",
      "from": "transaction",
      "to": "fuzzing"
    },
    {
      "action": "transaction",
      "amount": 12.50,
      "currency": "USD",
      "status": "APPROVED"
    },
    {
      "action": "fuzzing",
      "strategy": "generate_ac",
      "iterations": 100,
      "results_count": 100
    }
  ],
  "total_operations": 3
}
```

---

## Integration with GREENWIRE

### Add to Menu System

Edit `core/ui/menu_actions.py`:

```python
def blandy_pos_transaction():
    """Run Blandy's Flowers POS transaction."""
    from modules.blandys_flowers_pos import BlandysFlowersPOS
    
    pos = BlandysFlowersPOS(debug=True)
    if pos.connect_reader():
        pos.process_transaction(amount_cents=1250)
        pos.print_report()

def smart_fuzzing():
    """Run smart APDU fuzzing."""
    from modules.smart_apdu_fuzzer import SmartAPDUFuzzer
    
    fuzzer = SmartAPDUFuzzer(debug=True)
    if fuzzer.connect():
        fuzzer.fuzz_generate_ac_mutations(iterations=100)
        fuzzer.print_summary()

def unified_interface():
    """Run unified interface."""
    from modules.unified_card_interface import UnifiedCardInterface
    
    interface = UnifiedCardInterface(debug=True)
    if interface.connect():
        interface.workflow_transaction_then_fuzz(1250, 50)
        interface.print_summary()

# Add to MENU_ACTIONS
MENU_ACTIONS = {
    # ... existing actions ...
    "blandy_pos": blandy_pos_transaction,
    "smart_fuzz": smart_fuzzing,
    "unified": unified_interface,
}
```

### Add to CLI

Edit `greenwire.py`:

```python
# Add command-line arguments
parser.add_argument('--blandy-pos', action='store_true',
                    help="Run Blandy's Flowers POS terminal")
parser.add_argument('--smart-fuzz', action='store_true',
                    help="Run smart APDU fuzzing")
parser.add_argument('--unified', action='store_true',
                    help="Run unified card interface")

# Add handlers
if args.blandy_pos:
    from modules.blandys_flowers_pos import BlandysFlowersPOS
    pos = BlandysFlowersPOS(debug=args.debug)
    pos.connect_reader()
    pos.process_transaction(amount_cents=1250)

if args.smart_fuzz:
    from modules.smart_apdu_fuzzer import SmartAPDUFuzzer
    fuzzer = SmartAPDUFuzzer(debug=args.debug)
    fuzzer.connect()
    fuzzer.fuzz_generate_ac_mutations(iterations=100)

if args.unified:
    from modules.unified_card_interface import UnifiedCardInterface
    interface = UnifiedCardInterface(debug=args.debug)
    interface.connect()
    interface.workflow_transaction_then_fuzz(1250, 50)
```

---

## Testing

### Test MAC Engine

```bash
cd GREENWIRE/modules
python crypto_mac_engine.py
```

Expected output:

```
Testing Retail MAC...
Testing AES-CMAC...
Testing EMV ARQC...
Testing KCV generation...
All tests passed!
```

### Test Blandy's POS

```bash
cd GREENWIRE/modules
python blandys_flowers_pos.py --amount 12.50
```

### Test Smart Fuzzer

```bash
cd GREENWIRE/modules
python smart_apdu_fuzzer.py --mode generate_ac --iterations 10
```

### Test Unified Interface

```bash
cd GREENWIRE/modules
python unified_card_interface.py --workflow tx_fuzz --amount 12.50 --iterations 10
```

---

## Security Considerations

### Key Management

- **Never commit real keys** to version control
- Use hardware-backed keys for production
- Implement key rotation policies
- Store keys in secure HSM

### Fuzzing Safety

- **Test only on development cards**
- Monitor card behavior for permanent damage
- Implement rate limiting to avoid card lockout
- Keep backup cards for testing

### POS Security

- Implement TLS for network communication
- Use EMV certificate validation
- Implement PIN encryption (not just simulation)
- Log all transactions for audit

---

## Troubleshooting

### PC/SC Not Available

```
Error: PC/SC not available
Solution: Install pyscard
  pip install pyscard
```

### No Card Readers Found

```
Error: No card readers found
Solution: 
  - Check reader connection (USB)
  - Install reader drivers
  - Check PC/SC service is running
```

### Card Not Responding

```
Error: Card not responding
Solution:
  - Check card is properly inserted
  - Try different reader
  - Verify card is not locked
  - Reduce fuzzing iteration rate
```

### MAC Verification Failed

```
Error: MAC verification failed
Solution:
  - Verify key is correct
  - Check key length (16 or 24 bytes for 3DES)
  - Verify algorithm selection (Retail MAC vs CMAC)
  - Check data padding
```

---

## References

- **EMV Book 2**: Security and Key Management
- **EMV Book 3**: Application Specification
- **ISO 9797-1**: Message Authentication Codes
- **NIST SP 800-38B**: CMAC Specification
- **GlobalPlatform**: Card Specification

---

## Future Enhancements

### Planned Features

- [ ] NFC/contactless fuzzing
- [ ] CDA (Combined DDA) support
- [ ] SDA (Static Data Authentication)
- [ ] DDA (Dynamic Data Authentication)
- [ ] Multi-application card support
- [ ] Remote POS terminal (network mode)
- [ ] Real-time monitoring dashboard
- [ ] Machine learning for fuzzing optimization

### Contribution

See `CONTRIBUTING.md` for guidelines on adding new features.

---

**Last Updated**: 2025-01-21  
**Version**: 1.0.0  
**Author**: GREENWIRE Team
