# GREENWIRE v4.0 - Modern CLI Documentation

## Overview

GREENWIRE v4.0 features a completely rewritten command-line interface that is:

- **Machine/AI-friendly** with structured JSON/YAML output
- **Self-documenting** with comprehensive help system
- **Modular and extensible** with plugin architecture
- **Standards-compliant** with proper exit codes
- **Cross-platform** compatible

## Installation & Setup

### Basic Usage

```bash
# Run the modern CLI
python greenwire_modern.py --help

# List all available commands
python greenwire_modern.py list commands

# Get help for a specific command
python greenwire_modern.py <command> --help
```

### Global Options

All commands support these global options:

- `--format {text,json,yaml,table}` - Output format (default: text)
- `--verbose, -v` - Enable verbose output
- `--quiet, -q` - Quiet mode (errors only)
- `--dry-run` - Show what would be done without executing
- `--log-level {DEBUG,INFO,WARNING,ERROR}` - Set logging level
- `--config CONFIG` - Configuration file path

## Available Commands

### Card Management Commands

#### `card-create` - Create New Payment Cards

Create payment cards with full EMV data and cryptographic keys.

```bash
# Create a card with generated PAN
python greenwire_modern.py card-create --generate-pan --emv-data --crypto-keys

# Create a specific card
python greenwire_modern.py card-create --pan 4000123456789012 --expiry "12/25" --name "John Doe"

# Create with full options
python greenwire_modern.py card-create \
  --generate-pan \
  --bin-prefix 4000 \
  --length 16 \
  --card-type visa \
  --emv-data \
  --crypto-keys \
  --output my_card.json
```

**Options:**

- `--pan` - Specify Primary Account Number
- `--generate-pan` - Auto-generate PAN with Luhn validation
- `--bin-prefix` - BIN prefix for generated PAN (default: 4000)
- `--length` - PAN length (default: 16)
- `--expiry` - Expiry date (MM/YY format)
- `--cvv` - Card verification value
- `--name` - Cardholder name
- `--card-type {visa,mastercard,amex,discover}` - Card type
- `--issuer` - Issuer identifier
- `--emv-data` - Include EMV application data
- `--crypto-keys` - Generate cryptographic keys
- `--output` - Output file path

#### `card-list` - List Available Cards

```bash
# List all card files in current directory
python greenwire_modern.py card-list

# List cards in specific directory
python greenwire_modern.py card-list --directory ./cards

# Output as table
python greenwire_modern.py --format table card-list
```

#### `card-validate` - Validate Card Data

```bash
# Validate a card file
python greenwire_modern.py card-validate my_card.json

# JSON output with validation details
python greenwire_modern.py --format json card-validate my_card.json
```

#### `card-clone` - Clone Existing Cards

```bash
# Clone with new PAN
python greenwire_modern.py card-clone source_card.json --generate-new-pan

# Clone with modifications
python greenwire_modern.py card-clone source_card.json \
  --new-name "Alice Smith" \
  --new-expiry "06/27" \
  --output cloned_card.json
```

### Security Testing Commands

#### `extract-data` - Enhanced Data Extraction

Advanced data extraction with multiple attack vectors.

```bash
# Run all attack types
python greenwire_modern.py extract-data --attack-type all --iterations 100

# Specific attack type
python greenwire_modern.py extract-data --attack-type fuzzing --iterations 50

# With combo attacks and artifact saving
python greenwire_modern.py extract-data \
  --attack-type all \
  --combo-mode \
  --artifact-dir ./artifacts \
  --output extraction_results.json
```

**Attack Types:**

- `fuzzing` - Traditional APDU Fuzzing
- `timing` - Timing Analysis Attack
- `downgrade` - Protocol Downgrade Attack
- `covert` - Covert Channel Attack
- `bruteforce` - Brute Force Key Attack
- `persistence` - Advanced Persistence Attack
- `all` - Execute all attack types

#### `security-scan` - Vulnerability Scanning

```bash
# Basic security scan
python greenwire_modern.py security-scan

# Scan with specific target
python greenwire_modern.py security-scan --target smartcard_reader

# Save results
python greenwire_modern.py security-scan --output vuln_report.json
```

#### `fuzz` - Comprehensive Fuzzing

```bash
# Protocol fuzzing with learning
python greenwire_modern.py fuzz \
  --iterations 1000 \
  --learning \
  --protocol emv \
  --strategy guided

# NFC-specific fuzzing
python greenwire_modern.py fuzz-nfc --protocol iso14443a --iterations 500
```

#### `pentest` - Penetration Testing

```bash
# Comprehensive penetration test
python greenwire_modern.py pentest --target smartcard --suite comprehensive

# EMV-specific testing
python greenwire_modern.py pentest --target terminal --suite emv
```

### Emulation Commands

#### `emulate-terminal` - Payment Terminal Emulation

```bash
# Basic terminal emulation
python greenwire_modern.py emulate-terminal

# Wireless terminal with specific card types
python greenwire_modern.py emulate-terminal \
  --wireless \
  --card-types visa mastercard \
  --auth-mode contactless
```

#### `emulate-card` - Payment Card Emulation

```bash
# Emulate a specific card
python greenwire_modern.py emulate-card \
  --card-type visa \
  --pan 4000123456789012 \
  --contactless

# Emulate with custom UID
python greenwire_modern.py emulate-card --uid DEADBEEF --contactless
```

### Cryptographic Commands

#### `crypto-keygen` - Key Generation

```bash
# Generate AES key
python greenwire_modern.py crypto-keygen --algorithm aes --key-size 256

# Generate RSA key pair
python greenwire_modern.py crypto-keygen --algorithm rsa --key-size 2048 --format pem
```

#### `crypto-encrypt` - Data Encryption

```bash
# Encrypt a file
python greenwire_modern.py crypto-encrypt input.txt encrypted.bin --algorithm aes
```

### NFC Commands

#### `nfc-scan` - NFC Device Scanning

```bash
# Continuous NFC scanning
python greenwire_modern.py nfc-scan --continuous --timeout 60

# Scan specific protocol
python greenwire_modern.py nfc-scan --protocol iso14443a
```

#### `nfc-read` - NFC Data Reading

```bash
# Read NFC card data
python greenwire_modern.py nfc-read --aid A0000000031010 --output nfc_data.json
```

### Fuzzing Commands

#### `fuzz-apdu` - APDU-Level Fuzzing

```bash
# APDU fuzzing with learning
python greenwire_modern.py fuzz-apdu \
  --iterations 1000 \
  --learning \
  --aids A0000000031010,A0000000041010
```

## Output Formats

### Text Format (Default)

```bash
python greenwire_modern.py card-create --generate-pan
# Output: ✅ Card created successfully: 4000123456789012
```

### JSON Format

```bash
python greenwire_modern.py --format json card-create --generate-pan
```

```json
{
  "success": true,
  "message": "Card created successfully: 4000123456789012",
  "data": {
    "pan": "4000123456789012",
    "expiry": "08/30",
    "output_file": "card_9012.json",
    "has_emv": false,
    "has_crypto": false
  },
  "exit_code": 0,
  "timestamp": "2025-10-04T00:11:07.003187Z",
  "command": "card-create --generate-pan",
  "duration_ms": 45
}
```

### YAML Format

```bash
python greenwire_modern.py --format yaml security-scan
```

```yaml
success: true
message: Security scan completed - 2 vulnerabilities found
data:
  scan_id: scan_1759536676
  started_at: 2025-10-04T00:11:16.914309Z
  vulnerability_count: 2
exit_code: 0
timestamp: 2025-10-04T00:11:16.914320Z
```

### Table Format

```bash
python greenwire_modern.py --format table card-list
```

```
file           | pan               | expiry | type | created
test_card.json | 400040******4597  | 08/30  | visa | 2025-10-04T00:09:41.919256Z
```

## Machine/AI Integration

### Structured Output

All commands return structured data when using `--format json` or `--format yaml`, making them perfect for automation and AI processing.

### Exit Codes

- `0` - Success
- `1` - General error
- `2` - Misuse of command
- `126` - Cannot execute
- `127` - Command not found
- `128` - Invalid exit argument
- `130` - Interrupted

### Dry-Run Mode

Use `--dry-run` to see what would be executed without making changes:

```bash
python greenwire_modern.py --dry-run card-create --generate-pan --emv-data
```

## Configuration

### Configuration File

Create a YAML configuration file:

```yaml
# greenwire_config.yaml
logging:
  level: INFO
  file: greenwire.log

defaults:
  card_type: visa
  emv_data: true
  artifact_dir: ./artifacts
```

Use with:

```bash
python greenwire_modern.py --config greenwire_config.yaml <command>
```

## Built-in Commands

### System Information

```bash
# List all commands
python greenwire_modern.py list commands

# System health check
python greenwire_modern.py health

# Show configuration
python greenwire_modern.py config show
```

### Documentation

```bash
# Generate documentation
python greenwire_modern.py docs generate --format html --output docs/

# View documentation
python greenwire_modern.py docs view
```

## Integration Examples

### CI/CD Pipeline

```bash
#!/bin/bash
# Automated security testing pipeline

# Create test cards
python greenwire_modern.py card-create --generate-pan --emv-data --output test_card.json

# Run security scan
python greenwire_modern.py --format json security-scan --output security_results.json

# Run penetration testing
python greenwire_modern.py --format json pentest --target test_card.json --suite comprehensive

# Check results
if [ $? -eq 0 ]; then
  echo "Security tests passed"
else
  echo "Security issues detected"
  exit 1
fi
```

### Python Integration

```python
import subprocess
import json

# Run GREENWIRE command from Python
result = subprocess.run([
    'python', 'greenwire_modern.py', 
    '--format', 'json',
    'extract-data', 
    '--attack-type', 'fuzzing',
    '--iterations', '100'
], capture_output=True, text=True)

# Parse JSON output
data = json.loads(result.stdout)
print(f"Attack success rate: {data['success']}")
print(f"Vulnerabilities found: {len(data['data']['results'])}")
```

## Advanced Features

### Command Chaining

```bash
# Create card, validate it, then run security scan
python greenwire_modern.py card-create --generate-pan --output temp_card.json && \
python greenwire_modern.py card-validate temp_card.json && \
python greenwire_modern.py security-scan --target temp_card.json
```

### Parallel Execution

```bash
# Run multiple fuzzing attacks in parallel
python greenwire_modern.py fuzz-apdu --iterations 500 &
python greenwire_modern.py fuzz-nfc --iterations 500 &
wait
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed
2. **Permission Errors**: Run with appropriate permissions for hardware access
3. **Configuration Issues**: Validate configuration file syntax

### Debug Mode

```bash
python greenwire_modern.py --log-level DEBUG --verbose <command>
```

### Help System

Every command has comprehensive help:

```bash
python greenwire_modern.py <command> --help
```

## Migration from Legacy CLI

The new CLI maintains compatibility while providing enhanced features:

- All old functionality is available through new commands
- Structured output replaces plain text where beneficial
- Better error handling and validation
- Comprehensive logging and debugging

For specific migration assistance, refer to the legacy compatibility guide.

---

**GREENWIRE v4.0** - Modern, machine-friendly, and comprehensive payment card security testing.
