# GREENWIRE v4.1 - Quick Reference

## Essential Commands

### Card Operations

```bash
# Create a new card with full EMV data
python greenwire_modern.py card-create --generate-pan --emv-data --crypto-keys

# List all cards
python greenwire_modern.py --format table card-list

# Validate a card
python greenwire_modern.py card-validate my_card.json
```

### Security Testing

```bash
# Enhanced data extraction (all attacks)
python greenwire_modern.py extract-data --attack-type all --iterations 100

# Quick security scan
python greenwire_modern.py security-scan

# Comprehensive penetration test
python greenwire_modern.py pentest --target smartcard --suite comprehensive
```

### Output Formats

```bash
# JSON output (machine-readable)
python greenwire_modern.py --format json <command>

# YAML output
python greenwire_modern.py --format yaml <command>

# Table format
python greenwire_modern.py --format table <command>

# Text format (default)
python greenwire_modern.py <command>
```

### Common Options

- `--format {text,json,yaml,table}` - Output format
- `--verbose` - Verbose output  
- `--quiet` - Quiet mode
- `--dry-run` - Show what would be done
- `--help` - Command help

## Available Commands (16 total)

### Card Management (4 commands)

- `card-create` - Create new payment cards
- `card-list` - List available cards  
- `card-validate` - Validate card data
- `card-clone` - Clone existing cards

### Security Testing (4 commands)

- `extract-data` - Enhanced data extraction
- `security-scan` - Vulnerability scanning
- `fuzz` - Comprehensive fuzzing
- `pentest` - Penetration testing

### Emulation (2 commands)

- `emulate-terminal` - Payment terminal emulation
- `emulate-card` - Payment card emulation

### Fuzzing (2 commands)

- `fuzz-apdu` - APDU-level fuzzing
- `fuzz-nfc` - NFC protocol fuzzing

### Cryptography (2 commands)

- `crypto-keygen` - Key generation
- `crypto-encrypt` - Data encryption

### NFC Operations (2 commands)

- `nfc-scan` - NFC device scanning
- `nfc-read` - NFC data reading

## Help System

```bash
# General help
python greenwire_modern.py --help

# List all commands
python greenwire_modern.py list commands

# Help for specific command
python greenwire_modern.py <command> --help
```

## Machine Integration

### Exit Codes

- `0` - Success
- `1` - Error
- `2` - Usage error

### Structured Output

```bash
# JSON for automation
python greenwire_modern.py --format json card-create --generate-pan

# Parse with jq
python greenwire_modern.py --format json security-scan | jq '.data.vulnerabilities'
```

### CI/CD Example

```bash
#!/bin/bash
python greenwire_modern.py card-create --generate-pan --output test.json
python greenwire_modern.py --format json security-scan --output results.json
if [ $? -eq 0 ]; then echo "Tests passed"; fi
```
