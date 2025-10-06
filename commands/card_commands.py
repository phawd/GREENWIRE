"""
Card Management Commands
========================

Commands for creating, managing, and manipulating payment cards.
"""

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import the CLI framework
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from greenwire_modern import CommandResult, GreenwireCLI


def card_create(args: argparse.Namespace) -> CommandResult:
    """Create a new payment card with specified parameters"""
    
    # Validate required parameters
    if not args.pan and not args.generate_pan:
        return CommandResult(
            success=False,
            message="Either --pan or --generate-pan must be specified",
            exit_code=2
        )
    
    # Card data structure
    card_data = {
        'pan': args.pan or _generate_pan(args.bin_prefix, args.length),
        'expiry': args.expiry or _generate_expiry(),
        'cvv': args.cvv or _generate_cvv(),
        'cardholder_name': args.name or "TEST CARDHOLDER",
        'created_at': datetime.utcnow().isoformat() + "Z",
        'card_type': args.card_type,
        'issuer': args.issuer or "TEST_ISSUER"
    }
    
    # Add EMV data if requested
    if args.emv_data:
        card_data['emv'] = _generate_emv_data(card_data)
    
    # Add cryptographic keys if requested
    if args.crypto_keys:
        card_data['crypto'] = _generate_crypto_keys()
    
    # Save card data
    output_file = args.output or f"card_{card_data['pan'][-4:]}.json"
    
    if not args.dry_run:
        with open(output_file, 'w') as f:
            json.dump(card_data, f, indent=2)
    
    return CommandResult(
        success=True,
        message=f"Card created successfully: {card_data['pan']}",
        data={
            'pan': card_data['pan'],
            'expiry': card_data['expiry'],
            'output_file': output_file,
            'has_emv': args.emv_data,
            'has_crypto': args.crypto_keys
        }
    )


def card_list(args: argparse.Namespace) -> CommandResult:
    """List available card files"""
    
    search_dir = Path(args.directory or ".")
    pattern = args.pattern or "*.json"
    
    card_files = list(search_dir.glob(pattern))
    cards_data = []
    
    for card_file in card_files:
        try:
            with open(card_file) as f:
                card_data = json.load(f)
            
            if 'pan' in card_data:  # Looks like a card file
                cards_data.append({
                    'file': str(card_file),
                    'pan': _mask_pan(card_data['pan']),
                    'expiry': card_data.get('expiry', 'N/A'),
                    'type': card_data.get('card_type', 'Unknown'),
                    'created': card_data.get('created_at', 'N/A')
                })
        except (json.JSONDecodeError, KeyError):
            continue  # Skip non-card files
    
    return CommandResult(
        success=True,
        message=f"Found {len(cards_data)} card files",
        data={'cards': cards_data}
    )


def card_validate(args: argparse.Namespace) -> CommandResult:
    """Validate card data integrity and compliance"""
    
    try:
        with open(args.file) as f:
            card_data = json.load(f)
    except FileNotFoundError:
        return CommandResult(
            success=False,
            message=f"Card file not found: {args.file}",
            exit_code=1
        )
    except json.JSONDecodeError as e:
        return CommandResult(
            success=False,
            message=f"Invalid JSON in card file: {e}",
            exit_code=1
        )
    
    validation_results = {}
    
    # Validate PAN
    pan = card_data.get('pan', '')
    validation_results['pan_present'] = bool(pan)
    validation_results['pan_length'] = len(pan) in [16, 17, 18, 19]
    validation_results['luhn_valid'] = _validate_luhn(pan)
    
    # Validate expiry
    expiry = card_data.get('expiry', '')
    validation_results['expiry_present'] = bool(expiry)
    validation_results['expiry_format'] = len(expiry) == 5 and expiry[2] == '/'
    
    # Validate CVV
    cvv = card_data.get('cvv', '')
    validation_results['cvv_present'] = bool(cvv)
    validation_results['cvv_length'] = len(cvv) in [3, 4]
    
    # Overall validation
    all_valid = all(validation_results.values())
    
    return CommandResult(
        success=all_valid,
        message="Card validation passed" if all_valid else "Card validation failed",
        data={'validation': validation_results, 'card_file': str(args.file)}
    )


def card_clone(args: argparse.Namespace) -> CommandResult:
    """Clone an existing card with modifications"""
    
    try:
        with open(args.source) as f:
            source_card = json.load(f)
    except FileNotFoundError:
        return CommandResult(
            success=False,
            message=f"Source card file not found: {args.source}",
            exit_code=1
        )
    
    # Clone and modify
    cloned_card = source_card.copy()
    
    if args.new_pan:
        cloned_card['pan'] = args.new_pan
    elif args.generate_new_pan:
        cloned_card['pan'] = _generate_pan()
    
    if args.new_expiry:
        cloned_card['expiry'] = args.new_expiry
    
    if args.new_name:
        cloned_card['cardholder_name'] = args.new_name
    
    # Update metadata
    cloned_card['cloned_from'] = str(args.source)
    cloned_card['cloned_at'] = datetime.utcnow().isoformat() + "Z"
    
    # Save cloned card
    output_file = args.output or f"cloned_{cloned_card['pan'][-4:]}.json"
    
    if not args.dry_run:
        with open(output_file, 'w') as f:
            json.dump(cloned_card, f, indent=2)
    
    return CommandResult(
        success=True,
        message=f"Card cloned successfully",
        data={
            'source': str(args.source),
            'output': output_file,
            'new_pan': _mask_pan(cloned_card['pan'])
        }
    )


def _generate_pan(bin_prefix: str = "4000", length: int = 16) -> str:
    """Generate a valid PAN with Luhn checksum"""
    import random
    
    # Generate base number
    base = bin_prefix + ''.join(str(random.randint(0, 9)) for _ in range(length - len(bin_prefix) - 1))
    
    # Calculate Luhn checksum
    checksum = _calculate_luhn_checksum(base)
    return base + str(checksum)


def _generate_expiry() -> str:
    """Generate future expiry date"""
    import random
    from datetime import datetime, timedelta
    
    future_date = datetime.now() + timedelta(days=random.randint(365, 1825))  # 1-5 years
    return future_date.strftime("%m/%y")


def _generate_cvv() -> str:
    """Generate random CVV"""
    import random
    return str(random.randint(100, 999))


def _generate_emv_data(card_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate EMV application data"""
    return {
        'aid': '315041592E5359532E4444463031',  # Visa DDF
        'application_label': 'VISA',
        'track2_data': f"{card_data['pan']}D{card_data['expiry'].replace('/', '')}101",
        'tags': {
            '5A': card_data['pan'],  # Application PAN
            '5F24': card_data['expiry'].replace('/', ''),  # Expiry date
            '9F08': '0002',  # Application version
            '9F42': '840',   # Application currency code (USD)
        }
    }


def _generate_crypto_keys() -> Dict[str, Any]:
    """Generate cryptographic keys for the card"""
    import secrets
    
    return {
        'ac_key': secrets.token_hex(16),  # Application Cryptogram key
        'smc_key': secrets.token_hex(16),  # Secure Messaging for Confidentiality
        'smi_key': secrets.token_hex(16),  # Secure Messaging for Integrity
        'dac_key': secrets.token_hex(16),  # Data Authentication Code key
    }


def _mask_pan(pan: str) -> str:
    """Mask PAN for safe display"""
    if len(pan) < 8:
        return pan
    return pan[:6] + '*' * (len(pan) - 10) + pan[-4:]


def _validate_luhn(pan: str) -> bool:
    """Validate PAN using Luhn algorithm"""
    if not pan.isdigit():
        return False
    
    total = 0
    reverse_digits = pan[::-1]
    
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:  # Every second digit from the right
            n *= 2
            if n > 9:
                n = n // 10 + n % 10
        total += n
    
    return total % 10 == 0


def _calculate_luhn_checksum(partial_pan: str) -> int:
    """Calculate Luhn checksum digit"""
    total = 0
    reverse_digits = partial_pan[::-1]
    
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 0:  # Every second digit from the right (after checksum)
            n *= 2
            if n > 9:
                n = n // 10 + n % 10
        total += n
    
    return (10 - (total % 10)) % 10


def register_card_commands(cli: GreenwireCLI):
    """Register all card management commands"""
    
    # Card create command
    cli.register_command(
        name='card-create',
        func=card_create,
        description='Create a new payment card',
        args=[
            {'name': '--pan', 'type': str, 'help': 'Primary Account Number'},
            {'name': '--generate-pan', 'action': 'store_true', 'help': 'Generate random PAN'},
            {'name': '--bin-prefix', 'type': str, 'default': '4000', 'help': 'BIN prefix for generated PAN'},
            {'name': '--length', 'type': int, 'default': 16, 'help': 'PAN length'},
            {'name': '--expiry', 'type': str, 'help': 'Expiry date (MM/YY)'},
            {'name': '--cvv', 'type': str, 'help': 'Card verification value'},
            {'name': '--name', 'type': str, 'help': 'Cardholder name'},
            {'name': '--card-type', 'choices': ['visa', 'mastercard', 'amex', 'discover'], 
             'default': 'visa', 'help': 'Card type'},
            {'name': '--issuer', 'type': str, 'help': 'Issuer identifier'},
            {'name': '--emv-data', 'action': 'store_true', 'help': 'Include EMV application data'},
            {'name': '--crypto-keys', 'action': 'store_true', 'help': 'Generate cryptographic keys'},
            {'name': '--output', 'type': str, 'help': 'Output file path'},
        ],
        aliases=['create-card']
    )
    
    # Card list command
    cli.register_command(
        name='card-list',
        func=card_list,
        description='List available card files',
        args=[
            {'name': '--directory', 'type': str, 'help': 'Directory to search'},
            {'name': '--pattern', 'type': str, 'help': 'File pattern to match'},
        ],
        aliases=['list-cards']
    )
    
    # Card validate command
    cli.register_command(
        name='card-validate',
        func=card_validate,
        description='Validate card data integrity',
        args=[
            {'name': 'file', 'help': 'Card file to validate'},
        ],
        aliases=['validate-card']
    )
    
    # Card clone command
    cli.register_command(
        name='card-clone',
        func=card_clone,
        description='Clone an existing card with modifications',
        args=[
            {'name': 'source', 'help': 'Source card file'},
            {'name': '--new-pan', 'type': str, 'help': 'New PAN for cloned card'},
            {'name': '--generate-new-pan', 'action': 'store_true', 'help': 'Generate new PAN'},
            {'name': '--new-expiry', 'type': str, 'help': 'New expiry date'},
            {'name': '--new-name', 'type': str, 'help': 'New cardholder name'},
            {'name': '--output', 'type': str, 'help': 'Output file path'},
        ],
        aliases=['clone-card']
    )