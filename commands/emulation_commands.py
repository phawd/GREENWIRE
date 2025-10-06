"""
Emulation Commands
==================

Commands for terminal and card emulation.
"""

import argparse
import sys
import os

# Import the CLI framework
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from greenwire_modern import CommandResult, GreenwireCLI


def emulate_terminal(args: argparse.Namespace) -> CommandResult:
    """Emulate a payment terminal"""
    
    config = {
        'mode': 'terminal',
        'wireless': args.wireless,
        'card_types': args.card_types or ['visa', 'mastercard'],
        'authentication': args.auth_mode,
        'amount_limit': args.amount_limit
    }
    
    if not args.dry_run:
        # Simulate terminal emulation
        print("🏪 Starting payment terminal emulation...")
        print(f"   Wireless: {'✅' if args.wireless else '❌'}")
        print(f"   Card types: {', '.join(config['card_types'])}")
        print(f"   Auth mode: {config['authentication']}")
        
    return CommandResult(
        success=True,
        message="Terminal emulation started successfully",
        data=config
    )


def emulate_card(args: argparse.Namespace) -> CommandResult:
    """Emulate a payment card"""
    
    config = {
        'mode': 'card',
        'card_type': args.card_type,
        'pan': args.pan,
        'uid': args.uid,
        'contactless': args.contactless
    }
    
    if not args.dry_run:
        print("💳 Starting payment card emulation...")
        print(f"   Type: {config['card_type']}")
        print(f"   PAN: {config['pan'][:6]}****{config['pan'][-4:] if config['pan'] else 'auto'}")
        print(f"   Contactless: {'✅' if args.contactless else '❌'}")
    
    return CommandResult(
        success=True,
        message="Card emulation started successfully", 
        data=config
    )


def register_emulation_commands(cli: GreenwireCLI):
    """Register emulation commands"""
    
    cli.register_command(
        name='emulate-terminal',
        func=emulate_terminal,
        description='Emulate a payment terminal',
        args=[
            {'name': '--wireless', 'action': 'store_true', 'help': 'Enable wireless/NFC mode'},
            {'name': '--card-types', 'nargs': '+', 'help': 'Supported card types'},
            {'name': '--auth-mode', 'choices': ['pin', 'signature', 'contactless'], 'default': 'pin'},
            {'name': '--amount-limit', 'type': float, 'default': 100.0, 'help': 'Transaction limit'},
        ],
        aliases=['terminal']
    )
    
    cli.register_command(
        name='emulate-card',
        func=emulate_card,
        description='Emulate a payment card',
        args=[
            {'name': '--card-type', 'choices': ['visa', 'mastercard', 'amex'], 'default': 'visa'},
            {'name': '--pan', 'type': str, 'help': 'Primary Account Number'},
            {'name': '--uid', 'type': str, 'help': 'Card UID'},
            {'name': '--contactless', 'action': 'store_true', 'help': 'Enable contactless mode'},
        ],
        aliases=['card']
    )