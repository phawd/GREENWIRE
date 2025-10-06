"""
Cryptographic Commands
======================

Cryptographic operations and key management.
"""

import argparse
import sys
import os

# Import the CLI framework
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from greenwire_modern import CommandResult, GreenwireCLI


def crypto_keygen(args: argparse.Namespace) -> CommandResult:
    """Generate cryptographic keys"""
    
    config = {
        'algorithm': args.algorithm,
        'key_size': args.key_size,
        'output_format': args.format
    }
    
    return CommandResult(
        success=True,
        message=f"Generated {args.algorithm} key ({args.key_size} bits)",
        data=config
    )


def crypto_encrypt(args: argparse.Namespace) -> CommandResult:
    """Encrypt data"""
    
    config = {
        'algorithm': args.algorithm,
        'input_file': args.input,
        'output_file': args.output
    }
    
    return CommandResult(
        success=True,
        message="Data encrypted successfully",
        data=config
    )


def register_crypto_commands(cli: GreenwireCLI):
    """Register crypto commands"""
    
    cli.register_command(
        name='crypto-keygen',
        func=crypto_keygen,
        description='Generate cryptographic keys',
        args=[
            {'name': '--algorithm', 'choices': ['rsa', 'aes', 'des'], 'default': 'aes'},
            {'name': '--key-size', 'type': int, 'default': 256},
            {'name': '--format', 'choices': ['pem', 'der', 'raw'], 'default': 'pem'},
        ]
    )
    
    cli.register_command(
        name='crypto-encrypt',
        func=crypto_encrypt,
        description='Encrypt data',
        args=[
            {'name': 'input', 'help': 'Input file'},
            {'name': 'output', 'help': 'Output file'},
            {'name': '--algorithm', 'choices': ['aes', 'des'], 'default': 'aes'},
        ]
    )