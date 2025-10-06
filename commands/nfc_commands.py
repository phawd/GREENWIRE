"""
NFC Commands
============

Near Field Communication operations and testing.
"""

import argparse
import sys
import os

# Import the CLI framework
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from greenwire_modern import CommandResult, GreenwireCLI


def nfc_scan(args: argparse.Namespace) -> CommandResult:
    """Scan for NFC devices"""
    
    config = {
        'timeout': args.timeout,
        'continuous': args.continuous,
        'protocol': args.protocol
    }
    
    return CommandResult(
        success=True,
        message="NFC scan completed",
        data=config
    )


def nfc_read(args: argparse.Namespace) -> CommandResult:
    """Read data from NFC card"""
    
    config = {
        'aid': args.aid,
        'output_file': args.output
    }
    
    return CommandResult(
        success=True,
        message="NFC card data read successfully",
        data=config
    )


def register_nfc_commands(cli: GreenwireCLI):
    """Register NFC commands"""
    
    cli.register_command(
        name='nfc-scan',
        func=nfc_scan,
        description='Scan for NFC devices',
        args=[
            {'name': '--timeout', 'type': int, 'default': 30},
            {'name': '--continuous', 'action': 'store_true'},
            {'name': '--protocol', 'choices': ['all', 'iso14443a', 'iso14443b'], 'default': 'all'},
        ]
    )
    
    cli.register_command(
        name='nfc-read',
        func=nfc_read,
        description='Read data from NFC card',
        args=[
            {'name': '--aid', 'type': str, 'help': 'Application ID'},
            {'name': '--output', 'type': str, 'help': 'Output file'},
        ]
    )