"""
Fuzzing Commands
================

Advanced fuzzing capabilities for payment systems.
"""

import argparse
import sys
import os

# Import the CLI framework
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from greenwire_modern import CommandResult, GreenwireCLI


def fuzz_apdu(args: argparse.Namespace) -> CommandResult:
    """APDU-level fuzzing"""
    
    config = {
        'iterations': args.iterations,
        'mutation_rate': args.mutation_rate,
        'target_aids': args.aids,
        'learning_mode': args.learning
    }
    
    return CommandResult(
        success=True,
        message=f"APDU fuzzing configured for {args.iterations} iterations",
        data=config
    )


def fuzz_nfc(args: argparse.Namespace) -> CommandResult:
    """NFC protocol fuzzing"""
    
    config = {
        'protocol': args.protocol,
        'iterations': args.iterations,
        'collision_detection': args.collision
    }
    
    return CommandResult(
        success=True,
        message=f"NFC fuzzing configured for {args.protocol} protocol",
        data=config
    )


def register_fuzz_commands(cli: GreenwireCLI):
    """Register fuzzing commands"""
    
    cli.register_command(
        name='fuzz-apdu',
        func=fuzz_apdu,
        description='APDU-level fuzzing',
        args=[
            {'name': '--iterations', 'type': int, 'default': 1000},
            {'name': '--mutation-rate', 'type': float, 'default': 0.1},
            {'name': '--aids', 'nargs': '+', 'help': 'Target AIDs'},
            {'name': '--learning', 'action': 'store_true', 'help': 'Enable learning mode'},
        ]
    )
    
    cli.register_command(
        name='fuzz-nfc',
        func=fuzz_nfc,
        description='NFC protocol fuzzing',
        args=[
            {'name': '--protocol', 'choices': ['iso14443a', 'iso14443b', 'felica'], 'default': 'iso14443a'},
            {'name': '--iterations', 'type': int, 'default': 500},
            {'name': '--collision', 'action': 'store_true', 'help': 'Test collision detection'},
        ]
    )