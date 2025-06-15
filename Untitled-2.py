#!/usr/bin/env python3

"""
GREENWIRE CLI Interface

Advanced EMV and smartcard security testing tool implementing EMVCo specified
attack methodologies and industry standard test requirements.

Attack Capabilities:
- Timing Analysis (EMVCo Book 4 §2.4)
  - PIN verification timing
  - Cryptographic operation analysis
  - Memory access patterns

- Power Analysis (EMVCo CAST §5.4)
  - Simple Power Analysis (SPA)
  - Differential Power Analysis (DPA)
  - Correlation Power Analysis (CPA)

- Clock Glitch (EMVCo CAST §4.2)
  - Instruction skip attacks
  - Data corruption
  - Crypto fault injection

- Combined Channel Attacks
  - Timing + power analysis
  - Protocol + timing vulnerabilities
  - Cross-interface attacks

Standards Compliance:
- EMVCo Books 1-4
- Mastercard CQM
- Visa PTP
- Amex AEIPS
- NIST FIPS 140-3
- Common Criteria EAL4+

Usage:
  greenwire-brute.py [options] --mode <mode> [--type <type>] [--count N]

Modes:
  standard     Basic EMV protocol testing
  simulate     Transaction simulation with fuzzing
  fuzz         Dedicated fuzzing mode
  readfuzz     Focus on READ RECORD fuzzing
  extractkeys  Extract and analyze keys

Attack Options:
  --mode MODE           Testing mode (required)
  --type TYPE          Card type (visa,mc,amex,etc)
  --count N            Number of iterations
  --auth AUTH          Authentication (pin,sig)
  --fuzz FUZZ          Fuzzing strategy

Analysis Options:
  --timing             Enable timing analysis
  --power              Enable power analysis
  --glitch             Enable glitch detection
  --combined           Test combined attacks

Output Options:
  --verbose            Enable detailed logging)
  --silent             Suppress non-error output
  --export FILE        Export results to JSON
"""

import sys
import time
import json
import argparse
import logging
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from datetime import datetime
import random
import struct
from math import log2
import hashlib
from collections import Counter
import threading
from concurrent.futures import ThreadPoolExecutor
import csv
import sqlite3
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass
from greenwire.core.fuzzer import SmartcardFuzzer
from smartcard.CardConnection import CardConnection

# Database Schema Version
DB_VERSION = 1

# Analysis thresholds defined in standards
ANALYSIS_THRESHOLDS = {
    'MIN_ENTROPY': 3.5,             # Minimum entropy for RNG quality (NIST SP 800-90B)
    'RESPONSE_TIME_THRESHOLD': 1.0,  # Max acceptable timing variation (EMV Book 4)
    'POWER_TRACE_SAMPLES': 1000,    # Minimum power traces for DPA (EMVCo CAST)
    'GLITCH_WIDTH_MIN': 10,         # Minimum glitch width in ns (EMVCo CAST)
    'GLITCH_WIDTH_MAX': 100         # Maximum glitch width in ns (EMVCo CAST)
}

# Card OS command sets for different platforms
CARD_OS_COMMANDS = {
    'JAVACARD': {
        'SELECT_APPLET': {'cla': 0x00, 'ins': 0xA4, 'p1': 0x04, 'p2': 0x00},
        'GET_STATUS': {'cla': 0x80, 'ins': 0xF2, 'p1': 0x40, 'p2': 0x00},
        'GET_MEMORY_INFO': {'cla': 0x80, 'ins': 0xF2, 'p1': 0x02, 'p2': 0x00},
        'VERIFY_PIN': {'cla': 0x00, 'ins': 0x20, 'p1': 0x00, 'p2': 0x00},
        'GET_CHALLENGE': {'cla': 0x00, 'ins': 0x84, 'p1': 0x00, 'p2': 0x00},
        'READ_BINARY': {'cla': 0x00, 'ins': 0xB0, 'p1': 0x00, 'p2': 0x00},
        'READ_RECORD': {'cla': 0x00, 'ins': 0xB2, 'p1': 0x00, 'p2': 0x00},
        'AUTHENTICATE': {'cla': 0x00, 'ins': 0x88, 'p1': 0x00, 'p2': 0x00},
    },
    'MULTOS': {
        'SELECT_APPLICATION': {'cla': 0x00, 'ins': 0xA4, 'p1': 0x04, 'p2': 0x00},
        'GET_DATA': {'cla': 0x80, 'ins': 0xCA, 'p1': 0x00, 'p2': 0x00},
        'GET_PURSE_BALANCE': {'cla': 0x80, 'ins': 0x50, 'p1': 0x00, 'p2': 0x00},
        'READ_RECORD': {'cla': 0x00, 'ins': 0xB2, 'p1': 0x00, 'p2': 0x00},
        'GET_RESPONSE': {'cla': 0x00, 'ins': 0xC0, 'p1': 0x00, 'p2': 0x00},
        'AUTHENTICATE': {'cla': 0x00, 'ins': 0x82, 'p1': 0x00, 'p2': 0x00},
    },
    'EMV': {
        'SELECT': {'cla': 0x00, 'ins': 0xA4, 'p1': 0x04, 'p2': 0x00},
        'GET_PROCESSING_OPTIONS': {'cla': 0x80, 'ins': 0xA8, 'p1': 0x00, 'p2': 0x00},
        'READ_RECORD': {'cla': 0x00, 'ins': 0xB2, 'p1': 0x00, 'p2': 0x00},
        'GET_DATA': {'cla': 0x80, 'ins': 0xCA, 'p1': 0x00, 'p2': 0x00},
        'INTERNAL_AUTHENTICATE': {'cla': 0x00, 'ins': 0x88, 'p1': 0x00, 'p2': 0x00},
        'GENERATE_AC': {'cla': 0x80, 'ins': 0xAE, 'p1': 0x00, 'p2': 0x00},
        'GET_CHALLENGE': {'cla': 0x00, 'ins': 0x84, 'p1': 0x00, 'p2': 0x00},
        'EXTERNAL_AUTHENTICATE': {'cla': 0x00, 'ins': 0x82, 'p1': 0x00, 'p2': 0x00},
        'PIN_VERIFY': {'cla': 0x00, 'ins': 0x20, 'p1': 0x00, 'p2': 0x00},
    }
}

# Configure logging with more detailed format and multiple handlers
LOG_FORMAT = '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
VERBOSE_FORMAT = '''
Time: %(asctime)s
Level: %(levelname)s
Thread: %(threadName)s
Message: %(message)s
'''

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required arguments
    parser.add_argument('--mode', required=True,
                       choices=['standard', 'simulate', 'fuzz', 'readfuzz', 'extractkeys'],
                       help='Testing mode')

    # Card options
    parser.add_argument('--type',
                       choices=['visa', 'mc', 'amex', 'maestro', 'discover', 'jcb', 'all', 'auto'],
                       default='auto',
                       help='Card type (default: auto)')

    parser.add_argument('--count', type=int, default=1,
                       help='Number of iterations')

    parser.add_argument('--auth',
                       choices=['pin', 'signature'],
                       help='Authentication method')

    # Attack options
    parser.add_argument('--fuzz',
                       choices=['random', 'param', 'crypto', 'entropy'],
                       help='Fuzzing strategy')

    parser.add_argument('--timing', action='store_true',
                       help='Enable timing analysis')

    parser.add_argument('--power', action='store_true',
                       help='Enable power analysis')

    parser.add_argument('--glitch', action='store_true',
                       help='Enable clock glitch detection')

    parser.add_argument('--combined', action='store_true',
                       help='Test combined attack vectors')

    # Output options
    parser.add_argument('--verbose', action='store_true',
                       help='Enable detailed logging')

    parser.add_argument('--silent', action='store_true',
                       help='Suppress non-error output')

    parser.add_argument('--export',
                       help='Export results to JSON file')

    # Advanced options
    parser.add_argument('--pattern-depth', type=int, default=3,
                        help='Maximum recursion depth for pattern fuzzing')

    parser.add_argument('--pattern-tags', type=str,
                        help='Comma-separated list of EMV tags to target')

    parser.add_argument('--max-retries', type=int, default=3,
                        help='Maximum retry attempts per command')

    args = parser.parse_args()

    # Post-processing of arguments
    if args.silent:
        args.verbose = False

    return args

def main():
    """Main execution flow"""
    args = parse_args()
    init_logging(args)

    try:
        logging.info(f"Starting GREENWIRE in {args.mode} mode")
        logging.info(f"Card type: {args.type}")

        # Initialize fuzzer
        fuzzer = SmartcardFuzzer()

        if args.timing or args.mode == 'standard':
            timing_results = run_timing_analysis(
                fuzzer,
                CARD_OS_COMMANDS['EMV'],
                args.count
            )

        if args.power:
            power_results = run_power_analysis(
                fuzzer,
                CARD_OS_COMMANDS['EMV'],
                ANALYSIS_THRESHOLDS['POWER_TRACE_SAMPLES']
            )

        if args.glitch:
            glitch_results = run_glitch_detection(
                fuzzer,
                CARD_OS_COMMANDS['EMV'],
                args.count
            )

        if args.combined:
            combined_results = run_combined_analysis(fuzzer, args)

        if args.export:
            results = {
                'timing': timing_results if args.timing else None,
                'power': power_results if args.power else None,
                'glitch': glitch_results if args.glitch else None,
                'combined': combined_results if args.combined else None,
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'mode': args.mode,
                    'card_type': args.type,
                    'iterations': args.count
                }
            }

            with open(args.export, 'w') as f:
                json.dump(results, f, indent=2)

        logging.info("Testing complete")

    except Exception as e:
        logging.error(f"Error during execution: {str(e)}", exc_info=True)
        sys.exit(1)

def run_timing_analysis(fuzzer: SmartcardFuzzer, commands: Dict, iterations: int) -> Dict:
    """
    Execute timing analysis attack suite following EMVCo Book 4 requirements

    Args:
        fuzzer: Initialized SmartcardFuzzer instance
        commands: Dictionary of APDU commands to test
        iterations: Number of test iterations

    Returns:
        Analysis results dictionary
    """
    results = {
        'vulnerabilities': [],
        'timings': {},
        'anomalies': []
    }

    for cmd_name, cmd_data in commands.items():
        logging.info(f"Running timing analysis for {cmd_name}")

        cmd = bytes(cmd_data.values())
        analysis = fuzzer.analyze_timing_attack(cmd, iterations)

        results['timings'][cmd_name] = analysis['timing']
        if analysis.get('vulnerabilities'):
            results['vulnerabilities'].extend(analysis['vulnerabilities'])

        # Log suspicious timing variations
        if analysis['timing'].get('anomalies'):
            logging.warning(f"[ANOMALY] Suspicious timing pattern in {cmd_name}")
            results['anomalies'].append({
                'command': cmd_name,
                'type': 'TIMING',
                'details': analysis['timing']['anomalies']
            })

    return results

def run_power_analysis(fuzzer: SmartcardFuzzer, commands: Dict, samples: int) -> Dict:
    """
    Execute power analysis attack suite following EMVCo CAST requirements

    Args:
        fuzzer: Initialized SmartcardFuzzer instance
        commands: Dictionary of APDU commands to test
        samples: Number of power traces to collect

    Returns:
        Analysis results dictionary
    """
    results = {
        'vulnerabilities': [],
        'traces': {},
        'correlations': {}
    }

    for cmd_name, cmd_data in commands.items():
        logging.info(f"Collecting power traces for {cmd_name}")

        cmd = bytes(cmd_data.values())
        analysis = fuzzer.test_power_analysis(cmd, samples)

        results['traces'][cmd_name] = analysis['traces']
        results['correlations'][cmd_name] = analysis['correlations']

        if analysis.get('vulnerabilities'):
            results['vulnerabilities'].extend(analysis['vulnerabilities'])

    return results

def run_glitch_detection(fuzzer: SmartcardFuzzer, commands: Dict, iterations: int) -> Dict:
    """
    Execute clock glitch detection following EMVCo CAST requirements

    Args:
        fuzzer: Initialized SmartcardFuzzer instance
        commands: Dictionary of APDU commands to test
        iterations: Number of test iterations

    Returns:
        Analysis results dictionary
    """
    results = {
        'vulnerabilities': [],
        'glitches': {},
        'anomalies': []
    }

    for cmd_name, cmd_data in commands.items():
        logging.info(f"Testing clock glitch resistance for {cmd_name}")

        cmd = bytes(cmd_data.values())
        analysis = fuzzer.detect_clock_glitch(cmd, iterations)

        results['glitches'][cmd_name] = analysis['glitches']

        if analysis['glitches']:
            logging.warning(f"[ANOMALY] Potential glitch vulnerability in {cmd_name}")
            results['anomalies'].append({
                'command': cmd_name,
                'type': 'GLITCH',
                'count': len(analysis['glitches'])
            })

        if analysis.get('vulnerabilities'):
            results['vulnerabilities'].extend(analysis['vulnerabilities'])

    return results

def run_combined_analysis(fuzzer: SmartcardFuzzer, args) -> Dict:
    """
    Execute combined attack detection looking for vulnerability combinations

    Args:
        fuzzer: Initialized SmartcardFuzzer instance
        args: Parsed command line arguments

    Returns:
        Analysis results dictionary
    """
    results = {
        'vulnerabilities': [],
        'correlations': [],
        'attack_chains': []
    }

    # Get baseline data from individual analyses
    timing_results = run_timing_analysis(fuzzer, CARD_OS_COMMANDS['EMV'], args.count)
    power_results = run_power_analysis(fuzzer, CARD_OS_COMMANDS['EMV'], ANALYSIS_THRESHOLDS['POWER_TRACE_SAMPLES'])
    glitch_results = run_glitch_detection(fuzzer, CARD_OS_COMMANDS['EMV'], args.count)

    # Look for correlated vulnerabilities
    for timing_vuln in timing_results['vulnerabilities']:
        for power_vuln in power_results['vulnerabilities']:
            if timing_vuln['command'] == power_vuln['command']:
                results['correlations'].append({
                    'type': 'TIMING_POWER',
                    'command': timing_vuln['command'],
                    'timing_details': timing_vuln,
                    'power_details': power_vuln
                })

    # Identify potential attack chains
    for corr in results['correlations']:
        if corr['type'] == 'TIMING_POWER':
            chain = {
                'type': 'KEY_EXTRACTION',
                'steps': [
                    f"Timing analysis of {corr['command']}",
                    f"Power analysis confirmation",
                    "Statistical key bit recovery",
                    "Key validation through protocol"
                ],
                'commands': [corr['command']],
                'standards': ['EMV_BOOK4_2.4', 'CAST_5.4']
            }
            results['attack_chains'].append(chain)

    return results

def main():
    """Main execution flow"""
    args = parse_args()
    init_logging(args)

    try:
        logging.info(f"Starting GREENWIRE in {args.mode} mode")
        logging.info(f"Card type: {args.type}")

        # Initialize fuzzer
        fuzzer = SmartcardFuzzer()

        if args.timing or args.mode == 'standard':
            timing_results = run_timing_analysis(
                fuzzer,
                CARD_OS_COMMANDS['EMV'],
                args.count
            )

        if args.power:
            power_results = run_power_analysis(
                fuzzer,
                CARD_OS_COMMANDS['EMV'],
                ANALYSIS_THRESHOLDS['POWER_TRACE_SAMPLES']
            )

        if args.glitch:
            glitch_results = run_glitch_detection(
                fuzzer,
                CARD_OS_COMMANDS['EMV'],
                args.count
            )

        if args.combined:
            combined_results = run_combined_analysis(fuzzer, args)

        if args.export:
            results = {
                'timing': timing_results if args.timing else None,
                'power': power_results if args.power else None,
                'glitch': glitch_results if args.glitch else None,
                'combined': combined_results if args.combined else None,
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'mode': args.mode,
                    'card_type': args.type,
                    'iterations': args.count
                }
            }

            with open(args.export, 'w') as f:
                json.dump(results, f, indent=2)

        logging.info("Testing complete")

    except Exception as e:
        logging.error(f"Error during execution: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
