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
  --verbose            Enable detailed logging
  --silent             Suppress non-error output
  --export FILE        Export results to JSON
"""

import sys
import time
import json
import argparse
import logging
from typing import Dict, List, Tuple, Optional, Union, Any, Set
from dataclasses import dataclass
from pathlib import Path
import os
import re
import sqlite3
import random
import hashlib
from math import log2
from collections import Counter
import threading
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime
import struct

# Third-party imports
try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    from smartcard.CardConnection import CardConnection
    from greenwire.core.fuzzer import SmartcardFuzzer
except ImportError:
    logging.warning("Smartcard library not found. Running in simulation mode.")
    # Define mock classes/functions for simulation mode
    class CardConnection:
        def __init__(self, reader=None):
            self.reader = reader
        
        def transmit(self, apdu):
            return [], 0x90, 0x00
    
    class SmartcardFuzzer:
        def analyze_timing_attack(self, cmd, iterations):
            return {'timing': {}, 'vulnerabilities': []}
        
        def test_power_analysis(self, cmd, samples):
            return {'traces': {}, 'correlations': {}, 'vulnerabilities': []}
        
        def detect_clock_glitch(self, cmd, iterations):
            return {'glitches': {}, 'vulnerabilities': []}

# Constants
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

# EMV Command constants
EMV_COMMANDS = {
    'SELECT': [0x00, 0xA4, 0x04, 0x00],
    'READ_RECORD': [0x00, 0xB2],
    'GET_PROCESSING_OPTIONS': [0x80, 0xA8, 0x00, 0x00],
    'GET_DATA': [0x80, 0xCA],
    'INTERNAL_AUTHENTICATE': [0x00, 0x88, 0x00, 0x00],
    'GENERATE_AC': [0x80, 0xAE],
    'GET_CHALLENGE': [0x00, 0x84, 0x00, 0x00],
    'VERIFY': [0x00, 0x20, 0x00, 0x80],
    'EXTERNAL_AUTHENTICATE': [0x00, 0x82, 0x00, 0x00]
}

# Extended card types and commands
CARD_OS_TYPES = {
    'JAVACARD': {
        'aids': ['A0000000620001', 'A0000000620002'],
        'instructions': {
            'SELECT_APPLET': [0x00, 0xA4, 0x04, 0x00],
            'GET_STATUS': [0x80, 0xF2, 0x40, 0x00],
            'GET_DATA': [0x80, 0xCA],
            'PUT_DATA': [0x80, 0xDA],
            'CREATE_APPLET': [0x80, 0xB8, 0x00, 0x00],
            'DELETE_APPLET': [0x80, 0xE4, 0x00, 0x00],
            'GET_CARD_MANAGER_DATA': [0x80, 0xCA, 0x00, 0x66],
            'INSTALL': [0x80, 0xE6, 0x0C, 0x00],
            'LOAD': [0x80, 0xE8, 0x00, 0x00],
            'PUT_KEY': [0x80, 0xD8, 0x00, 0x00],
            'SET_STATUS': [0x80, 0xF0, 0x40, 0x00],
            'STORE_DATA': [0x80, 0xE2, 0x00, 0x00],
            'SELECT_SSD': [0x00, 0xA5, 0x00, 0x00],
        }
    },
    'MULTOS': {
        'aids': ['A000000401', 'A000000402'],
        'instructions': {
            'SELECT_APP': [0x00, 0xA4, 0x04, 0x00],
            'GET_MANUFACTURER': [0x00, 0x00, 0x00, 0x00],
            'GET_DIR': [0x80, 0xF2, 0x40, 0x00],
            'READ_MEMORY': [0xB0, 0x00, 0x00, 0x00],
            'WRITE_MEMORY': [0xD6, 0x00, 0x00, 0x00],
            'GET_CONFIGURATION_DATA': [0x80, 0xCA, 0xBF, 0x21],
            'GET_MANUFACTURER_DATA': [0x80, 0xCA, 0x00, 0x46],
            'GET_MULTOS_DATA': [0x80, 0xCA, 0x9F, 0x7F],
        }
    },
    'EMV_ADVANCED': {
        'aids': ['A0000000031010', 'A0000000041010'],
        'instructions': {
            'READ_BINARY': [0x00, 0xB0, 0x00, 0x00],
            'READ_BINARY_ODD': [0x00, 0xB1, 0x00, 0x00],
            'READ_RECORD': [0x00, 0xB2, 0x00, 0x00],
            'READ_RECORD_ODD': [0x00, 0xB3, 0x00, 0x00],
            'GET_DATA': [0x80, 0xCA, 0x00, 0x00],
            'GET_RESPONSE': [0x00, 0xC0, 0x00, 0x00],
            'ENVELOPE': [0x80, 0xC2, 0x00, 0x00],
            'GET_CHALLENGE': [0x00, 0x84, 0x00, 0x00],
            'EXTERNAL_AUTHENTICATE': [0x00, 0x82, 0x00, 0x00],
            'INTERNAL_AUTHENTICATE': [0x00, 0x88, 0x00, 0x00],
            'PIN_CHANGE': [0x00, 0x24, 0x00, 0x00],
            'UNBLOCK_PIN': [0x00, 0x2C, 0x00, 0x00],
            'GENERATE_AC': [0x80, 0xAE, 0x00, 0x00],
            'GET_PROCESSING_OPTIONS': [0x80, 0xA8, 0x00, 0x00],
            'VERIFY': [0x00, 0x20, 0x00, 0x00],
        }
    }
}

# Common AIDs (Application IDs)
EMV_AIDS = {
    'VISA': ['A0000000031010', 'A0000000032010', 'A0000000033010'],
    'MASTERCARD': ['A0000000041010', 'A0000000042010', 'A0000000043060'],
    'AMEX': ['A00000002501', 'A0000000250101'],
    'JCB': ['A0000000651010'],
    'DISCOVER': ['A0000003241010'],
    'INTERAC': ['A0000002771010'],
    'UNIONPAY': ['A000000333010101'],
    'VISA_DEBIT': ['A0000000980840', 'A0000000031020'],
    'VISA_CREDIT': ['A0000000031010'],
    'VISA_PLUS': ['A0000000038010'],
    'MC_DEBIT': ['A0000000043060'],
    'MC_CREDIT': ['A0000000041010'],
    'MC_MAESTRO': ['A0000000043060'],
    'AMEX_GREEN': ['A00000002501'],
    'AMEX_GOLD': ['A0000000250101'],
    'UNIONPAY_DEBIT': ['A000000333010101'],
    'UNIONPAY_CREDIT': ['A000000333010102'],
    'MIR': ['A0000006581010'],
    'RUPAY': ['A0000005241010'],
    'BANCONTACT': ['A0000000048002'],
    'EFTPOS': ['A0000003710001'],
}

# EMV Tag Definitions
EMV_TAGS = {
    '5A': 'Application PAN',
    '5F20': 'Cardholder Name',
    '5F24': 'Application Expiration Date',
    '5F25': 'Application Effective Date',
    '5F28': 'Issuer Country Code',
    '5F2A': 'Transaction Currency Code',
    '5F2D': 'Language Preference',
    '5F30': 'Service Code',
    '5F34': 'Application PAN Sequence Number',
    '82': 'Application Interchange Profile',
    '8C': 'CDOL1',
    '8D': 'CDOL2',
    '8E': 'CVM List',
    '8F': 'Certification Authority Public Key Index',
    '90': 'Issuer Public Key Certificate',
    '92': 'Issuer Public Key Remainder',
    '93': 'Signed Static Application Data',
    '94': 'Application File Locator',
    '95': 'Terminal Verification Results',
    '9A': 'Transaction Date',
    '9B': 'Transaction Status Information',
    '9C': 'Transaction Type',
    '9F02': 'Amount, Authorized',
    '9F03': 'Amount, Other',
    '9F05': 'Application Discretionary Data',
    '9F07': 'Application Usage Control',
    '9F08': 'Application Version Number',
    '9F0B': 'Cardholder Name Extended',
    '9F0D': 'Issuer Action Code - Default',
    '9F0E': 'Issuer Action Code - Denial',
    '9F0F': 'Issuer Action Code - Online',
    '9F10': 'Issuer Application Data',
    '9F11': 'Issuer Code Table Index',
    '9F12': 'Application Preferred Name',
    '9F1A': 'Terminal Country Code',
    '9F1F': 'Track 1 Discretionary Data',
    '9F20': 'Track 2 Discretionary Data',
    '9F26': 'Application Cryptogram',
    '9F27': 'Cryptogram Information Data',
    '9F32': 'Issuer Public Key Exponent',
    '9F36': 'Application Transaction Counter',
    '9F37': 'Unpredictable Number',
    '9F38': 'Processing Options Data Object List',
    '9F42': 'Application Currency Code',
    '9F44': 'Application Currency Exponent',
    '9F45': 'Data Authentication Code',
    '9F46': 'ICC Public Key Certificate',
    '9F47': 'ICC Public Key Exponent',
    '9F48': 'ICC Public Key Remainder',
    '9F4A': 'Static Data Authentication Tag List',
    '9F4C': 'ICC Dynamic Number'
}

CRYPTO_CONSTANTS = {
    'ECC_CURVES': ['curve25519', 'secp256k1']
}

KEY_TYPES = {
    'RSA': ['9F32', '9F47'],  # Public key exponents
    'DES': ['9F45', '9F4B'],  # Session keys
    'AES': ['9F4D', '9F4E'],  # Advanced keys
    'ECC': ['9F50', '9F51']   # Elliptic curve keys
}

FUZZ_PATTERNS = {
    'BUFFER_OVERFLOW': [
        [0xFF] * 256,  # Long sequence of FF
        [0x00] * 256,  # Long sequence of nulls
        [i % 256 for i in range(256)]  # Incrementing pattern
    ],
    'TIMING_ATTACK': [
        [0xA5] * 8,   # Fixed pattern
        [0x5A] * 16,  # Another fixed pattern
        [0xFF] * 32   # Maximum length pattern
    ]
}

# Configure logging with more detailed format and multiple handlers
LOG_FORMAT = '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
VERBOSE_FORMAT = '''
Time: %(asctime)s
Level: %(levelname)s
Thread: %(threadName)s
Message: %(message)s
'''

@dataclass
class TLVObject:
    """Representation of a BER-TLV data object"""
    tag: bytes
    length: int
    value: bytes
    
    @property
    def tag_str(self) -> str:
        """Return tag as a hexadecimal string"""
        return self.tag.hex().upper()
    
    @property
    def name(self) -> str:
        """Return the EMV tag name if known, otherwise 'Unknown'"""
        return EMV_TAGS.get(self.tag_str, 'Unknown')
    
    def __str__(self) -> str:
        """String representation of the TLV object"""
        return f"{self.tag_str} ({self.name}): {self.value.hex().upper()}"


class TLVParser:
    """BER-TLV parser for EMV data objects"""
    
    @staticmethod
    def parse(data: bytes) -> List[TLVObject]:
        """
        Parse BER-TLV encoded data into a list of TLV objects
        
        Args:
            data: Raw bytes containing BER-TLV encoded data
            
        Returns:
            List of parsed TLVObject instances
        """
        objects = []
        offset = 0
        
        while offset < len(data):
            if offset + 1 > len(data):
                break
                
            # Parse tag
            tag_start = offset
            first_byte = data[offset]
            offset += 1
            
            # Check for multi-byte tag
            if (first_byte & 0x1F) == 0x1F:
                while offset < len(data) and (data[offset] & 0x80) == 0x80:
                    offset += 1
                offset += 1
                
            tag = data[tag_start:offset]
            
            # Parse length
            if offset >= len(data):
                break
                
            length_byte = data[offset]
            offset += 1
            
            if length_byte & 0x80:
                num_length_bytes = length_byte & 0x7F
                if offset + num_length_bytes > len(data):
                    break
                    
                length = 0
                for i in range(num_length_bytes):
                    length = (length << 8) | data[offset + i]
                offset += num_length_bytes
            else:
                length = length_byte
                
            # Parse value
            if offset + length > len(data):
                break
                
            value = data[offset:offset + length]
            offset += length
            
            objects.append(TLVObject(tag, length, value))
            
        return objects

    @staticmethod
    def find_tag(data: bytes, tag: Union[str, bytes]) -> Optional[bytes]:
        """
        Find the value of a specific tag in BER-TLV encoded data
        
        Args:
            data: Raw bytes containing BER-TLV encoded data
            tag: Tag to search for, either as a string or bytes
            
        Returns:
            Value of the tag if found, None otherwise
        """
        if isinstance(tag, str):
            tag = bytes.fromhex(tag)
            
        objects = TLVParser.parse(data)
        for obj in objects:
            if obj.tag == tag:
                return obj.value
        return None


class CardResponseAnalyzer:
    """Helper class for analyzing card responses"""
    
    @staticmethod
    def analyze_timing(start_time: float, end_time: float, command_type: str) -> Dict[str, Any]:
        """
        Analyze response timing for potential side-channel vulnerabilities
        
        Args:
            start_time: Start time of the command execution
            end_time: End time of the command execution
            command_type: Type of command being analyzed
            
        Returns:
            Dictionary with timing analysis information
        """
        response_time = end_time - start_time
        timing_info = {
            'command': command_type,
            'response_time': response_time,
            'timestamp': datetime.now().isoformat(),
            'anomaly': response_time > ANALYSIS_THRESHOLDS['RESPONSE_TIME_THRESHOLD']
        }
        return timing_info
    
    @staticmethod
    def analyze_response_pattern(data: bytes) -> Optional[Dict[str, Any]]:
        """
        Analyze response data for patterns and anomalies
        
        Args:
            data: Response data to analyze
            
        Returns:
            Dictionary with pattern analysis information or None if data is empty
        """
        if not data:
            return None
            
        pattern_info = {
            'length': len(data),
            'unique_bytes': len(set(data)),
            'repeating_patterns': [],
            'byte_frequency': dict(Counter(data))
        }
        
        # Look for repeating patterns
        for pattern_len in range(2, min(16, len(data))):
            patterns = {}
            for i in range(len(data) - pattern_len):
                pattern = tuple(data[i:i+pattern_len])
                if pattern in patterns:
                    pattern_info['repeating_patterns'].append({
                        'pattern': list(pattern),
                        'length': pattern_len,
                        'positions': patterns[pattern] + [i]
                    })
                patterns[pattern] = [i]
                
        return pattern_info

    @staticmethod
    def detect_weak_random(data: bytes, min_entropy: float = ANALYSIS_THRESHOLDS['MIN_ENTROPY']) -> Dict[str, Any]:
        """
        Detect potentially weak random number generation
        
        Args:
            data: Data to analyze
            min_entropy: Minimum acceptable entropy threshold
            
        Returns:
            Dictionary with weak random detection results
        """
        if not data:
            return {'entropy_low': False, 'has_repeating_sequences': False, 
                    'has_linear_relationship': False, 'entropy_value': 0.0}
            
        entropy = CardResponseAnalyzer.calculate_entropy(data)
        repeating = CardResponseAnalyzer.find_repeating_sequences(data)
        linear = CardResponseAnalyzer.check_linear_relationship(data)
        
        return {
            'entropy_low': entropy < min_entropy,
            'has_repeating_sequences': bool(repeating),
            'has_linear_relationship': linear,
            'entropy_value': entropy
        }

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Data to calculate entropy for
            
        Returns:
            Entropy value
        """
        if not data:
            return 0.0
        counts = Counter(data)
        probs = [float(c)/len(data) for c in counts.values()]
        return -sum(p * log2(p) for p in probs)

    @staticmethod
    def find_repeating_sequences(data: bytes, min_length: int = 3) -> List[Dict[str, Any]]:
        """
        Find repeating sequences in data
        
        Args:
            data: Data to analyze
            min_length: Minimum length of sequences to consider
            
        Returns:
            List of dictionaries describing repeating sequences
        """
        sequences = []
        for length in range(min_length, len(data)//2):
            for start in range(len(data) - length):
                sequence = data[start:start+length]
                rest = data[start+length:]
                if sequence in rest:
                    sequences.append({
                        'sequence': sequence,
                        'length': length,
                        'positions': [start, start+length+rest.index(sequence)]
                    })
        return sequences

    @staticmethod
    def check_linear_relationship(data: bytes, window: int = 8) -> bool:
        """
        Check for linear relationships in data
        
        Args:
            data: Data to analyze
            window: Window size for analysis
            
        Returns:
            True if a linear relationship is detected, False otherwise
        """
        if len(data) < window:
            return False
            
        differences = []
        for i in range(len(data)-1):
            differences.append((data[i+1] - data[i]) % 256)
            
        # Check if differences are constant
        return len(set(differences[:window])) == 1


class VulnerabilityDetector:
    """Enhanced vulnerability detection system"""
    
    def __init__(self, db_manager):
        """
        Initialize the vulnerability detector
        
        Args:
            db_manager: Database manager instance for logging vulnerabilities
        """
        self.db_manager = db_manager
        self.command_timing_history = {}
        self.response_patterns = {}
        self.anomaly_thresholds = {
            'timing_deviation': 2.0,  # Standard deviations
            'response_length_min': 4,
            'suspicious_sw_codes': {
                0x6283: 'Selected file invalidated',
                0x6700: 'Wrong length',
                0x6982: 'Security status not satisfied',
                0x6983: 'Authentication method blocked',
                0x6984: 'Reference data invalidated',
                0x6985: 'Conditions of use not satisfied',
                0x6986: 'Command not allowed',
                0x6987: 'Expected SM data objects missing',
                0x6988: 'SM data objects incorrect'
            }
        }

    def analyze_command(self, command_type: str, apdu: bytes, response: bytes, 
                        sw1: int, sw2: int, execution_time: float) -> List[Dict[str, Any]]:
        """
        Analyze a command for potential vulnerabilities
        
        Args:
            command_type: Type of command being analyzed
            apdu: Command APDU
            response: Response data
            sw1: Status word 1
            sw2: Status word 2
            execution_time: Command execution time
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Timing analysis
        self._analyze_timing(command_type, execution_time, findings)
        
        # Response analysis
        self._analyze_response(response, findings)
        
        # Status word analysis
        self._analyze_status_words(sw1, sw2, findings)
        
        # Pattern analysis
        self._analyze_patterns(command_type, apdu, response, findings)
        
        # Log any findings
        for finding in findings:
            self.db_manager.log_vulnerability(
                finding['type'],
                finding['description'],
                finding['severity'],
                apdu,
                response
            )
        
        return findings

    def _analyze_timing(self, command_type: str, execution_time: float, findings: List[Dict[str, Any]]) -> None:
        """
        Analyze command timing for anomalies
        
        Args:
            command_type: Type of command being analyzed
            execution_time: Command execution time
            findings: List to append findings to
        """
        if command_type not in self.command_timing_history:
