#!/usr/bin/env python3

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

from greenwire.core.nfc_emv import (
    ContactlessEMVTerminal,
    CAPublicKey,
    load_ca_keys,
    DEFAULT_CA_KEYS,
)

# Analysis thresholds for security checks
ANALYSIS_THRESHOLDS = {
    'MIN_ENTROPY': 6.5,            # Minimum entropy for random values
    'MAX_PATTERN_RATIO': 0.1,      # Maximum ratio of repeating patterns
    'MIN_TIMING_DIFF': 0.001,      # Minimum significant timing difference (seconds)
    'MAX_ERROR_RATE': 0.05,        # Maximum acceptable error rate
    'MIN_KEY_STRENGTH': 128,       # Minimum acceptable key strength (bits)
}

# EMV standard definitions
EMV_STANDARDS = {
    'EMV_BOOK2': {
        'version': '4.3',
        'title': 'EMV Book 2 - Security and Key Management',
        'sections': {
            '6.3': 'Card Authentication Methods',
            '6.5': 'Offline PIN Processing',
            '7.2': 'Cryptogram Generation'
        }
    },
    'EMV_BOOK3': {
        'version': '4.3',
        'title': 'EMV Book 3 - Application Specification',
        'sections': {
            '10.5': 'CVM Processing',
            '6.5.5': 'Processing Restrictions'
        }
    },
    'EXPRESSPAY': {
        'version': '3.1',
        'title': 'American Express ExpressPay Specification',
        'sections': {
            '5.3': 'Transaction Flow',
            '6.2': 'Cryptogram Verification'
        }
    }
}

# Attack scenario definitions
ATTACK_SCENARIOS = {
    'SDA_DOWNGRADE': {
        'name': 'SDA Downgrade Attack',
        'standard': 'EMV_BOOK2',
        'section': '6.3',
        'steps': [
            'Intercept GENERATE AC command',
            'Modify AIP to indicate SDA only',
            'Force fallback to less secure SDA',
            'Validate cryptographic protection'
        ]
    },
    'PIN_BYPASS': {
        'name': 'PIN Bypass Attack',
        'standard': 'EMV_BOOK3',
        'section': '10.5',
        'steps': [
            'Modify CVM list',
            'Skip VERIFY command',
            'Force offline transaction',
            'Validate CVM processing'
        ]
    },
    'PRE_PLAY': {
        'name': 'Pre-play Attack',
        'standard': 'EMV_BOOK2',
        'section': '7.2',
        'steps': [
            'Collect terminal UNs',
            'Predict future values',
            'Pre-generate cryptograms',
            'Validate replay protection'
        ]
    },
    'EXPRESSPAY_REPLAY': {
        'name': 'ExpressPay Replay Attack',
        'standard': 'EXPRESSPAY',
        'section': '5.3',
        'steps': [
            'Capture NC and UDOL',
            'Manipulate parameters',
            'Replay cryptogram',
            'Validate replay protection'
        ]
    }
}

# Database Schema Version
DB_VERSION = 1

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

# Analysis thresholds for security checks
ANALYSIS_THRESHOLDS = {
    'MIN_ENTROPY': 6.5,            # Minimum entropy for random values
    'MAX_PATTERN_RATIO': 0.1,      # Maximum ratio of repeating patterns
    'MIN_TIMING_DIFF': 0.001,      # Minimum significant timing difference (seconds)
    'MAX_ERROR_RATE': 0.05,        # Maximum acceptable error rate
    'MIN_KEY_STRENGTH': 128,       # Minimum acceptable key strength (bits)
}

def init_database():
    """Initialize SQLite database with schema"""
    db_path = Path('greenwire.db')
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    
    # Create tables if they don't exist
    c.executescript('''
        -- Sessions table to track testing runs
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            card_type TEXT,
            mode TEXT,
            fuzzing_strategy TEXT
        );

        -- Commands table for APDU command history
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            command_type TEXT,
            apdu TEXT,
            response TEXT,
            sw1 INTEGER,
            sw2 INTEGER,
            execution_time REAL,
            is_anomaly BOOLEAN,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        -- Vulnerabilities table for tracking discovered issues
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            vulnerability_type TEXT,
            description TEXT,
            severity TEXT,
            apdu TEXT,
            response TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        -- Keys table for storing discovered keys and certificates
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            key_type TEXT,
            key_data BLOB,
            metadata TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        -- Timing analysis table for performance monitoring
        CREATE TABLE IF NOT EXISTS timing_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            command_type TEXT,
            execution_time REAL,
            statistics TEXT,
            anomaly_score REAL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        -- Version tracking table
        CREATE TABLE IF NOT EXISTS db_version (
            version INTEGER PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    
    # Insert/update version
    c.execute('INSERT OR REPLACE INTO db_version (version) VALUES (?)', (DB_VERSION,))
    conn.commit()
    conn.close()

def setup_logging(verbose=False):
    """Configure logging with multiple handlers and formats"""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Clear existing handlers
    root_logger.handlers = []
    
    # File handler for all logs
    file_handler = logging.FileHandler('greenwire-brute.log')
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root_logger.addHandler(file_handler)
    
    # Console handler with different format based on verbose mode
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(VERBOSE_FORMAT if verbose else LOG_FORMAT))
    root_logger.addHandler(console_handler)
    
    # Separate handlers for different types of data
    os.makedirs('logs', exist_ok=True)
    
    vuln_handler = logging.FileHandler('logs/vulnerabilities.log')
    vuln_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    vuln_handler.addFilter(lambda record: 'VULNERABILITY' in record.getMessage())
    root_logger.addHandler(vuln_handler)
    
    key_handler = logging.FileHandler('logs/keys.log')
    key_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    key_handler.addFilter(lambda record: 'KEY' in record.getMessage())
    root_logger.addHandler(key_handler)
    
    timing_handler = logging.FileHandler('logs/timing.log')
    timing_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    timing_handler.addFilter(lambda record: 'TIMING' in record.getMessage())
    root_logger.addHandler(timing_handler)

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

@dataclass
class TLVObject:
    """Representation of a BER-TLV data object"""
    tag: bytes
    length: int
    value: bytes
    
    @property
    def tag_str(self) -> str:
        return self.tag.hex().upper()
    
    @property
    def name(self) -> str:
        return EMV_TAGS.get(self.tag_str, 'Unknown')
    
    def __str__(self) -> str:
        return f"{self.tag_str} ({self.name}): {self.value.hex().upper()}"

class TLVParser:
    """BER-TLV parser for EMV data objects"""
    
    @staticmethod
    def parse(data: bytes) -> List[TLVObject]:
        """Parse BER-TLV encoded data into a list of TLV objects"""
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
        """Find the value of a specific tag in BER-TLV encoded data"""
        if isinstance(tag, str):
            tag = bytes.fromhex(tag)
            
        objects = TLVParser.parse(data)
        for obj in objects:
            if obj.tag == tag:
                return obj.value
        return None

class VulnerabilityDetector:
    """Enhanced vulnerability detection system"""
    
    def __init__(self, db_manager):
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

    def analyze_command(self, command_type, apdu, response, sw1, sw2, execution_time):
        """Analyze a command for potential vulnerabilities"""
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

    def _analyze_timing(self, command_type, execution_time, findings):
        """Analyze command timing for anomalies"""
        if command_type not in self.command_timing_history:
            self.command_timing_history[command_type] = []
        
        history = self.command_timing_history[command_type]
        history.append(execution_time)
        
        if len(history) > 10:  # Need enough samples for meaningful analysis
            mean = sum(history) / len(history)
            std_dev = (sum((x - mean) ** 2 for x in history) / len(history)) ** 0.5
            
            if abs(execution_time - mean) > self.anomaly_thresholds['timing_deviation'] * std_dev:
                findings.append({
                    'type': 'TIMING_ANOMALY',
                    'description': f'Unusual timing detected for {command_type}',
                    'severity': 'MEDIUM',
                    'details': {
                        'execution_time': execution_time,
                        'mean': mean,
                        'std_dev': std_dev
                    }
                })

    def _analyze_response(self, response, findings):
        """Analyze response data for potential vulnerabilities"""
        if not response:
            return
        
        # Check for potentially sensitive data patterns
        patterns = {
            'PAN': r'5[1-5][0-9]{14}',
            'CVV': r'^\d{3,4}$',
            'TRACK_DATA': r'%B\d{13,19}\^[\w\s/]{2,26}\^[0-9]{12}',
            'KEY_COMPONENT': r'[0-9A-F]{32,48}'
        }
        
        for pattern_name, pattern in patterns.items():
            if re.search(pattern, response.hex()):
                findings.append({
                    'type': 'DATA_LEAKAGE',
                    'description': f'Potential {pattern_name} data found in response',
                    'severity': 'HIGH'
                })

    def _analyze_status_words(self, sw1, sw2, findings):
        """Analyze status words for security implications"""
        sw = (sw1 << 8) | sw2
        
        if sw in self.anomaly_thresholds['suspicious_sw_codes']:
            findings.append({
                'type': 'SUSPICIOUS_STATUS',
                'description': f'Suspicious status word: {self.anomaly_thresholds["suspicious_sw_codes"][sw]}',
                'severity': 'MEDIUM' if sw != 0x6983 else 'HIGH'
            })

    def _analyze_patterns(self, command_type, apdu, response, findings):
        """Analyze command/response patterns for potential vulnerabilities"""
        if command_type not in self.response_patterns:
            self.response_patterns[command_type] = {}
        
        pattern_key = f"{apdu.hex()}:{response.hex() if response else ''}"
        if pattern_key in self.response_patterns[command_type]:
            # Identical command yields different response - potential non-deterministic behavior
            if self.response_patterns[command_type][pattern_key] != response:
                findings.append({
                    'type': 'NON_DETERMINISTIC',
                    'description': 'Non-deterministic response detected',
                    'severity': 'HIGH'
                })
        else:
            self.response_patterns[command_type][pattern_key] = response

class CardResponseAnalyzer:
    """Analyzes card responses for security vulnerabilities"""
    
    @staticmethod
    def detect_weak_random(data, min_entropy=ANALYSIS_THRESHOLDS['MIN_ENTROPY']):
        """Check if random data has sufficient entropy"""
        if not data:
            return False
            
        # Calculate Shannon entropy
        counts = Counter(data)
        entropy = 0
        for count in counts.values():
            p = count / len(data)
            entropy -= p * log2(p)
            
        return entropy >= min_entropy

    @staticmethod
    def detect_timing_leak(timings, threshold=ANALYSIS_THRESHOLDS['MIN_TIMING_DIFF']):
        """Detect potential timing side-channels"""
        if not timings or len(timings) < 2:
            return False
            
        mean = sum(timings) / len(timings)
        variance = sum((t - mean) ** 2 for t in timings) / len(timings)
        
        return variance > threshold

    @staticmethod
    def analyze_error_pattern(responses):
        """Analyze error responses for potential vulnerabilities"""
        if not responses:
            return []
            
        findings = []
        error_count = sum(1 for r in responses if r.get('sw1') != 0x90 or r.get('sw2') != 0x00)
        error_rate = error_count / len(responses)
        
        if error_rate > ANALYSIS_THRESHOLDS['MAX_ERROR_RATE']:
            findings.append({
                'type': 'HIGH_ERROR_RATE',
                'error_rate': error_rate,
                'threshold': ANALYSIS_THRESHOLDS['MAX_ERROR_RATE']
            })
            
        return findings

class DatabaseManager:
    def __init__(self):
        self.db_path = Path('greenwire.db')
        init_database()
        self.current_session_id = None

    def start_session(self, card_type, mode, fuzzing_strategy=None):
        """Start a new testing session"""
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('''
            INSERT INTO sessions (card_type, mode, fuzzing_strategy)
            VALUES (?, ?, ?)
        ''', (card_type, mode, fuzzing_strategy))
        self.current_session_id = c.lastrowid
        conn.commit()
        conn.close()
        return self.current_session_id

    def end_session(self):
        """End the current session"""
        if not self.current_session_id:
            return
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('''
            UPDATE sessions 
            SET end_time = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (self.current_session_id,))
        conn.commit()
        conn.close()

    def log_command(self, command_type, apdu, response, sw1, sw2, execution_time, is_anomaly=False):
        """Log an APDU command and its response"""
        if not self.current_session_id:
            return
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('''
            INSERT INTO commands 
            (session_id, command_type, apdu, response, sw1, sw2, execution_time, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (self.current_session_id, command_type, apdu, response, sw1, sw2, execution_time, is_anomaly))
        conn.commit()
        conn.close()

    def log_vulnerability(self, vuln_type, description, severity, apdu, response):
        """Log a discovered vulnerability"""
        if not self.current_session_id:
            return
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('''
            INSERT INTO vulnerabilities 
            (session_id, vulnerability_type, description, severity, apdu, response)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (self.current_session_id, vuln_type, description, severity, apdu, response))
        conn.commit()
        conn.close()

    def log_key(self, key_type, key_data, metadata):
        """Log discovered keys or certificates"""
        if not self.current_session_id:
            return
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('''
            INSERT INTO keys 
            (session_id, key_type, key_data, metadata)
            VALUES (?, ?, ?, ?)
        ''', (self.current_session_id, key_type, key_data, metadata))
        conn.commit()
        conn.close()

    def log_timing(self, command_type, execution_time, statistics, anomaly_score):
        """Log timing analysis data"""
        if not self.current_session_id:
            return
        conn = sqlite3.connect(str(self.db_path))
        c = conn.cursor()
        c.execute('''
            INSERT INTO timing_analysis 
            (session_id, command_type, execution_time, statistics, anomaly_score)
            VALUES (?, ?, ?, ?, ?)
        ''', (self.current_session_id, command_type, execution_time, statistics, anomaly_score))
        conn.commit()
        conn.close()

# Enhanced logging system with human-readable output
class LogManager:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.setup_logging()
        
        # Translation dictionaries for human-readable output
        self.command_descriptions = {
            'SELECT': 'Select card application/file',
            'READ_RECORD': 'Read card data record',
            'GET_PROCESSING_OPTIONS': 'Initialize transaction processing',
            'INTERNAL_AUTHENTICATE': 'Perform card authentication',
            'GENERATE_AC': 'Generate application cryptogram',
            'PIN_VERIFY': 'Verify PIN',
            'GET_CHALLENGE': 'Request random challenge',
            'GET_DATA': 'Read card data object'
        }
        
        self.status_descriptions = {
            0x9000: 'Success',
            0x6200: 'Warning: State of non-volatile memory unchanged',
            0x6281: 'Warning: Part of returned data may be corrupted',
            0x6282: 'Warning: End of file/record reached before reading expected number of bytes',
            0x6283: 'Warning: Selected file invalidated',
            0x6284: 'Warning: FCI format not supported',
            0x6300: 'Warning: State of non-volatile memory changed',
            0x6381: 'Warning: File filled up by last write',
            0x6700: 'Error: Wrong length',
            0x6800: 'Error: Functions in CLA not supported',
            0x6881: 'Error: Logical channel not supported',
            0x6882: 'Error: Secure messaging not supported',
            0x6900: 'Error: Command not allowed',
            0x6981: 'Error: Command incompatible with file structure',
            0x6982: 'Error: Security status not satisfied',
            0x6983: 'Error: Authentication method blocked',
            0x6984: 'Error: Reference data invalidated',
            0x6985: 'Error: Conditions of use not satisfied',
            0x6986: 'Error: Command not allowed (no current EF)',
            0x6987: 'Error: Expected secure messaging data objects missing',
            0x6988: 'Error: Secure messaging data objects incorrect'
        }

    def setup_logging(self):
        """Configure logging handlers and formats"""
        # Create logs directory if it doesn't exist
        Path('logs').mkdir(exist_ok=True)
        
        # Root logger configuration
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        # Clear existing handlers
        root_logger.handlers = []
        
        # Main log file
        main_handler = logging.FileHandler('logs/greenwire-brute.log')
        main_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root_logger.addHandler(main_handler)
        
        # Vulnerability log
        vuln_handler = logging.FileHandler('logs/vulnerabilities.log')
        vuln_handler.setFormatter(logging.Formatter(VERBOSE_FORMAT))
        vuln_handler.addFilter(lambda record: 'VULNERABILITY' in record.msg)
        root_logger.addHandler(vuln_handler)
        
        # Key discovery log
        key_handler = logging.FileHandler('logs/keys.log')
        key_handler.setFormatter(logging.Formatter(VERBOSE_FORMAT))
        key_handler.addFilter(lambda record: 'KEY_DISCOVERY' in record.msg)
        root_logger.addHandler(key_handler)
        
        # Timing analysis log
        timing_handler = logging.FileHandler('logs/timing.log')
        timing_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        timing_handler.addFilter(lambda record: 'TIMING' in record.msg)
        root_logger.addHandler(timing_handler)
        
        # Console output
        console_handler = logging.StreamHandler(sys.stdout)
        if self.verbose:
            console_handler.setFormatter(logging.Formatter(VERBOSE_FORMAT))
        else:
            console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root_logger.addHandler(console_handler)

    def log_command(self, command_type, apdu, response, sw1, sw2, execution_time):
        """Log a command with human-readable description"""
        sw = (sw1 << 8) | sw2
        status_desc = self.status_descriptions.get(sw, f'Unknown status {hex(sw)}')
        cmd_desc = self.command_descriptions.get(command_type, command_type)
        
        message = f"""
Command: {cmd_desc}
APDU: {apdu.hex()}
Response: {response.hex() if response else 'None'}
Status: {status_desc} ({hex(sw)})
Time: {execution_time:.4f}s
"""
        
        logging.info(message)
        
        # Log detailed timing information
        if execution_time > 1.0:  # Suspicious timing threshold
            logging.warning(f'TIMING: Slow response ({execution_time:.4f}s) for {cmd_desc}')

    def log_vulnerability(self, finding):
        """Log a vulnerability finding with detailed explanation"""
        severity_markers = {
            'LOW': '!',
            'MEDIUM': '!!',
            'HIGH': '!!!'
        }
        
        message = f"""
VULNERABILITY DETECTED {severity_markers.get(finding['severity'], '!')}
Type: {finding['type']}
Description: {finding['description']}
Severity: {finding['severity']}
Details: {json.dumps(finding.get('details', {}), indent=2)}
Recommendation: {self._get_vulnerability_recommendation(finding['type'])}
"""
        
        logging.warning(message)

    def log_key_discovery(self, key_type, metadata):
        """Log discovered keys or certificates"""
        message = f"""
KEY DISCOVERY
Type: {key_type}
Metadata: {json.dumps(metadata, indent=2)}
Time: {datetime.now().isoformat()}
"""
        
        logging.info(message)

    def _get_vulnerability_recommendation(self, vuln_type):
        """Get recommendation for handling a vulnerability type"""
        recommendations = {
            'TIMING_ANOMALY': 'Review command implementation for timing side-channels',
            'DATA_LEAKAGE': 'Implement secure data handling and encryption',
            'SUSPICIOUS_STATUS': 'Review access control and authentication mechanisms',
            'NON_DETERMINISTIC': 'Investigate potential race conditions or state inconsistencies'
        }
        return recommendations.get(vuln_type, 'Further investigation required')

class SmartcardFuzzer:
    def __init__(self, options):
        self.options = options
        self.dry_run = options.get('dry_run', False)
        self.verbose = options.get('verbose', False)
        self.vulnerabilities = []
        self.current_session = None
        self._init_logging()

    def _init_logging(self):
        """Initialize logging configuration"""
        if self.verbose:
            logging.basicConfig(level=logging.DEBUG, format=VERBOSE_FORMAT)
        else:
            logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

    def _correlate_vulnerabilities(self, scenario_name, results):
        """Analyze and correlate vulnerabilities from attack results"""
        if results.get('success'):
            # Record successful attack steps
            vuln = {
                'scenario': scenario_name,
                'timestamp': datetime.now().isoformat(),
                'type': ATTACK_SCENARIOS[scenario_name]['name'],
                'standard': ATTACK_SCENARIOS[scenario_name]['standard'],
                'section': ATTACK_SCENARIOS[scenario_name]['section'],
                'steps': results['steps']
            }
            
            self.vulnerabilities.append(vuln)
            
            # Analyze for related vulnerabilities
            if scenario_name == 'SDA_DOWNGRADE':
                # SDA downgrade might indicate weak key management
                self.vulnerabilities.append({
                    'scenario': 'KEY_MANAGEMENT',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'Related Key Management Weakness',
                    'standard': 'EMV_BOOK2',
                    'section': '6.3'
                })
            
            elif scenario_name == 'PIN_BYPASS':
                # PIN bypass might indicate CVM processing issues
                self.vulnerabilities.append({
                    'scenario': 'CVM_PROCESSING',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'Related CVM Processing Weakness',
                    'standard': 'EMV_BOOK3',
                    'section': '10.5'
                })

    def simulate_attack_scenario(self, scenario_name):
        """Simulate an attack scenario and return results"""
        if scenario_name not in ATTACK_SCENARIOS:
            raise ValueError(f"Unknown attack scenario: {scenario_name}")

        scenario = ATTACK_SCENARIOS[scenario_name]
        logging.info(f"Simulating {scenario['name']} attack scenario")
        
        if self.dry_run:
            # For dry runs, simulate successful attacks and correlate vulnerabilities
            results = {
                'success': True,
                'steps': [{'step': step, 'status': 'simulated'} for step in scenario['steps']]
            }
            self._correlate_vulnerabilities(scenario_name, results)
            return results

        results = {
            'success': False,
            'steps': []
        }

        try:
            for step in scenario['steps']:
                step_result = self._execute_attack_step(scenario_name, step)
                results['steps'].append(step_result)
                if not step_result.get('success', False):
                    break
            
            results['success'] = all(step.get('success', False) for step in results['steps'])
            if results['success']:
                self._correlate_vulnerabilities(scenario_name, results)
            
        except Exception as e:
            logging.error(f"Error in attack scenario {scenario_name}: {str(e)}")
            results['error'] = str(e)

        return results

    def check_standard_compliance(self, standard_name, section=None):
        """Check compliance with EMV standard requirements"""
        if standard_name not in EMV_STANDARDS:
            raise ValueError(f"Unknown EMV standard: {standard_name}")
        
        standard = EMV_STANDARDS[standard_name]
        results = {
            'standard': standard_name,
            'version': standard['version'],
            'sections': {}
        }

        if section and section not in standard['sections']:
            raise ValueError(f"Unknown section {section} in standard {standard_name}")

        sections_to_check = [section] if section else standard['sections'].keys()

        for sec in sections_to_check:
            results['sections'][sec] = self._check_section_compliance(standard_name, sec)

        return results

    def _execute_attack_step(self, scenario_name, step):
        """Execute a single step in an attack scenario."""
        if self.dry_run:
            return {'step': step, 'status': 'simulated', 'success': True}

        # This would contain actual smartcard communication logic
        return {
            'step': step,
            'status': 'completed',
            'success': True,
            'timestamp': datetime.now().isoformat(),
        }

    def _check_section_compliance(self, standard_name, section):
        """Check compliance with a specific section of an EMV standard."""
        if self.dry_run:
            return {
                'compliant': True,
                'details': 'Dry run - no actual check performed',
            }

        # This would contain actual compliance checking logic
        return {
            'compliant': True,
            'details': f'Compliance check simulated for {standard_name} section {section}',
            'timestamp': datetime.now().isoformat(),
        }

    def fuzz_contactless(
        self,
        aids: List[str],
        iterations: int = 1,
        ca_file: str | None = None,
    ) -> List[dict]:
        """Perform simple contactless EMV fuzzing using ``nfcpy``."""

        ca_dict = load_ca_keys(ca_file) if ca_file else DEFAULT_CA_KEYS
        ca_keys = {k: CAPublicKey(**v) for k, v in ca_dict.items()}
        terminal = ContactlessEMVTerminal(aids, ca_keys)

        results: List[dict] = []
        for _ in range(iterations):
            results.extend(terminal.run())

        return results

    def fuzz_applet_emulation(self, emulator, aid: str, iterations: int = 1) -> List[dict]:
        """Fuzz an AID using a card emulator by issuing random APDUs."""
        aid_bytes = bytes.fromhex(aid)
        results: List[dict] = []
        for _ in range(iterations):
            select_resp = emulator.send_apdu(0x00, 0xA4, 0x04, 0x00, aid_bytes)
            p1 = random.randint(0, 255)
            p2 = random.randint(0, 255)
            fuzz_resp = emulator.send_apdu(0x00, 0xB0, p1, p2, b"")
            results.append({"aid": aid, "select": bytes(select_resp), "fuzz_resp": bytes(fuzz_resp)})
        return results
