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

# Database Schema Version
DB_VERSION = 1

# Analysis thresholds must be defined before any use
ANALYSIS_THRESHOLDS = {
    'MIN_ENTROPY': 3.5,
    'RESPONSE_TIME_THRESHOLD': 1.0
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
    """Helper class for analyzing card responses"""
    
    @staticmethod
    def analyze_timing(start_time, end_time, command_type):
        """Analyze response timing for potential side-channel vulnerabilities"""
        response_time = end_time - start_time
        timing_info = {
            'command': command_type,
            'response_time': response_time,
            'timestamp': datetime.now().isoformat(),
            'anomaly': response_time > ANALYSIS_THRESHOLDS['RESPONSE_TIME_THRESHOLD']
        }
        return timing_info
    
    @staticmethod
    def analyze_response_pattern(data):
        """Analyze response data for patterns and anomalies"""
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
    def detect_weak_random(data, min_entropy=ANALYSIS_THRESHOLDS['MIN_ENTROPY']):
        """Detect potentially weak random number generation"""
        if not data:
            return False
            
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
    def calculate_entropy(data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        counts = Counter(data)
        probs = [float(c)/len(data) for c in counts.values()]
        return -sum(p * log2(p) for p in probs)

    @staticmethod
    def find_repeating_sequences(data, min_length=3):
        """Find repeating sequences in data"""
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
    def check_linear_relationship(data, window=8):
        """Check for linear relationships in data"""
        if len(data) < window:
            return False
            
        differences = []
        for i in range(len(data)-1):
            differences.append((data[i+1] - data[i]) % 256)
            
        # Check if differences are constant
        return len(set(differences[:window])) == 1

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
    def __init__(self, args):
        self.args = args
        self.connection = None
        self.reader = None
        self.pattern_data = []
        self.selected_aid = None
        self.current_application = None
        self.detected_keys = {}
        self.timing_data = []
        self.response_patterns = []
        self.vulnerabilities = []
        self.analyzer = CardResponseAnalyzer()
        self.stats = {
            'commands_sent': 0,
            'successful_responses': 0,
            'errors': 0,
            'timing_anomalies': 0
        }
        self.load_patterns()
        self.db_manager = DatabaseManager()

    def connect(self):
        """Establish connection to the first available reader"""
        if self.args.dry_run:
            logging.info("[DRY RUN] Would connect to card reader")
            return True
            
        r = readers()
        if not r:
            logging.error("No smartcard readers found")
            return False
            
        self.reader = r[0]
        try:
            self.connection = self.reader.createConnection()
            self.connection.connect()
            logging.info(f"Connected to {self.reader}")
            return True
        except Exception as e:
            logging.error(f"Failed to connect: {e}")
            return False

    def transmit(self, apdu, description=""):
        """Send APDU to card and handle retries"""
        if self.args.dry_run:
            logging.info(f"[DRY RUN] Would send APDU: {toHexString(apdu)}")
            return ([0x90, 0x00], None)

        retries = 0
        while retries < self.args.retries:
            try:
                response, sw1, sw2 = self.connection.transmit(apdu)
                self.stats['commands_sent'] += 1
                if sw1 == 0x90 and sw2 == 0x00:
                    self.stats['successful_responses'] += 1
                return [sw1, sw2], response
            except Exception as e:
                logging.warning(f"Command failed ({description}): {e}")
                retries += 1
                self.stats['errors'] += 1
                time.sleep(0.1 * retries)  # Increasing delay between retries
        
        return None

    def transmit_with_timing(self, apdu, description=""):
        """Send APDU and measure response time"""
        start_time = time.time()
        result = self.transmit(apdu, description)
        end_time = time.time()
        
        if result:
            sw, resp = result
            timing_info = self.analyzer.analyze_timing(start_time, end_time, description)
            self.timing_data.append(timing_info)
            
            if timing_info['anomaly']:
                self.stats['timing_anomalies'] += 1
                logging.warning(f"Timing anomaly detected in {description}")
                
        return result

    def fuzz_read_record(self):
        """Fuzz READ RECORD command with various SFI/record combinations"""
        for sfi in range(1, 31):
            for record in range(1, 10):
                apdu = [0x00, 0xB2, record, (sfi << 3) | 4, 0x00]
                sw, resp = self.transmit(apdu, f"READ RECORD SFI={sfi} REC={record}")
                if sw and sw[0] == 0x90 and sw[1] == 0x00:
                    self.analyze_response(resp)

    def analyze_response(self, response, command_name=""):
        """Analyze card response for patterns and EMV tags"""
        if not response:
            return
            
        hex_resp = toHexString(response)
        for tag, desc in EMV_TAGS.items():
            if tag in hex_resp:
                logging.info(f"Found {desc} ({tag}) in response")
                self.pattern_data.append({
                    'tag': tag,
                    'description': desc,
                    'data': hex_resp,
                    'timestamp': datetime.now().isoformat()
                })
        
        # Analyze response patterns
        pattern_info = self.analyzer.analyze_response_pattern(response)
        if pattern_info:
            self.response_patterns.append({
                'command': command_name,
                'patterns': pattern_info,
                'timestamp': datetime.now().isoformat()
            })

    def select_application(self, aid):
        """Select EMV application using its AID"""
        aid_bytes = toBytes(aid)
        apdu = EMV_COMMANDS['SELECT'] + [len(aid_bytes)] + aid_bytes
        sw, resp = self.transmit(apdu, f"SELECT AID {aid}")
        if sw and sw[0] == 0x90 and sw[1] == 0x00:
            self.selected_aid = aid
            self.current_application = resp
            return True
        return False

    def get_processing_options(self):
        """Perform GET PROCESSING OPTIONS command"""
        pdol = [0x83, 0x00]  # Empty PDOL
        apdu = EMV_COMMANDS['GET_PROCESSING_OPTIONS'] + [len(pdol)] + pdol + [0x00]
        return self.transmit(apdu, "GET PROCESSING OPTIONS")

    def internal_authenticate(self, challenge=None):
        """Perform INTERNAL AUTHENTICATE with optional challenge"""
        if not challenge:
            challenge = [random.randint(0, 255) for _ in range(8)]
        apdu = EMV_COMMANDS['INTERNAL_AUTHENTICATE'] + [len(challenge)] + challenge
        return self.transmit(apdu, "INTERNAL AUTHENTICATE")

    def get_challenge(self):
        """Request a challenge from the card"""
        apdu = EMV_COMMANDS['GET_CHALLENGE']
        return self.transmit(apdu, "GET CHALLENGE")

    def verify_pin(self, pin="0000"):
        """Attempt PIN verification"""
        if self.args.dry_run:
            return ([0x63, 0xC3], None)  # Simulate PIN retry counter
        pin_data = list(bytes.fromhex(pin.ljust(16, 'F')))
        apdu = EMV_COMMANDS['VERIFY'] + [len(pin_data)] + pin_data
        return self.transmit(apdu, "VERIFY PIN")

    def fuzz_with_entropy(self):
        """Fuzz commands that generate dynamic responses"""
        for _ in range(10):  # Try multiple times
            # Get challenge and analyze entropy
            sw, resp = self.get_challenge()
            if sw and sw[0] == 0x90 and sw[1] == 0x00:
                self.analyze_entropy(resp)
                
            # Try internal authenticate with random challenges
            challenge = [random.randint(0, 255) for _ in range(8)]
            sw, resp = self.internal_authenticate(challenge)
            if sw and sw[0] == 0x90 and sw[1] == 0x00:
                self.analyze_entropy(resp)

    def fuzz_key_detection(self):
        """Attempt to detect and analyze encryption keys"""
        # Try to read common key-related tags
        for key_type, tags in KEY_TYPES.items():
            for tag in tags:
                apdu = EMV_COMMANDS['GET_DATA'] + toBytes(tag) + [0x00]
                sw, resp = self.transmit(apdu, f"GET DATA for {key_type} key ({tag})")
                if sw and sw[0] == 0x90 and sw[1] == 0x00:
                    self.analyze_key_data(key_type, tag, resp)

    def fuzz_os_commands(self):
        """Test card operating system commands"""
        for os_type, config in CARD_OS_TYPES.items():
            logging.info(f"Testing {os_type} commands...")
            
            # Try selecting applications
            for aid in config['aids']:
                if self.select_application(aid):
                    logging.info(f"Found {os_type} application: {aid}")
                    
                    # Test OS-specific commands
                    for cmd_name, cmd_apdu in config['instructions'].items():
                        self.fuzz_command(cmd_name, cmd_apdu)
                        
                    # Test with buffer overflow patterns
                    self.test_buffer_overflow(config['instructions'])
                    
                    # Test with timing analysis
                    self.test_timing_attacks(config['instructions'])

    def fuzz_command(self, cmd_name, base_apdu, iterations=50):
        """Fuzz a specific command with various parameters"""
        for i in range(iterations):
            # Vary the parameters
            fuzzed_apdu = base_apdu.copy()
            if len(fuzzed_apdu) >= 4:
                # Modify P1/P2 parameters
                fuzzed_apdu[2] = random.randint(0, 255)
                fuzzed_apdu[3] = random.randint(0, 255)
            
            # Add random data
            data_length = random.randint(0, 255)
            fuzzed_apdu.extend([random.randint(0, 255) for _ in range(data_length)])
            
            # Send command and analyze response
            sw, resp = self.transmit_with_timing(fuzzed_apdu, f"FUZZ_{cmd_name}_{i}")
            if sw:
                self.analyze_response(resp, cmd_name)
                self.check_for_vulnerabilities(sw, resp, cmd_name)

    def test_buffer_overflow(self, instructions):
        """Test for buffer overflow vulnerabilities"""
        for pattern in FUZZ_PATTERNS['BUFFER_OVERFLOW']:
            for cmd_name, base_apdu in instructions.items():
                test_apdu = base_apdu + [len(pattern)] + pattern
                sw, resp = self.transmit(test_apdu, f"BUFFER_OVERFLOW_{cmd_name}")
                
                if sw and sw[0] != 0x6A and sw[0] != 0x67:  # Unexpected response
                    self.vulnerabilities.append({
                        'type': 'BUFFER_OVERFLOW',
                        'command': cmd_name,
                        'pattern_length': len(pattern),
                        'response': {'sw1': sw[0], 'sw2': sw[1]},
                        'timestamp': datetime.now().isoformat()
                    })

    def test_timing_attacks(self, instructions):
        """Test for timing attack vulnerabilities"""
        for pattern in FUZZ_PATTERNS['TIMING_ATTACK']:
            for cmd_name, base_apdu in instructions.items():
                timings = []
                for _ in range(10):  # Multiple attempts for statistical significance
                    test_apdu = base_apdu + [len(pattern)] + pattern
                    start_time = time.time()
                    self.transmit(test_apdu, f"TIMING_{cmd_name}")
                    end_time = time.time()
                    timings.append(end_time - start_time)
                
                # Analyze timing variations
                if timings:
                    avg_time = sum(timings) / len(timings)
                    max_variation = max(timings) - min(timings)
                    if max_variation > ANALYSIS_THRESHOLDS['RESPONSE_TIME_THRESHOLD']:
                        self.vulnerabilities.append({
                            'type': 'TIMING_VARIATION',
                            'command': cmd_name,
                            'average_time': avg_time,
                            'variation': max_variation,
                            'timestamp': datetime.now().isoformat()
                        })

    def analyze_key_data(self, key_type, tag, data):
        """Enhanced key data analysis"""
        if not data:
            return
            
        key_info = {
            'type': key_type,
            'tag': tag,
            'length': len(data),
            'data': toHexString(data),
            'timestamp': datetime.now().isoformat(),
            'analysis': {}
        }
        
        # Basic key analysis
        if key_type == 'RSA':
            self.analyze_rsa_key(data, key_info)
        elif key_type in ['DES', 'AES']:
            self.analyze_symmetric_key(data, key_info)
        elif key_type == 'ECC':
            self.analyze_ecc_key(data, key_info)
            
        # Advanced analysis
        key_info['analysis'].update({
            'entropy': self.analyzer.calculate_entropy(data),
            'weak_random': self.analyzer.detect_weak_random(data),
            'patterns': self.analyzer.analyze_response_pattern(data)
        })
        
        self.detected_keys[tag] = key_info
        logging.info(f"Analyzed {key_type} key material in tag {tag}")
        self.pattern_data.append(key_info)

    def analyze_ecc_key(self, data, key_info):
        """Analyze ECC key components"""
        key_info['analysis']['ecc'] = {
            'potential_curve': None,
            'key_size': len(data) * 8,
            'structure_valid': False
        }
        
        # Check for known ECC patterns
        for curve in CRYPTO_CONSTANTS['ECC_CURVES']:
            if len(data) in [32, 48, 66]:  # Common ECC key sizes
                key_info['analysis']['ecc'].update({
                    'potential_curve': curve,
                    'structure_valid': True
                })

    def save_detailed_report(self):
        """Save a detailed analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'detected_keys': self.detected_keys,
            'vulnerabilities': self.vulnerabilities,
            'timing_analysis': self.timing_data,
            'response_patterns': self.response_patterns
        }
        
        # Save JSON report
        with open(self.args.output, 'w') as f:
            json.dump(report, f, indent=2)
            
        # Save CSV timing data
        with open(self.args.timing_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['command', 'response_time', 'timestamp', 'anomaly'])
            writer.writeheader()
            writer.writerows(self.timing_data)

    def run(self):
        """Enhanced main fuzzing routine"""
        if not self.connect():
            return False

        # Start a new database session
        self.db_manager.start_session(self.args.mode, self.args.card_type, self.args.provider)

        try:
            if self.args.mode == 'readfuzz':
                self.fuzz_read_record()
            elif self.args.mode == 'entropy':
                self.fuzz_with_entropy()
            elif self.args.mode == 'keys':
                self.fuzz_key_detection()
            elif self.args.mode == 'os':
                self.fuzz_os_commands()
            elif self.args.mode == 'timing':
                self.test_timing_attacks(EMV_COMMANDS)
            elif self.args.mode == 'full':
                with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                    futures = []
                    futures.append(executor.submit(self.fuzz_all_aids))
                    futures.append(executor.submit(self.fuzz_os_commands))
                    futures.append(executor.submit(self.fuzz_key_detection))
                    
                    for future in futures:
                        future.result()  # Wait for all tests to complete

            self.save_detailed_report()
            return True
            
        except Exception as e:
            logging.error(f"Error during fuzzing: {e}")
            return False

    def simulate_signature_transaction(self):
        """Simulate a signature-based transaction with timing analysis"""
        timing_results = []
        start_total = time.time()

        # SELECT with timing
        aid = random.choice(EMV_AIDS['VISA'] + EMV_AIDS['MASTERCARD'])
        timing_results.append(self.timed_command('SELECT', 
            EMV_COMMANDS['SELECT'] + [len(aid)] + bytes.fromhex(aid)))

        # GET PROCESSING OPTIONS with timing
        gpo_data = bytes([0x83, 0x00])  # Empty PDOL data
        timing_results.append(self.timed_command('GET_PROCESSING_OPTIONS',
            EMV_COMMANDS['GET_PROCESSING_OPTIONS'] + [len(gpo_data)] + list(gpo_data)))

        # READ RECORD for important records
        for sfi in range(1, 4):
            for record in range(1, 4):
                timing_results.append(self.timed_command('READ_RECORD',
                    EMV_COMMANDS['READ_RECORD'] + [sfi << 3 | record, 0x00]))

        # INTERNAL AUTHENTICATE with random challenge
        challenge = os.urandom(8)
        timing_results.append(self.timed_command('INTERNAL_AUTHENTICATE',
            EMV_COMMANDS['INTERNAL_AUTHENTICATE'] + [len(challenge)] + list(challenge)))

        # GENERATE AC (signature equivalent)
        cdol1_data = self.build_cdol1_data()
        timing_results.append(self.timed_command('GENERATE_AC',
            EMV_COMMANDS['GENERATE_AC'] + [0x40, len(cdol1_data)] + list(cdol1_data)))

        total_time = time.time() - start_total
        
        # Log timing data
        self.db_manager.log_timing('FULL_TRANSACTION', total_time, 
            json.dumps({cmd: time for cmd, time in timing_results}),
            self.calculate_timing_anomaly_score(timing_results))

        return timing_results, total_time

    def timed_command(self, command_type, apdu):
        """Execute a command with precise timing measurement"""
        start = time.time()
        result = self.transmit(apdu, command_type)
        end = time.time()
        duration = end - start
        
        # Log the command
        if result:
            sw, resp = result
            self.db_manager.log_command(command_type, bytes(apdu), resp, sw[0], sw[1], duration)
        
        return command_type, duration

    def build_cdol1_data(self):
        """Build CDOL1 data for GENERATE AC command"""
        # Standard CDOL1 fields for signature transaction
        amount = bytes.fromhex('000000001000')  # Amount: 10.00
        term_country = bytes.fromhex('0840')    # USA
        tvr = bytes.fromhex('0000000000')       # All checks passed
        currency = bytes.fromhex('0840')        # USD
        date = datetime.now().strftime('%y%m%d').encode('ascii')
        type = bytes([0x00])                    # Purchase
        un = os.urandom(4)                      # Unpredictable number
        
        return amount + term_country + tvr + currency + date + type + un

    def calculate_timing_anomaly_score(self, timing_results):
        """Calculate anomaly score for transaction timing"""
        if not timing_results:
            return 0.0
            
        # Calculate mean and std dev
        times = [t for _, t in timing_results]
        mean = sum(times) / len(times)
        variance = sum((t - mean) ** 2 for t in times) / len(times)
        std_dev = variance ** 0.5
        
        # Score based on deviation from expected timing
        score = 0.0
        expected_timings = {
            'SELECT': 0.1,
            'GET_PROCESSING_OPTIONS': 0.15,
            'READ_RECORD': 0.05,
            'INTERNAL_AUTHENTICATE': 0.2,
            'GENERATE_AC': 0.25
        }
        
        for cmd, time in timing_results:
            expected = expected_timings.get(cmd, 0.1)
            if abs(time - expected) > 2 * std_dev:
                score += 1.0
            elif abs(time - expected) > std_dev:
                score += 0.5
                
        return score

    def speed_optimized_fuzzing(self, num_iterations=100):
        """Perform speed-optimized fuzzing after signature simulation"""
        fuzzing_patterns = [
            self._fuzz_select,
            self._fuzz_read_record,
            self._fuzz_processing_options,
            self._fuzz_authentication
        ]
        
        results = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for _ in range(num_iterations):
                pattern = random.choice(fuzzing_patterns)
                futures.append(executor.submit(pattern))
            
            for future in futures:
                try:
                    result = future.result(timeout=2.0)  # 2-second timeout
                    if result:
                        results.append(result)
                except Exception as e:
                    logging.error(f"Fuzzing error: {e}")
                    
        return results

    def _fuzz_select(self):
        """Fuzz SELECT command with various mutations"""
        aid = random.choice(list(EMV_AIDS.values()))[0]
        mutations = [
            bytes.fromhex(aid[:-2] + '00'),  # Truncated AID
            bytes.fromhex(aid) + b'\x00',    # Extended AID
            bytes.fromhex(aid[:8] + ''.join(random.choices('0123456789ABCDEF', k=6))),  # Mutated AID
        ]
        
        for mutated_aid in mutations:
            apdu = EMV_COMMANDS['SELECT'] + [len(mutated_aid)] + list(mutated_aid)
            result = self.transmit_with_timing(apdu, 'SELECT_FUZZ')
            if result and result[0] != [0x90, 0x00]:
                self.analyze_response(result[1], 'SELECT_FUZZ')

    def _fuzz_read_record(self):
        """Fuzz READ RECORD command with boundary testing"""
        # Test boundary conditions and invalid combinations
        test_cases = [
            (0xFF, 0x00),  # Invalid SFI
            (0x01, 0xFF),  # Invalid record
            (0x00, 0x00),  # Zero values
            (0x1F, 0x0A),  # Maximum valid SFI
        ]
        
        for sfi, record in test_cases:
            apdu = EMV_COMMANDS['READ_RECORD'] + [sfi << 3 | record, 0x00]
            result = self.transmit_with_timing(apdu, 'READ_RECORD_FUZZ')
            if result:
                self.analyze_response(result[1], 'READ_RECORD_FUZZ')

    def _fuzz_processing_options(self):
        """Fuzz GET PROCESSING OPTIONS with malformed PDOL data"""
        test_cases = [
            bytes([0x83, 0x00]),  # Empty PDOL
            bytes([0x83, 0x01, 0x00]),  # Invalid length
            os.urandom(8),  # Random data
            bytes([0x83, 0x04]) + bytes.fromhex('FFFFFFFF'),  # Maximum values
        ]
        
        for pdol_data in test_cases:
            apdu = EMV_COMMANDS['GET_PROCESSING_OPTIONS'] + [len(pdol_data)] + list(pdol_data)
            result = self.transmit_with_timing(apdu, 'GPO_FUZZ')
            if result:
                self.analyze_response(result[1], 'GPO_FUZZ')

    def _fuzz_authentication(self):
        """Fuzz authentication commands with various test cases"""
        # Test cases for INTERNAL AUTHENTICATE
        auth_tests = [
            bytes([0x00] * 8),  # Zero challenge
            bytes([0xFF] * 8),  # All ones
            os.urandom(8),      # Random challenge
            os.urandom(4),      # Short challenge
            os.urandom(16),     # Long challenge
        ]
        
        for challenge in auth_tests:
            apdu = EMV_COMMANDS['INTERNAL_AUTHENTICATE'] + [len(challenge)] + list(challenge)
            result = self.transmit_with_timing(apdu, 'AUTH_FUZZ')
            if result:
                self.analyze_response(result[1], 'AUTH_FUZZ')

    def standard_test(self):
        """Perform standard EMV testing sequence with comprehensive diagnostics"""
        logging.info("Starting standard EMV test sequence")
        results = {'success': 0, 'failed': 0, 'vulnerabilities': []}

        try:
            # Test EMV AIDs
            for card_type, aids in EMV_AIDS.items():
                logging.info(f"Testing {card_type} applications")
                for aid in aids:
                    if self.select_application(aid):
                        logging.info(f"Successfully selected {card_type} AID: {aid}")
                        results['success'] += 1
                        
                        # Get Processing Options
                        sw, resp = self.get_processing_options()
                        if sw and sw[0] == 0x90 and sw[1] == 0x00:
                            tlv_data = TLVParser.parse(resp)
                            # Analyze AIP and AFL if present
                            for tlv in tlv_data:
                                if tlv.tag_str in ['82', '94']:
                                    self.analyze_response(tlv.value, f"GPO_{tlv.tag_str}")
                        
                        # Basic Record Reading
                        for sfi in range(1, 31):
                            for record in range(1, 4):  # First few records
                                sw, resp = self.transmit([0x00, 0xB2, record, (sfi << 3) | 4, 0x00],
                                                       f"READ_RECORD SFI={sfi} REC={record}")
                                if sw and sw[0] == 0x90 and sw[1] == 0x00:
                                    self.analyze_response(resp, f"READ_RECORD_{sfi}_{record}")
                                
                        # Test GET CHALLENGE and INTERNAL AUTHENTICATE
                        challenge_sw, challenge = self.get_challenge()
                        if challenge_sw and challenge_sw[0] == 0x90 and challenge_sw[1] == 0x00:
                            auth_sw, auth_resp = self.internal_authenticate(challenge)
                            if auth_resp:
                                self.analyze_response(auth_resp, "INTERNAL_AUTH")
                    else:
                        results['failed'] += 1
                        
            # Test basic commands from different card OS types
            for os_type, commands in CARD_OS_COMMANDS.items():
                for cmd_name, cmd in commands.items():
                    sw, resp = self.transmit([cmd['cla'], cmd['ins'], cmd['p1'], cmd['p2'], 0x00],
                                          f"{os_type}_{cmd_name}")
                    if sw:
                        self.analyze_response(resp, f"{os_type}_{cmd_name}")
                        
            # Cryptographic testing
            crypto_results = self.test_cryptographic_operations()
            results.update({'crypto_tests': crypto_results})
            
            # Protocol compliance testing
            compliance_results = self.test_protocol_compliance()
            results.update({'compliance_tests': compliance_results})
            
        except Exception as e:
            logging.error(f"Error during standard test: {e}")
            results['failed'] += 1
            
        return results

    def test_all_commands(self):
        """Test all supported commands for all card types"""
        results = {}
        
        # Test EMV commands
        for name, command in EMV_COMMANDS.items():
            results[f'EMV_{name}'] = self._test_command(name, command)
            
        # Test JavaCard commands
        for name, cmd in CARD_OS_COMMANDS['JAVACARD'].items():
            apdu = [cmd['cla'], cmd['ins'], cmd['p1'], cmd['p2']]
            results[f'JAVACARD_{name}'] = self._test_command(name, apdu)
            
        # Test MULTOS commands
        for name, cmd in CARD_OS_COMMANDS['MULTOS'].items():
            apdu = [cmd['cla'], cmd['ins'], cmd['p1'], cmd['p2']]
            results[f'MULTOS_{name}'] = self._test_command(name, apdu)
            
        return results

    def _test_command(self, name, command):
        """Test a single command with various parameters"""
        results = []
        
        # Test with different lengths
        for length in [0, 1, 255]:
            apdu = command + [length] + [0] * length
            result = self.transmit_with_timing(apdu, f"{name}_LENGTH_{length}")
            results.append((length, result))
            
        # Test with different P1/P2 values
        test_params = [(0x00, 0x00), (0xFF, 0xFF), (0x80, 0x80)]
        for p1, p2 in test_params:
            modified_cmd = command[:]
            if len(modified_cmd) >= 4:
                modified_cmd[2:4] = [p1, p2]
                result = self.transmit_with_timing(modified_cmd, f"{name}_P1P2_{p1:02X}{p2:02X}")
                results.append((f"P1P2_{p1:02X}{p2:02X}", result))
                
        return results

    def test_cryptographic_operations(self):
        """Test cryptographic operations and random number generation"""
        results = []
        
        # Test GET_CHALLENGE with different lengths
        for length in [4, 8, 16, 32]:
            apdu = EMV_COMMANDS['GET_CHALLENGE'] + [length]
            result = self.transmit_with_timing(apdu, f"GET_CHALLENGE_{length}")
            if result and result[1]:
                analysis = self.analyzer.detect_weak_random(result[1])
                if analysis['entropy_low'] or analysis['has_linear_relationship']:
                    self.vulnerabilities.append({
                        'type': 'WEAK_RANDOM',
                        'description': f'Potential weak random number generation detected (length {length})',
                        'details': analysis
                    })
            results.append(('GET_CHALLENGE', length, result))
            
        # Test INTERNAL_AUTHENTICATE with various challenges
        test_data = [
            bytes([0x00] * 8),  # Zero challenge
            bytes([0xFF] * 8),  # All ones
            os.urandom(8),      # Random challenge
        ]
        
        for data in test_data:
            apdu = EMV_COMMANDS['INTERNAL_AUTHENTICATE'] + [len(data)] + list(data)
            result = self.transmit_with_timing(apdu, "INTERNAL_AUTH")
            results.append(('INTERNAL_AUTH', data.hex(), result))
            
        return results

    def test_protocol_compliance(self):
        """Test protocol compliance and error handling"""
        tests = [
            # Malformed SELECT
            (EMV_COMMANDS['SELECT'] + [0x04, 0xA0, 0x00], 'Truncated AID'),
            (EMV_COMMANDS['SELECT'] + [0xFF] + [0x00]*255, 'Oversized SELECT'),
            
            # Invalid CLA
            ([0xFF] + EMV_COMMANDS['SELECT'][1:], 'Invalid CLA'),
            
            # Invalid INS
            ([0x00, 0xFF, 0x00, 0x00], 'Invalid INS'),
            
            # Incorrect lengths
            (EMV_COMMANDS['READ_RECORD'] + [0x01], 'Short READ_RECORD'),
            (EMV_COMMANDS['GET_DATA'] + [0x01], 'Short GET_DATA'),
            
            # Boundary testing
            (EMV_COMMANDS['READ_RECORD'] + [0xFF, 0xFF], 'Boundary READ_RECORD'),
            (EMV_COMMANDS['GET_DATA'] + [0xFF, 0xFF], 'Boundary GET_DATA')
        ]
        
        results = []
        for apdu, description in tests:
            result = self.transmit_with_timing(apdu, f"COMPLIANCE_{description}")
            results.append((description, result))
            
        return results

    def test_fuzzing_patterns(self):
        """Test various fuzzing patterns"""
        patterns = [
            self._fuzz_length,
            self._fuzz_cla,
            self._fuzz_ins,
            self._fuzz_p1p2,
            self._fuzz_data
        ]
        
        results = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for pattern in patterns:
                futures.append(executor.submit(pattern))
            
            for future in futures:
                try:
                    result = future.result(timeout=10.0)
                    if result:
                        results.extend(result)
                except Exception as e:
                    logging.error(f"Fuzzing pattern error: {e}")
                    
        return results

    def _fuzz_length(self):
        """Fuzz length fields"""
        results = []
        commands = [
            ('SELECT', EMV_COMMANDS['SELECT']),
            ('READ_RECORD', EMV_COMMANDS['READ_RECORD']),
            ('GET_DATA', EMV_COMMANDS['GET_DATA'])
        ]
        
        lengths = [0x00, 0x01, 0x7F, 0x80, 0xFF]
        for name, cmd in commands:
            for length in lengths:
                apdu = cmd + [length] + [0x00] * (length % 16)
                result = self.transmit_with_timing(apdu, f"{name}_LENGTH_{length:02X}")
                results.append((f"{name}_LENGTH_{length:02X}", result))
                
        return results

    def _fuzz_cla(self):
        """Fuzz CLA byte"""
        results = []
        cla_values = [0x00, 0x80, 0x84, 0x90, 0x94, 0xF0, 0xFF]
        
        for cla in cla_values:
            for name, cmd in EMV_COMMANDS.items():
                modified_cmd = [cla] + cmd[1:]
                result = self.transmit_with_timing(modified_cmd, f"{name}_CLA_{cla:02X}")
                results.append((f"{name}_CLA_{cla:02X}", result))
                
        return results

    def _fuzz_ins(self):
        """Fuzz INS byte"""
        results = []
        ins_values = list(range(0xA0, 0xB0)) + [0x00, 0xFF]
        
        for ins in ins_values:
            apdu = [0x00, ins, 0x00, 0x00]
            result = self.transmit_with_timing(apdu, f"INS_{ins:02X}")
            results.append((f"INS_{ins:02X}", result))
                
        return results

    def _fuzz_p1p2(self):
        """Fuzz P1/P2 parameters"""
        results = []
        p1p2_pairs = [(0x00, 0x00), (0xFF, 0xFF), (0x80, 0x80), (0x40, 0x40)]
        
        for name, cmd in EMV_COMMANDS.items():
            for p1, p2 in p1p2_pairs:
                modified_cmd = cmd[:2] + [p1, p2]
                result = self.transmit_with_timing(modified_cmd, f"{name}_P1P2_{p1:02X}{p2:02X}")
                results.append((f"{name}_P1P2_{p1:02X}{p2:02X}", result))
                
        return results

    def _fuzz_data(self):
        """Fuzz data field with various patterns"""
        results = []
        patterns = [
            bytes([0x00] * 16),  # All zeros
            bytes([0xFF] * 16),  # All ones
            os.urandom(16),      # Random data
            bytes(range(16)),    # Sequence
            bytes([0xAA] * 16)   # Alternating bits
        ]
        
        for i, pattern in enumerate(patterns):
            for name, cmd in EMV_COMMANDS.items():
                apdu = cmd + [len(pattern)] + list(pattern)
                result = self.transmit_with_timing(apdu, f"{name}_DATA_PATTERN_{i}")
                results.append((f"{name}_DATA_PATTERN_{i}", result))
                
        return results

    def dummy_transaction(self):
        """Perform a dummy transaction to test basic EMV functionality"""
        logging.info("Starting dummy transaction simulation")
        results = {'steps': [], 'success': True, 'vulnerabilities': []}

        try:
            # Step 1: Application selection
            aid = random.choice(EMV_AIDS['VISA'] + EMV_AIDS['MASTERCARD'])
            sw, resp = self.transmit_with_timing(
                EMV_COMMANDS['SELECT'] + [len(bytes.fromhex(aid))] + bytes.fromhex(aid),
                "SELECT_APP"
            )
            results['steps'].append({
                'step': 'SELECT',
                'success': sw == [0x90, 0x00] if sw else False,
                'sw': sw,
                'response': resp.hex() if resp else None
            })
            
            if not sw or sw != [0x90, 0x00]:
                results['success'] = False
                return results

            # Step 2: Get Processing Options
            pdol_data = bytes([
                0x83, 0x00  # Empty PDOL
            ])
            sw, resp = self.transmit_with_timing(
                EMV_COMMANDS['GET_PROCESSING_OPTIONS'] + [len(pdol_data)] + list(pdol_data),
                "GPO"
            )
            results['steps'].append({
                'step': 'GPO',
                'success': sw == [0x90, 0x00] if sw else False,
                'sw': sw,
                'response': resp.hex() if resp else None
            })

            if sw and sw == [0x90, 0x00]:
                # Parse AFL from response
                tlv_data = TLVParser.parse(resp)
                for tlv in tlv_data:
                    if tlv.tag_str == '94':  # AFL
                        self._process_afl(tlv.value, results)

            # Step 3: Generate random challenge
            sw, challenge = self.get_challenge()
            results['steps'].append({
                'step': 'GET_CHALLENGE',
                'success': sw == [0x90, 0x00] if sw else False,
                'sw': sw,
                'response': challenge.hex() if challenge else None
            })

            # Step 4: Internal Authenticate
            if challenge:
                sw, auth_resp = self.transmit_with_timing(
                    EMV_COMMANDS['INTERNAL_AUTHENTICATE'] + [len(challenge)] + list(challenge),
                    "INTERNAL_AUTH"
                )
                results['steps'].append({
                    'step': 'INTERNAL_AUTH',
                    'success': sw == [0x90, 0x00] if sw else False,
                    'sw': sw,
                    'response': auth_resp.hex() if auth_resp else None
                })

            # Step 5: Generate AC (ARQC)
            cdol1_data = self._build_dummy_cdol1()
            sw, ac_resp = self.transmit_with_timing(
                EMV_COMMANDS['GENERATE_AC'] + [0x80, len(cdol1_data)] + list(cdol1_data),
                "GENERATE_AC"
            )
            results['steps'].append({
                'step': 'GENERATE_AC',
                'success': sw == [0x90, 0x00] if sw else False,
                'sw': sw,
                'response': ac_resp.hex() if ac_resp else None
            })

            # Analyze transaction timing
            timing_analysis = self._analyze_transaction_timing(results['steps'])
            results['timing_analysis'] = timing_analysis

            # Check for potential vulnerabilities
            self._check_transaction_vulnerabilities(results)

        except Exception as e:
            logging.error(f"Error during dummy transaction: {e}")
            results['success'] = False
            results['error'] = str(e)

        return results

    def _process_afl(self, afl_data, results):
        """Process Application File Locator (AFL) and read records"""
        if not afl_data or len(afl_data) % 4 != 0:
            return

        for i in range(0, len(afl_data), 4):
            sfi = afl_data[i] >> 3
            start_record = afl_data[i + 1]
            end_record = afl_data[i + 2]
            
            for record in range(start_record, end_record + 1):
                sw, resp = self.transmit_with_timing(
                    EMV_COMMANDS['READ_RECORD'] + [record, (sfi << 3) | 4, 0x00],
                    f"READ_RECORD_SFI{sfi}_REC{record}"
                )
                results['steps'].append({
                    'step': f'READ_RECORD_{sfi}_{record}',
                    'success': sw == [0x90, 0x00] if sw else False,
                    'sw': sw,
                    'response': resp.hex() if resp else None
                })

    def _build_dummy_cdol1(self):
        """Build dummy CDOL1 data for transaction"""
        # Standard EMV CDOL1 fields
        amount = bytes.fromhex('000000001000')  # Amount: 10.00
        terminal_country = bytes.fromhex('0840')  # USA
        tvr = bytes.fromhex('0000000000')  # All checks passed
        transaction_date = datetime.now().strftime('%y%m%d').encode('ascii')
        transaction_type = bytes([0x00])  # Purchase
        unpredictable_number = os.urandom(4)
        
        return amount + terminal_country + tvr + transaction_date + transaction_type + unpredictable_number

    def _analyze_transaction_timing(self, steps):
        """Analyze timing patterns in transaction steps"""
        timing_analysis = {
            'average_response_time': 0,
            'slowest_step': None,
            'fastest_step': None,
            'anomalies': []
        }
        
        step_times = []
        for step in steps:
            if 'timing' in step:
                step_times.append((step['step'], step['timing']))
        
        if step_times:
            # Calculate statistics
            times = [t[1] for t in step_times]
            avg_time = sum(times) / len(times)
            std_dev = (sum((t - avg_time) ** 2 for t in times) / len(times)) ** 0.5
            
            timing_analysis['average_response_time'] = avg_time
            timing_analysis['slowest_step'] = max(step_times, key=lambda x: x[1])
            timing_analysis['fastest_step'] = min(step_times, key=lambda x: x[1])
            
            # Detect anomalies
            for step, time in step_times:
                if abs(time - avg_time) > 2 * std_dev:
                    timing_analysis['anomalies'].append({
                        'step': step,
                        'time': time,
                        'deviation': abs(time - avg_time)
                    })
                    
        return timing_analysis

    def _check_transaction_vulnerabilities(self, results):
        """Check for potential vulnerabilities in transaction flow"""
        vulns = []
        
        for step in results['steps']:
            # Check for unusual status words
            if step.get('sw') and step['sw'] != [0x90, 0x00]:
                if step['sw'][0] in [0x6A, 0x6F, 0x6D]:
                    vulns.append({
                        'type': 'UNEXPECTED_RESPONSE',
                        'step': step['step'],
                        'sw': step['sw'],
                        'severity': 'MEDIUM'
                    })
            
            # Check response patterns
            if step.get('response'):
                try:
                    resp_data = bytes.fromhex(step['response'])
                    # Check for sensitive data patterns
                    if self._check_sensitive_data(resp_data):
                        vulns.append({
                            'type': 'SENSITIVE_DATA_EXPOSURE',
                            'step': step['step'],
                            'severity': 'HIGH'
                        })
                    
                    # Check for weak random data
                    if step['step'] in ['GET_CHALLENGE', 'INTERNAL_AUTH']:
                        if self._check_weak_random(resp_data):
                            vulns.append({
                                'type': 'WEAK_RANDOM',
                                'step': step['step'],
                                'severity': 'HIGH'
                            })
                except Exception:
                    pass
        
        # Check timing vulnerabilities
        if 'timing_analysis' in results and results['timing_analysis']['anomalies']:
            vulns.extend([{
                'type': 'TIMING_ANOMALY',
                'step': anomaly['step'],
                'severity': 'MEDIUM',
                'details': anomaly
            } for anomaly in results['timing_analysis']['anomalies']])
        
        results['vulnerabilities'] = vulns

    def _check_sensitive_data(self, data):
        """Check for sensitive data patterns in response"""
        patterns = {
            'PAN': re.compile(rb'[45]\d{15}'),
            'TRACK_DATA': re.compile(rb'%B\d{13,19}\^[\w\s/]{2,26}\^'),
            'PIN_BLOCK': re.compile(rb'[0-9A-F]{16}')
        }
        
        return any(pattern.search(data) for pattern in patterns.values())

    def _check_weak_random(self, data):
        """Check for weak random number generation"""
        if len(data) < 8:
            return False
            
        # Calculate entropy
        entropy = self.analyzer.calculate_entropy(data)
        if entropy < ANALYSIS_THRESHOLDS['MIN_ENTROPY']:
            return True
            
        # Check for repeating patterns
        if self.analyzer.find_repeating_sequences(data):
            return True
            
        # Check for linear relationships
        if self.analyzer.check_linear_relationship(data):
            return True
            
        return False

    def extract_keys(self):
        """Extract and analyze cryptographic keys from the card"""
        logging.info("Starting key extraction and analysis")
        results = {
            'extracted_keys': [],
            'potential_vulnerabilities': [],
            'analysis': {}
        }

        try:
            # 1. Key-related EMV tags
            key_tags = {
                # ICC Public Key
                '9F46': 'ICC Public Key Certificate',
                '9F47': 'ICC Public Key Exponent',
                '9F48': 'ICC Public Key Remainder',
                # Issuer Public Key
                '90': 'Issuer Public Key Certificate',
                '9F32': 'Issuer Public Key Exponent',
                '92': 'Issuer Public Key Remainder',
                # Other cryptographic data
                '8F': 'Certification Authority Public Key Index',
                '93': 'Signed Static Application Data',
                '9F45': 'Data Authentication Code',
                '9F4A': 'Static Data Authentication Tag List'
            }

            # Extract key data
            for tag, description in key_tags.items():
                sw, resp = self.transmit_with_timing(
                    EMV_COMMANDS['GET_DATA'] + bytes.fromhex(tag),
                    f"GET_KEY_{tag}"
                )
                if sw and sw == [0x90, 0x00] and resp:
                    key_data = {
                        'tag': tag,
                        'description': description,
                        'data': resp.hex(),
                        'length': len(resp),
                        'analysis': {}
                    }
                    
                    # Analyze key data
                    self._analyze_key_material(key_data)
                    results['extracted_keys'].append(key_data)

            # 2. Test for key derivation vulnerabilities
            diversification_test_results = self._test_key_diversification()
            results['analysis']['key_diversification'] = diversification_test_results

            # 3. Public key recovery attempts
            pk_recovery_results = self._attempt_public_key_recovery()
            results['analysis']['public_key_recovery'] = pk_recovery_results

            # 4. Key usage analysis
            key_usage_results = self._analyze_key_usage()
            results['analysis']['key_usage'] = key_usage_results

            # 5. Check for known vulnerabilities
            self._check_known_key_vulnerabilities(results)

        except Exception as e:
            logging.error(f"Error during key extraction: {e}")
            results['error'] = str(e)

        return results

    def _analyze_key_material(self, key_data):
        """Analyze extracted key material for potential issues"""
        if not key_data or 'data' not in key_data:
            return

        try:
            data = bytes.fromhex(key_data['data'])
            analysis = key_data['analysis']

            # Calculate entropy
            entropy = self.analyzer.calculate_entropy(data)
            analysis['entropy'] = entropy
            analysis['weak_entropy'] = entropy < ANALYSIS_THRESHOLDS['MIN_ENTROPY']

            # Pattern analysis
            repeating = self.analyzer.find_repeating_sequences(data)
            if repeating:
                analysis['repeating_sequences'] = repeating
                analysis['potential_issues'] = ['Repeating sequences in key material']

            # Length analysis
            if len(data) < 16:  # Suspicious for cryptographic keys
                analysis['potential_issues'] = analysis.get('potential_issues', []) + ['Key length too short']

            # Structure analysis
            analysis['structure'] = {
                'zero_bytes': data.count(0),
                'max_byte_value': max(data),
                'distinct_bytes': len(set(data))
            }

            # Known patterns check
            if self._check_known_patterns(data):
                analysis['potential_issues'] = analysis.get('potential_issues', []) + ['Contains known weak patterns']

        except Exception as e:
            logging.error(f"Error in key material analysis: {e}")
            key_data['analysis']['error'] = str(e)

    def _test_key_diversification(self):
        """Test for key diversification vulnerabilities"""
        results = {
            'tests_performed': [],
            'vulnerabilities': []
        }

        # Test different challenges
        challenges = [
            bytes([0x00] * 8),  # Zero challenge
            bytes([0xFF] * 8),  # All ones
            os.urandom(8)       # Random challenge
        ]

        for challenge in challenges:
            sw, resp1 = self.internal_authenticate(challenge)
            if sw and sw == [0x90, 0x00]:
                # Immediate retry with same challenge
                sw, resp2 = self.internal_authenticate(challenge)
                if sw and sw == [0x90, 0x00]:
                    results['tests_performed'].append({
                        'challenge': challenge.hex(),
                        'response1': resp1.hex() if resp1 else None,
                        'response2': resp2.hex() if resp2 else None,
                        'identical': resp1 == resp2 if resp1 and resp2 else None
                    })

                    # Check for concerning patterns
                    if resp1 == resp2:
                        results['vulnerabilities'].append({
                            'type': 'STATIC_RESPONSE',
                            'severity': 'HIGH',
                            'details': 'Same challenge produces identical response'
                        })

        return results

    def _attempt_public_key_recovery(self):
        """Attempt to recover public key information"""
        results = {
            'recovered_components': [],
            'potential_weaknesses': []
        }

        # Collect public key components
        key_components = {}
        for tag in ['9F46', '9F47', '9F48']:  # ICC Public Key components
            sw, resp = self.transmit(
                EMV_COMMANDS['GET_DATA'] + bytes.fromhex(tag),
                f"GET_PK_{tag}"
            )
            if sw and sw == [0x90, 0x00] and resp:
                key_components[tag] = resp

        if key_components:
            # Analyze modulus (if present)
            if '9F46' in key_components:
                self._analyze_rsa_modulus(key_components['9F46'], results)

            # Analyze exponent (if present)
            if '9F47' in key_components:
                self._analyze_rsa_exponent(key_components['9F47'], results)

        return results

    def _analyze_key_usage(self):
        """Analyze key usage patterns"""
        results = {
            'usage_patterns': [],
            'anomalies': []
        }

        # Test key usage in different scenarios
        test_cases = [
            (self._test_offline_auth, 'OFFLINE_AUTH'),
            (self._test_online_auth, 'ONLINE_AUTH'),
            (self._test_key_diversification, 'KEY_DIVERSIFICATION')
        ]

        for test_func, test_type in test_cases:
            try:
                test_result = test_func()
                results['usage_patterns'].append({
                    'type': test_type,
                    'result': test_result
                })
            except Exception as e:
                logging.error(f"Error in {test_type} test: {e}")

        return results

    def _check_known_key_vulnerabilities(self, results):
        """Check for known key-related vulnerabilities"""
        for key_data in results.get('extracted_keys', []):
            if not key_data.get('data'):
                continue

            data = bytes.fromhex(key_data['data'])
            
            # Check for weak key patterns
            if self._check_weak_key_patterns(data):
                results['potential_vulnerabilities'].append({
                    'type': 'WEAK_KEY',
                    'tag': key_data['tag'],
                    'description': key_data['description'],
                    'severity': 'HIGH'
                })

            # Check for known vulnerable key lengths
            if len(data) in [8, 16] and key_data['tag'] in ['9F46', '90']:  # Public key data
                results['potential_vulnerabilities'].append({
                    'type': 'INSUFFICIENT_KEY_LENGTH',
                    'tag': key_data['tag'],
                    'length': len(data),
                    'severity': 'HIGH'
                })

    def _check_known_patterns(self, data):
        """Check for known weak patterns in key data"""
        patterns = [
            bytes([0x00] * 8),  # All zeros
            bytes([0xFF] * 8),  # All ones
            bytes(range(8)),    # Sequential
        ]
        
        for pattern in patterns:
            if pattern in data:
                return True
        return False

    def _check_weak_key_patterns(self, data):
        """Check for patterns indicating weak keys"""
        if len(data) < 8:
            return True

        # Check for low entropy
        if self.analyzer.calculate_entropy(data) < ANALYSIS_THRESHOLDS['MIN_ENTROPY']:
            return True

        # Check for repeating blocks
        chunks = [data[i:i+8] for i in range(0, len(data), 8)]
        if len(set(chunks)) < len(chunks) / 2:
            return True

        # Check for simple patterns
        if self.analyzer.check_linear_relationship(data):
            return True

        return False

    def _analyze_rsa_modulus(self, modulus_data, results):
        """Analyze RSA modulus for potential weaknesses"""
        try:
            # Basic length check
            if len(modulus_data) < 128:  # Less than 1024 bits
                results['potential_weaknesses'].append({
                    'type': 'WEAK_MODULUS_LENGTH',
                    'length': len(modulus_data) * 8,
                    'severity': 'HIGH'
                })

            # Check for unusual patterns
            zero_bytes = modulus_data.count(0)
            if zero_bytes > len(modulus_data) / 8:
                results['potential_weaknesses'].append({
                    'type': 'SUSPICIOUS_MODULUS_PATTERN',
                    'details': f'High number of zero bytes: {zero_bytes}',
                    'severity': 'MEDIUM'
                })

        except Exception as e:
            logging.error(f"Error analyzing RSA modulus: {e}")

    def _analyze_rsa_exponent(self, exponent_data, results):
        """Analyze RSA exponent for potential weaknesses"""
        try:
            # Convert to integer
            e = int.from_bytes(exponent_data, 'big')
            
            # Check for common weak exponents
            weak_exponents = {3, 5, 17, 257, 65537}
            if e not in weak_exponents:
                results['potential_weaknesses'].append({
                    'type': 'UNUSUAL_EXPONENT',
                    'value': hex(e),
                    'severity': 'MEDIUM'
                })

        except Exception as e:
            logging.error(f"Error analyzing RSA exponent: {e}")

    def _test_offline_auth(self):
        """Test offline authentication mechanisms"""
        results = {
            'static_auth': None,
            'dynamic_auth': None,
            'vulnerabilities': []
        }

        # Test Static Data Authentication (SDA)
        sda_data = self._test_sda()
        results['static_auth'] = sda_data

        # Test Dynamic Data Authentication (DDA)
        dda_data = self._test_dda()
        results['dynamic_auth'] = dda_data

        return results

    def _test_sda(self):
        """Test Static Data Authentication"""
        sw, resp = self.transmit(
            EMV_COMMANDS['GET_DATA'] + bytes.fromhex('93'),  # Signed Static Application Data
            "GET_STATIC_DATA"
        )
        return {
            'success': sw == [0x90, 0x00] if sw else False,
            'data': resp.hex() if resp else None
        }

    def _test_dda(self):
        """Test Dynamic Data Authentication"""
        # Get challenge
        sw, challenge = self.get_challenge()
        if not sw or sw != [0x90, 0x00]:
            return {'success': False}

        # Internal Authenticate
        sw, resp = self.internal_authenticate(challenge)
        return {
            'success': sw == [0x90, 0x00] if sw else False,
            'challenge': challenge.hex() if challenge else None,
            'response': resp.hex() if resp else None
        }

    def _test_online_auth(self):
        """Test online authentication capabilities"""
        results = {
            'arqc_generation': None,
            'vulnerabilities': []
        }

        # Generate ARQC
        cdol1_data = self._build_dummy_cdol1()
        sw, resp = self.transmit(
            EMV_COMMANDS['GENERATE_AC'] + [0x80, len(cdol1_data)] + list(cdol1_data),
            "GENERATE_ARQC"
        )

        results['arqc_generation'] = {
            'success': sw == [0x90, 0x00] if sw else False,
            'response': resp.hex() if resp else None
        }

        return results

    # EMV Standards and Specifications
    EMV_STANDARDS = {
        'EMV_BOOK1': {
            'version': '4.3',
            'title': 'Application Independent ICC to Terminal Interface Requirements',
            'sections': {
                '11.3': 'Application Selection',
                '12.4': 'Command Processing'
            }
        },
        'EMV_BOOK2': {
            'version': '4.3',
            'title': 'Security and Key Management',
            'sections': {
                '6.3': 'Card Authentication',
                '7.2': 'Key Management'
            }
        },
        'EMV_BOOK3': {
            'version': '4.3',
            'title': 'Application Specification',
            'sections': {
                '10.5': 'CVM Processing',
                '6.5': 'Transaction Processing'
            }
        },
        'EMV_BOOK4': {
            'version': '4.3',
            'title': 'Cardholder, Attendant, and Acquirer Interface Requirements',
            'sections': {
                '2.4': 'Interface Requirements',
                '3.2': 'Transaction Flow'
            }
        },
        'EXPRESSPAY': {
            'version': '3.1',
            'title': 'American Express ExpressPay Specifications',
            'sections': {
                '5.3': 'Transaction Cryptogram',
                '4.2': 'Card Authentication'
            }
        }
    }

    # Attack Scenario Configurations
    ATTACK_SCENARIOS = {
        'SDA_DOWNGRADE': {
            'name': 'SDA Downgrade Attack',
            'standard': 'EMV_BOOK2',
            'section': '6.3',
            'steps': [
                'MODIFY_AIP',
                'FORCE_SDA',
                'BYPASS_DDA',
                'GENERATE_AC'
            ]
        },
        'PIN_BYPASS': {
            'name': 'Offline PIN Bypass',
            'standard': 'EMV_BOOK3',
            'section': '10.5',
            'steps': [
                'MODIFY_CVM',
                'SKIP_VERIFY',
                'FORCE_OFFLINE',
                'ACCEPT_TX'
            ]
        },
        'PRE_PLAY': {
            'name': 'Terminal UN Pre-play Attack',
            'standard': 'EMV_BOOK2',
            'section': '7.2',
            'steps': [
                'COLLECT_UN',
                'PREDICT_UN',
                'PRE_GENERATE_AC',
                'REPLAY_TX'
            ]
        },
        'EXPRESSPAY_REPLAY': {
            'name': 'ExpressPay Replay Attack',
            'standard': 'EXPRESSPAY',
            'section': '5.3',
            'steps': [
                'CAPTURE_NC',
                'MODIFY_PARAMS',
                'REPLAY_CRYPTOGRAM',
                'BYPASS_TRM'
            ]
        }
    }

    def simulate_attack_scenario(self, scenario_name):
        """Simulate a specific attack scenario"""
        if scenario_name not in ATTACK_SCENARIOS:
            raise ValueError(f"Unknown attack scenario: {scenario_name}")
            
        scenario = ATTACK_SCENARIOS[scenario_name]
        logging.info(f"Starting attack scenario: {scenario['name']}")
        results = {
            'scenario': scenario['name'],
            'standard': scenario['standard'],
            'section': scenario['section'],
            'steps': [],
            'success': False
        }
        
        try:
            for step in scenario['steps']:
                step_result = self._execute_attack_step(step)
                results['steps'].append(step_result)
                if not step_result['success']:
                    break
                    
            # Analyze results
            results['success'] = all(step['success'] for step in results['steps'])
            if results['success']:
                self.vulnerabilities.append({
                    'type': 'ATTACK_SUCCESSFUL',
                    'scenario': scenario['name'],
                    'standard': f"{scenario['standard']} Section {scenario['section']}",
                    'severity': 'HIGH'
                })
                
        except Exception as e:
            logging.error(f"Error in attack scenario {scenario['name']}: {e}")
            results['error'] = str(e)
            
        return results

    def _execute_attack_step(self, step):
        """Execute a specific attack step"""
        result = {
            'step': step,
            'success': False,
            'data': None
        }
        
        try:
            if step == 'MODIFY_AIP':
                result.update(self._modify_application_interchange_profile())
            elif step == 'FORCE_SDA':
                result.update(self._force_sda_authentication())
            elif step == 'MODIFY_CVM':
                result.update(self._modify_cvm_list())
            elif step == 'SKIP_VERIFY':
                result.update(self._skip_pin_verify())
            elif step == 'COLLECT_UN':
                result.update(self._collect_unpredictable_numbers())
            elif step == 'CAPTURE_NC':
                result.update(self._capture_expresspay_nonce())
            # Add other step implementations as needed
            
        except Exception as e:
            logging.error(f"Error executing step {step}: {e}")
            result['error'] = str(e)
            
        return result

    def _modify_application_interchange_profile(self):
        """Attempt to modify AIP for SDA downgrade"""
        # Read original AIP
        sw, resp = self.transmit(
            EMV_COMMANDS['GET_DATA'] + bytes.fromhex('9F52'),
            "GET_AIP"
        )
        
        if sw and sw == [0x90, 0x00] and resp:
            # Modify AIP to indicate SDA only
            modified_aip = bytes([resp[0] & 0xFE])  # Clear DDA/CDA bits
            return {
                'success': True,
                'original_aip': resp.hex(),
                'modified_aip': modified_aip.hex()
            }
        return {'success': False}

    def _force_sda_authentication(self):
        """Force SDA authentication method"""
        # Attempt to perform SDA
        sw, resp = self.transmit(
            EMV_COMMANDS['GET_DATA'] + bytes.fromhex('93'),
            "GET_SIGNED_DATA"
        )
        
        return {
            'success': sw and sw == [0x90, 0x00],
            'signed_data': resp.hex() if resp else None
        }

    def _modify_cvm_list(self):
        """Modify CVM list to prefer signature"""
        # Read CVM list
        sw, resp = self.transmit(
            EMV_COMMANDS['GET_DATA'] + bytes.fromhex('8E'),
            "GET_CVM_LIST"
        )
        
        if sw and sw == [0x90, 0x00] and resp:
            # Modify CVM list to prefer signature
            modified_cvm = bytearray(resp)
            if len(modified_cvm) >= 8:
                modified_cvm[2] = 0x02  # Signature CVM
                return {
                    'success': True,
                    'original_cvm': resp.hex(),
                    'modified_cvm': modified_cvm.hex()
                }
        return {'success': False}

    def _skip_pin_verify(self):
        """Attempt PIN verification bypass"""
        # Try transaction without VERIFY
        cdol1_data = self._build_dummy_cdol1()
        sw, resp = self.transmit(
            EMV_COMMANDS['GENERATE_AC'] + [0x80, len(cdol1_data)] + list(cdol1_data),
            "GENERATE_AC_NO_PIN"
        )
        
        return {
            'success': sw and sw == [0x90, 0x00],
            'response': resp.hex() if resp else None
        }

    def _collect_unpredictable_numbers(self):
        """Collect and analyze terminal unpredictable numbers"""
        uns = []
        for _ in range(10):
            sw, resp = self.get_challenge()
            if sw and sw == [0x90, 0x00]:
                uns.append(resp)
                
        if uns:
            # Analyze UN patterns
            entropy = self.analyzer.calculate_entropy(b''.join(uns))
            return {
                'success': True,
                'un_samples': [un.hex() for un in uns],
                'entropy': entropy,
                'predictable': entropy < ANALYSIS_THRESHOLDS['MIN_ENTROPY']
            }
        return {'success': False}

    def _capture_expresspay_nonce(self):
        """Capture ExpressPay nonce and transaction data"""
        # Select ExpressPay application
        if not self.select_application('A00000002501'):
            return {'success': False}
            
        # Get processing options
        sw, resp = self.get_processing_options()
        if sw and sw == [0x90, 0x00]:
            return {
                'success': True,
                'nonce': resp.hex() if resp else None
            }
        return {'success': False}

    def check_standard_compliance(self, standard, section=None):
        """Check compliance with specific EMV standard section"""
        if standard not in EMV_STANDARDS:
            raise ValueError(f"Unknown EMV standard: {standard}")
            
        std = EMV_STANDARDS[standard]
        results = {
            'standard': standard,
            'version': std['version'],
            'title': std['title'],
            'sections': {}
        }
        
        sections = [section] if section else std['sections'].keys()
        
        for sec in sections:
            if sec not in std['sections']:
                continue
                
            # Perform section-specific compliance checks
            section_result = self._check_section_compliance(standard, sec)
            results['sections'][sec] = section_result
            
        return results

    def _check_section_compliance(self, standard, section):
        """Check compliance with a specific standard section"""
        result = {
            'compliant': False,
            'tests': [],
            'vulnerabilities': []
        }
        
        try:
            if standard == 'EMV_BOOK2' and section == '6.3':
                # Card Authentication Tests
                result.update(self._test_card_authentication())
            elif standard == 'EMV_BOOK3' and section == '10.5':
                # CVM Processing Tests
                result.update(self._test_cvm_processing())
            elif standard == 'EXPRESSPAY' and section == '5.3':
                # ExpressPay Cryptogram Tests
                result.update(self._test_expresspay_cryptogram())
            # Add other section-specific tests
            
        except Exception as e:
            logging.error(f"Error checking {standard} section {section}: {e}")
            result['error'] = str(e)
            
        return result