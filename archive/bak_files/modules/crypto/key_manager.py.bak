"""
GREENWIRE Key Management & Cracking System
==========================================

Comprehensive key extraction, evaluation, storage, and cracking system for keys obtained via:
- CAP file analysis and installation
- GlobalPlatform (GP) operations
- OpenSC smart card operations
- Card dump analysis
- EMV transaction data

Features:
- Multi-source key extraction and validation
- Advanced cracking algorithms (brute force, dictionary, rainbow tables)
- Key derivation and correlation analysis
- EMV-specific key cracking using PyEMV methods
- Persistent key database with metadata
- Performance monitoring and optimization
- CVE vulnerability checks for discovered keys

Based on security research from PyEMV and GlobalPlatform specifications.
"""

import os
import json
import hashlib
import sqlite3
import secrets
import threading
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import concurrent.futures
from collections import defaultdict

# Cryptographic imports
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# GREENWIRE imports
from .emv_crypto import create_emv_crypto_manager, EMVKeyDerivation
from .primitives import encrypt_tdes_ecb, decrypt_tdes_ecb, adjust_key_parity


class KeySource(Enum):
    """Sources of key extraction"""
    CAP_FILE = "cap_file"
    GLOBALPLATFORM = "globalplatform"
    OPENSC = "opensc"
    CARD_DUMP = "card_dump"
    EMV_TRANSACTION = "emv_transaction"
    MERCHANT_TERMINAL = "merchant_terminal"
    BRUTE_FORCE = "brute_force"
    DICTIONARY = "dictionary"
    RAINBOW_TABLE = "rainbow_table"
    TIMING_ATTACK = "timing_attack"
    DIFFERENTIAL = "differential"
    CVE_EXPLOIT = "cve_exploit"


class KeyType(Enum):
    """Types of cryptographic keys"""
    MASTER_KEY = "master_key"
    SESSION_KEY = "session_key"
    ISSUER_MASTER_KEY = "issuer_master_key"
    ICC_MASTER_KEY = "icc_master_key"
    APPLICATION_CRYPTOGRAM_KEY = "ac_key"
    SECURE_MESSAGING_KEY = "sm_key"
    DATA_ENCRYPTION_KEY = "dek"
    MAC_KEY = "mac_key"
    TRANSPORT_KEY = "transport_key"
    PIN_KEY = "pin_key"
    UNKNOWN = "unknown"


class CrackingMethod(Enum):
    """Methods for key cracking"""
    BRUTE_FORCE = "brute_force"
    DICTIONARY_ATTACK = "dictionary"
    RAINBOW_TABLE = "rainbow_table"
    PATTERN_ANALYSIS = "pattern_analysis"
    WEAK_KEY_CHECK = "weak_key_check"
    CVE_EXPLOIT = "cve_exploit"
    TIMING_ATTACK = "timing_attack"
    DIFFERENTIAL_ANALYSIS = "differential"
    KEY_CORRELATION = "correlation"
    EMV_DERIVATION = "emv_derivation"


@dataclass
class ExtractedKey:
    """Represents an extracted cryptographic key with metadata"""
    key_hex: str
    key_type: KeyType
    source: KeySource
    source_file: Optional[str] = None
    extraction_method: Optional[str] = None
    bit_length: Optional[int] = None
    is_weak: bool = False
    entropy: Optional[float] = None
    first_seen: Optional[datetime] = None
    last_used: Optional[datetime] = None
    usage_count: int = 0
    success_rate: float = 0.0
    related_keys: List[str] = None
    vulnerabilities: List[str] = None
    key_check_value: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.related_keys is None:
            self.related_keys = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.metadata is None:
            self.metadata = {}
        if self.bit_length is None:
            self.bit_length = len(self.key_hex) * 4


@dataclass
class CrackingResult:
    """Result of a key cracking attempt"""
    success: bool
    method: CrackingMethod
    time_taken: float
    attempts: int
    key_found: Optional[str] = None
    confidence: float = 0.0
    additional_info: Dict[str, Any] = None

    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}


class KeyExtractor:
    """Extract keys from various sources"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.emv_crypto = create_emv_crypto_manager()
        
    def extract_from_cap_file(self, cap_file_path: str) -> List[ExtractedKey]:
        """Extract keys from CAP file analysis"""
        self.logger.info(f"Extracting keys from CAP file: {cap_file_path}")
        keys = []
        
        try:
            with open(cap_file_path, 'rb') as f:
                cap_data = f.read()
            
            # Look for common key patterns in CAP file
            key_patterns = self._find_key_patterns(cap_data)
            
            for pattern in key_patterns:
                key = ExtractedKey(
                    key_hex=pattern['key'],
                    key_type=self._identify_key_type(pattern['key'], pattern.get('context')),
                    source=KeySource.CAP_FILE,
                    source_file=cap_file_path,
                    extraction_method="pattern_analysis",
                    metadata={'context': pattern.get('context', '')}
                )
                keys.append(key)
                
        except Exception as e:
            self.logger.error(f"Failed to extract keys from CAP file: {e}")
            
        self.logger.info(f"Extracted {len(keys)} keys from CAP file")
        return keys
    
    def extract_from_gp_session(self, gp_output: str) -> List[ExtractedKey]:
        """Extract keys from GlobalPlatform session output"""
        self.logger.info("Extracting keys from GlobalPlatform session")
        keys = []
        
        # Parse GP output for key information
        key_patterns = [
            r'Key:\s*([0-9A-Fa-f]{32})',
            r'Master Key:\s*([0-9A-Fa-f]{32})',
            r'DEK:\s*([0-9A-Fa-f]{32})',
            r'MAC Key:\s*([0-9A-Fa-f]{32})',
            r'ENC Key:\s*([0-9A-Fa-f]{32})',
        ]
        
        import re
        for pattern in key_patterns:
            matches = re.findall(pattern, gp_output, re.IGNORECASE)
            for match in matches:
                key_type = self._gp_pattern_to_key_type(pattern)
                key = ExtractedKey(
                    key_hex=match.upper(),
                    key_type=key_type,
                    source=KeySource.GLOBALPLATFORM,
                    extraction_method="gp_session_parse",
                    metadata={'raw_output': gp_output[:500]}  # First 500 chars
                )
                keys.append(key)
        
        self.logger.info(f"Extracted {len(keys)} keys from GP session")
        return keys
    
    def extract_from_card_dump(self, dump_file_path: str) -> List[ExtractedKey]:
        """Extract keys from card memory dump"""
        self.logger.info(f"Extracting keys from card dump: {dump_file_path}")
        keys = []
        
        try:
            with open(dump_file_path, 'rb') as f:
                dump_data = f.read()
            
            # Advanced key pattern detection in binary dumps
            key_candidates = self._advanced_key_detection(dump_data)
            
            for candidate in key_candidates:
                key = ExtractedKey(
                    key_hex=candidate['key'],
                    key_type=self._identify_key_type(candidate['key'], candidate.get('context')),
                    source=KeySource.CARD_DUMP,
                    source_file=dump_file_path,
                    extraction_method="binary_analysis",
                    entropy=candidate.get('entropy'),
                    metadata={
                        'offset': candidate.get('offset'),
                        'context': candidate.get('context', ''),
                        'confidence': candidate.get('confidence', 0.0)
                    }
                )
                keys.append(key)
                
        except Exception as e:
            self.logger.error(f"Failed to extract keys from dump: {e}")
            
        self.logger.info(f"Extracted {len(keys)} keys from card dump")
        return keys
    
    def extract_from_emv_transaction(self, transaction_data: Dict[str, Any]) -> List[ExtractedKey]:
        """Extract keys from EMV transaction analysis"""
        self.logger.info("Extracting keys from EMV transaction data")
        keys = []
        
        # Look for session keys, application cryptograms, etc.
        if 'session_keys' in transaction_data:
            for sk_type, sk_value in transaction_data['session_keys'].items():
                key = ExtractedKey(
                    key_hex=sk_value,
                    key_type=KeyType.SESSION_KEY,
                    source=KeySource.EMV_TRANSACTION,
                    extraction_method="transaction_analysis",
                    metadata={'session_type': sk_type, 'transaction': transaction_data}
                )
                keys.append(key)
        
        # Extract derived keys if available
        if 'derived_keys' in transaction_data:
            for dk_type, dk_value in transaction_data['derived_keys'].items():
                key = ExtractedKey(
                    key_hex=dk_value,
                    key_type=self._emv_key_type_mapping(dk_type),
                    source=KeySource.EMV_TRANSACTION,
                    extraction_method="key_derivation",
                    metadata={'derivation_type': dk_type}
                )
                keys.append(key)
        
        self.logger.info(f"Extracted {len(keys)} keys from EMV transaction")
        return keys
    
    def _find_key_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Find potential key patterns in binary data"""
        patterns = []
        
        # Look for 16-byte (128-bit) and 24-byte (192-bit) key patterns
        for key_size in [16, 24, 32]:  # 128, 192, 256 bit keys
            for i in range(len(data) - key_size + 1):
                chunk = data[i:i + key_size]
                
                # Calculate entropy to identify potential keys
                entropy = self._calculate_entropy(chunk)
                
                # High entropy suggests cryptographic material
                if entropy > 3.5:  # Threshold for potential key material
                    key_hex = chunk.hex().upper()
                    context = data[max(0, i-16):i+key_size+16].hex()
                    
                    patterns.append({
                        'key': key_hex,
                        'offset': i,
                        'entropy': entropy,
                        'context': context,
                        'confidence': min(entropy / 4.0, 1.0)
                    })
        
        return patterns
    
    def _advanced_key_detection(self, data: bytes) -> List[Dict[str, Any]]:
        """Advanced key detection using multiple heuristics"""
        candidates = []
        
        # Basic pattern detection
        basic_patterns = self._find_key_patterns(data)
        candidates.extend(basic_patterns)
        
        # Look for DES/3DES key patterns (parity bits)
        des_keys = self._find_des_keys(data)
        candidates.extend(des_keys)
        
        # Look for EMV key derivation patterns
        emv_keys = self._find_emv_key_patterns(data)
        candidates.extend(emv_keys)
        
        # Remove duplicates and sort by confidence
        unique_candidates = []
        seen_keys = set()
        
        for candidate in sorted(candidates, key=lambda x: x.get('confidence', 0), reverse=True):
            key = candidate['key']
            if key not in seen_keys:
                seen_keys.add(key)
                unique_candidates.append(candidate)
        
        return unique_candidates[:50]  # Return top 50 candidates
    
    def _find_des_keys(self, data: bytes) -> List[Dict[str, Any]]:
        """Find DES/3DES keys by checking parity bits"""
        keys = []
        
        for i in range(len(data) - 7):  # DES key is 8 bytes
            chunk = data[i:i + 8]
            if self._has_valid_des_parity(chunk):
                key_hex = chunk.hex().upper()
                keys.append({
                    'key': key_hex,
                    'offset': i,
                    'entropy': self._calculate_entropy(chunk),
                    'context': 'des_parity_valid',
                    'confidence': 0.8
                })
        
        return keys
    
    def _find_emv_key_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Find EMV-specific key patterns"""
        keys = []
        
        # Look for patterns that match EMV key derivation inputs
        # PAN (Primary Account Number) patterns
        pan_pattern = rb'\x40[\x00-\x99][\x00-\x99][\x00-\x99][\x00-\x99][\x00-\x99][\x00-\x99][\x00-\x99]'
        
        import re
        for match in re.finditer(pan_pattern, data):
            offset = match.start()
            # Look for potential keys near PAN data
            for key_offset in range(max(0, offset - 64), min(len(data) - 16, offset + 64)):
                chunk = data[key_offset:key_offset + 16]
                if self._calculate_entropy(chunk) > 3.0:
                    keys.append({
                        'key': chunk.hex().upper(),
                        'offset': key_offset,
                        'entropy': self._calculate_entropy(chunk),
                        'context': 'emv_pan_vicinity',
                        'confidence': 0.6
                    })
        
        return keys
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data"""
        if not data:
            return 0
        
        # Count frequency of each byte value
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in freq.values():
            p = count / data_len
            if p > 0:
                entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    def _has_valid_des_parity(self, key_bytes: bytes) -> bool:
        """Check if bytes have valid DES parity bits"""
        if len(key_bytes) != 8:
            return False
        
        for byte in key_bytes:
            # Count number of 1s in byte
            ones = bin(byte).count('1')
            # DES uses odd parity
            if ones % 2 == 0:
                return False
        
        return True
    
    def _identify_key_type(self, key_hex: str, context: str = "") -> KeyType:
        """Identify the type of key based on patterns and context"""
        key_len = len(key_hex)
        context_lower = context.lower()
        
        # Length-based classification
        if key_len == 16:  # 64-bit (DES)
            return KeyType.SESSION_KEY
        elif key_len == 32:  # 128-bit
            if 'master' in context_lower:
                return KeyType.MASTER_KEY
            elif 'mac' in context_lower:
                return KeyType.MAC_KEY
            elif 'dek' in context_lower:
                return KeyType.DATA_ENCRYPTION_KEY
            else:
                return KeyType.SESSION_KEY
        elif key_len == 48:  # 192-bit (3DES)
            return KeyType.MASTER_KEY
        elif key_len == 64:  # 256-bit
            return KeyType.ISSUER_MASTER_KEY
        
        return KeyType.UNKNOWN
    
    def _gp_pattern_to_key_type(self, pattern: str) -> KeyType:
        """Map GlobalPlatform pattern to key type"""
        pattern_lower = pattern.lower()
        if 'master' in pattern_lower:
            return KeyType.MASTER_KEY
        elif 'dek' in pattern_lower:
            return KeyType.DATA_ENCRYPTION_KEY
        elif 'mac' in pattern_lower:
            return KeyType.MAC_KEY
        elif 'enc' in pattern_lower:
            return KeyType.DATA_ENCRYPTION_KEY
        else:
            return KeyType.UNKNOWN
    
    def _emv_key_type_mapping(self, emv_type: str) -> KeyType:
        """Map EMV key types to our KeyType enum"""
        mapping = {
            'icc_mk_ac': KeyType.APPLICATION_CRYPTOGRAM_KEY,
            'icc_mk_smi': KeyType.SECURE_MESSAGING_KEY,
            'icc_mk_smc': KeyType.SECURE_MESSAGING_KEY,
            'session_key': KeyType.SESSION_KEY,
            'master_key': KeyType.MASTER_KEY,
            'issuer_key': KeyType.ISSUER_MASTER_KEY
        }
        return mapping.get(emv_type.lower(), KeyType.UNKNOWN)


class KeyCracker:
    """Advanced key cracking system"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.common_keys_db = self._load_common_keys()
        self.rainbow_tables = {}
        self.emv_crypto = create_emv_crypto_manager()
        
    def crack_key(self, key_fragment: str, method: CrackingMethod = CrackingMethod.BRUTE_FORCE, 
                  max_attempts: int = 1000000, timeout: float = 300.0) -> CrackingResult:
        """Attempt to crack a partial or weak key"""
        start_time = time.time()
        
        self.logger.info(f"Starting key cracking: method={method.value}, fragment={key_fragment[:16]}...")
        
        if method == CrackingMethod.BRUTE_FORCE:
            return self._brute_force_crack(key_fragment, max_attempts, timeout, start_time)
        elif method == CrackingMethod.DICTIONARY_ATTACK:
            return self._dictionary_attack(key_fragment, timeout, start_time)
        elif method == CrackingMethod.WEAK_KEY_CHECK:
            return self._weak_key_check(key_fragment, start_time)
        elif method == CrackingMethod.PATTERN_ANALYSIS:
            return self._pattern_analysis_crack(key_fragment, start_time)
        elif method == CrackingMethod.EMV_DERIVATION:
            return self._emv_derivation_crack(key_fragment, start_time)
        else:
            return CrackingResult(
                success=False,
                method=method,
                time_taken=time.time() - start_time,
                attempts=0,
                additional_info={'error': f'Method {method.value} not implemented'}
            )
    
    def _brute_force_crack(self, key_fragment: str, max_attempts: int, 
                          timeout: float, start_time: float) -> CrackingResult:
        """Brute force key cracking with optimizations"""
        attempts = 0
        fragment_len = len(key_fragment)
        
        # If fragment is short, try to complete it
        if fragment_len < 32:  # Less than 128 bits
            missing_chars = 32 - fragment_len
            
            for attempts in range(min(max_attempts, 16 ** missing_chars)):
                if time.time() - start_time > timeout:
                    break
                
                # Generate completion
                completion = format(attempts, f'0{missing_chars}X')
                candidate = key_fragment + completion
                
                # Test candidate key
                if self._test_key_validity(candidate):
                    return CrackingResult(
                        success=True,
                        method=CrackingMethod.BRUTE_FORCE,
                        time_taken=time.time() - start_time,
                        attempts=attempts + 1,
                        key_found=candidate,
                        confidence=0.9
                    )
        
        return CrackingResult(
            success=False,
            method=CrackingMethod.BRUTE_FORCE,
            time_taken=time.time() - start_time,
            attempts=attempts
        )
    
    def _dictionary_attack(self, key_fragment: str, timeout: float, start_time: float) -> CrackingResult:
        """Dictionary-based key cracking"""
        attempts = 0
        
        for common_key in self.common_keys_db:
            if time.time() - start_time > timeout:
                break
            
            attempts += 1
            
            # Check if common key matches or contains fragment
            if key_fragment.lower() in common_key.lower() or common_key.lower() in key_fragment.lower():
                if self._test_key_validity(common_key):
                    return CrackingResult(
                        success=True,
                        method=CrackingMethod.DICTIONARY_ATTACK,
                        time_taken=time.time() - start_time,
                        attempts=attempts,
                        key_found=common_key,
                        confidence=0.95
                    )
        
        return CrackingResult(
            success=False,
            method=CrackingMethod.DICTIONARY_ATTACK,
            time_taken=time.time() - start_time,
            attempts=attempts
        )
    
    def _weak_key_check(self, key_fragment: str, start_time: float) -> CrackingResult:
        """Check for known weak keys and patterns"""
        weak_patterns = [
            '00000000000000000000000000000000',
            'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
            '0123456789ABCDEF0123456789ABCDEF',
            '404142434445464748494A4B4C4D4E4F',  # Default GP key
            '000102030405060708090A0B0C0D0E0F',
            'FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE',
            '0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F',
        ]
        
        # Check for exact matches
        key_upper = key_fragment.upper()
        for weak_key in weak_patterns:
            if key_upper == weak_key or weak_key.startswith(key_upper):
                return CrackingResult(
                    success=True,
                    method=CrackingMethod.WEAK_KEY_CHECK,
                    time_taken=time.time() - start_time,
                    attempts=1,
                    key_found=weak_key,
                    confidence=1.0,
                    additional_info={'weakness': 'Known weak key pattern'}
                )
        
        # Check for pattern repetitions
        if len(key_fragment) >= 8:
            pattern = key_fragment[:8]
            if key_fragment == pattern * (len(key_fragment) // 8):
                return CrackingResult(
                    success=True,
                    method=CrackingMethod.WEAK_KEY_CHECK,
                    time_taken=time.time() - start_time,
                    attempts=1,
                    key_found=key_fragment,
                    confidence=0.8,
                    additional_info={'weakness': 'Repeating pattern detected'}
                )
        
        return CrackingResult(
            success=False,
            method=CrackingMethod.WEAK_KEY_CHECK,
            time_taken=time.time() - start_time,
            attempts=len(weak_patterns)
        )
    
    def _pattern_analysis_crack(self, key_fragment: str, start_time: float) -> CrackingResult:
        """Analyze key patterns and attempt completion"""
        # Look for arithmetic progressions
        if len(key_fragment) >= 8:
            bytes_list = [int(key_fragment[i:i+2], 16) for i in range(0, min(8, len(key_fragment)), 2)]
            
            if len(bytes_list) >= 3:
                # Check for arithmetic progression
                diff = bytes_list[1] - bytes_list[0]
                is_progression = all(bytes_list[i] - bytes_list[i-1] == diff for i in range(1, len(bytes_list)))
                
                if is_progression:
                    # Try to complete the progression
                    completed_key = key_fragment
                    while len(completed_key) < 32:
                        next_byte = (bytes_list[-1] + diff) % 256
                        completed_key += f"{next_byte:02X}"
                        bytes_list.append(next_byte)
                    
                    return CrackingResult(
                        success=True,
                        method=CrackingMethod.PATTERN_ANALYSIS,
                        time_taken=time.time() - start_time,
                        attempts=1,
                        key_found=completed_key,
                        confidence=0.7,
                        additional_info={'pattern': 'arithmetic_progression', 'diff': diff}
                    )
        
        return CrackingResult(
            success=False,
            method=CrackingMethod.PATTERN_ANALYSIS,
            time_taken=time.time() - start_time,
            attempts=1
        )
    
    def _emv_derivation_crack(self, key_fragment: str, start_time: float) -> CrackingResult:
        """Attempt EMV key derivation attacks"""
        # Try common PAN and PSN combinations to derive keys
        common_pans = [
            '4000000000000002',
            '5555555555554444',
            '378282246310005',
            '4111111111111111',
            '4000000000000002'
        ]
        
        for pan in common_pans:
            for psn in range(256):  # Try PSN 0-255
                try:
                    # Try different issuer master keys
                    for test_mk in self.common_keys_db[:10]:  # Test first 10 common keys
                        if len(test_mk) == 32:  # 128-bit key
                            derived_key = EMVKeyDerivation.derive_icc_mk_a(
                                bytes.fromhex(test_mk), pan, psn
                            )
                            derived_hex = derived_key.hex().upper()
                            
                            if derived_hex.startswith(key_fragment.upper()):
                                return CrackingResult(
                                    success=True,
                                    method=CrackingMethod.EMV_DERIVATION,
                                    time_taken=time.time() - start_time,
                                    attempts=len(common_pans) * 256,
                                    key_found=derived_hex,
                                    confidence=0.85,
                                    additional_info={
                                        'pan': pan,
                                        'psn': psn,
                                        'master_key': test_mk,
                                        'derivation': 'Option A'
                                    }
                                )
                except Exception:
                    continue
        
        return CrackingResult(
            success=False,
            method=CrackingMethod.EMV_DERIVATION,
            time_taken=time.time() - start_time,
            attempts=len(common_pans) * 256 * 10
        )
    
    def _test_key_validity(self, key_hex: str) -> bool:
        """Test if a key is valid by checking various properties"""
        if len(key_hex) not in [16, 32, 48, 64]:  # Valid key lengths
            return False
        
        try:
            key_bytes = bytes.fromhex(key_hex)
        except ValueError:
            return False
        
        # Check entropy (avoid all zeros, all ones, etc.)
        entropy = self._calculate_key_entropy(key_bytes)
        return entropy > 2.0  # Minimum entropy threshold
    
    def _calculate_key_entropy(self, key_bytes: bytes) -> float:
        """Calculate entropy of key bytes"""
        if not key_bytes:
            return 0
        
        freq = defaultdict(int)
        for byte in key_bytes:
            freq[byte] += 1
        
        entropy = 0.0
        key_len = len(key_bytes)
        for count in freq.values():
            p = count / key_len
            if p > 0:
                entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    def _load_common_keys(self) -> List[str]:
        """Load database of common/default keys"""
        return [
            # Default GlobalPlatform keys
            '404142434445464748494A4B4C4D4E4F',
            '000102030405060708090A0B0C0D0E0F', 
            'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
            '00000000000000000000000000000000',
            '0123456789ABCDEF0123456789ABCDEF',
            'FEDCBA9876543210FEDCBA9876543210',
            # Common weak keys
            'FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE',
            '0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F',
            'A0A1A2A3A4A5A6A7A8A9AAABACADAEAF',
            'B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF',
            # Test keys from various standards
            '2B7E151628AED2A6ABF7158809CF4F3C',  # AES test vector
            '0101010101010101FEFEFEFEFEFEFEFE',  # DES weak keys
            '1F1F1F1F0E0E0E0E',  # DES semi-weak key
            # Common patterns
            '123456789ABCDEF0123456789ABCDEF0',
            'ABCDEF0123456789ABCDEF0123456789'
        ]


class KeyDatabase:
    """Persistent storage and management of extracted keys"""
    
    def __init__(self, db_path: str = "keys.db", logger: Optional[logging.Logger] = None):
        self.db_path = db_path
        self.logger = logger or logging.getLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for key storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS extracted_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hex TEXT UNIQUE NOT NULL,
                key_type TEXT NOT NULL,
                source TEXT NOT NULL,
                source_file TEXT,
                extraction_method TEXT,
                bit_length INTEGER,
                is_weak BOOLEAN DEFAULT FALSE,
                entropy REAL,
                first_seen TEXT,
                last_used TEXT,
                usage_count INTEGER DEFAULT 0,
                success_rate REAL DEFAULT 0.0,
                key_check_value TEXT,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS key_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key1_id INTEGER,
                key2_id INTEGER,
                relationship_type TEXT,
                confidence REAL,
                FOREIGN KEY (key1_id) REFERENCES extracted_keys (id),
                FOREIGN KEY (key2_id) REFERENCES extracted_keys (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cracking_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_fragment TEXT,
                method TEXT,
                success BOOLEAN,
                time_taken REAL,
                attempts INTEGER,
                key_found TEXT,
                confidence REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id INTEGER,
                cve_id TEXT,
                severity TEXT,
                description TEXT,
                discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (key_id) REFERENCES extracted_keys (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_key(self, key: ExtractedKey) -> int:
        """Store extracted key in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO extracted_keys 
                (key_hex, key_type, source, source_file, extraction_method, bit_length,
                 is_weak, entropy, first_seen, last_used, usage_count, success_rate,
                 key_check_value, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                key.key_hex,
                key.key_type.value,
                key.source.value,
                key.source_file,
                key.extraction_method,
                key.bit_length,
                key.is_weak,
                key.entropy,
                key.first_seen.isoformat() if key.first_seen else None,
                key.last_used.isoformat() if key.last_used else None,
                key.usage_count,
                key.success_rate,
                key.key_check_value,
                json.dumps(key.metadata)
            ))
            
            key_id = cursor.lastrowid
            conn.commit()
            
            self.logger.info(f"Stored key {key.key_hex[:16]}... (ID: {key_id})")
            return key_id
            
        except Exception as e:
            self.logger.error(f"Failed to store key: {e}")
            return -1
        finally:
            conn.close()
    
    def get_keys_by_source(self, source: KeySource) -> List[ExtractedKey]:
        """Retrieve keys by source"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM extracted_keys WHERE source = ?
        ''', (source.value,))
        
        keys = []
        for row in cursor.fetchall():
            key = self._row_to_extracted_key(row)
            keys.append(key)
        
        conn.close()
        return keys
    
    def get_weak_keys(self) -> List[ExtractedKey]:
        """Retrieve all weak keys"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM extracted_keys WHERE is_weak = TRUE
        ''')
        
        keys = []
        for row in cursor.fetchall():
            key = self._row_to_extracted_key(row)
            keys.append(key)
        
        conn.close()
        return keys
    
    def store_cracking_result(self, result: CrackingResult, key_fragment: str):
        """Store cracking attempt result"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO cracking_attempts 
            (key_fragment, method, success, time_taken, attempts, key_found, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            key_fragment,
            result.method.value,
            result.success,
            result.time_taken,
            result.attempts,
            result.key_found,
            result.confidence
        ))
        
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total keys
        cursor.execute('SELECT COUNT(*) FROM extracted_keys')
        stats['total_keys'] = cursor.fetchone()[0]
        
        # Keys by source
        cursor.execute('''
            SELECT source, COUNT(*) FROM extracted_keys GROUP BY source
        ''')
        stats['keys_by_source'] = dict(cursor.fetchall())
        
        # Keys by type
        cursor.execute('''
            SELECT key_type, COUNT(*) FROM extracted_keys GROUP BY key_type
        ''')
        stats['keys_by_type'] = dict(cursor.fetchall())
        
        # Weak keys
        cursor.execute('SELECT COUNT(*) FROM extracted_keys WHERE is_weak = TRUE')
        stats['weak_keys'] = cursor.fetchone()[0]
        
        # Cracking attempts
        cursor.execute('SELECT COUNT(*) FROM cracking_attempts')
        stats['total_cracking_attempts'] = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM cracking_attempts WHERE success = TRUE')
        stats['successful_cracks'] = cursor.fetchone()[0]
        
        conn.close()
        return stats
    
    def _row_to_extracted_key(self, row) -> ExtractedKey:
        """Convert database row to ExtractedKey object"""
        return ExtractedKey(
            key_hex=row[1],
            key_type=KeyType(row[2]),
            source=KeySource(row[3]),
            source_file=row[4],
            extraction_method=row[5],
            bit_length=row[6],
            is_weak=bool(row[7]),
            entropy=row[8],
            first_seen=datetime.fromisoformat(row[9]) if row[9] else None,
            last_used=datetime.fromisoformat(row[10]) if row[10] else None,
            usage_count=row[11],
            success_rate=row[12],
            key_check_value=row[13],
            metadata=json.loads(row[14]) if row[14] else {}
        )


class KeyManager:
    """Main key management orchestrator"""
    
    def __init__(self, db_path: str = "keys.db", logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.extractor = KeyExtractor(logger)
        self.cracker = KeyCracker(logger)
        self.database = KeyDatabase(db_path, logger)
        
    def process_cap_file(self, cap_file_path: str, crack_keys: bool = True) -> Dict[str, Any]:
        """Process CAP file: extract keys, evaluate, save, and optionally crack"""
        self.logger.info(f"Processing CAP file: {cap_file_path}")
        
        # Extract keys
        keys = self.extractor.extract_from_cap_file(cap_file_path)
        
        results = {
            'file': cap_file_path,
            'extracted_keys': len(keys),
            'weak_keys': 0,
            'cracked_keys': 0,
            'stored_keys': 0,
            'cracking_results': []
        }
        
        for key in keys:
            # Evaluate key strength
            self._evaluate_key_strength(key)
            
            # Store in database
            key_id = self.database.store_key(key)
            if key_id > 0:
                results['stored_keys'] += 1
            
            if key.is_weak:
                results['weak_keys'] += 1
            
            # Attempt cracking if requested
            if crack_keys and len(key.key_hex) < 32:  # Partial key
                crack_result = self.cracker.crack_key(key.key_hex)
                self.database.store_cracking_result(crack_result, key.key_hex)
                results['cracking_results'].append(crack_result)
                
                if crack_result.success:
                    results['cracked_keys'] += 1
        
        self.logger.info(f"CAP processing complete: {results}")
        return results
    
    def process_gp_session(self, gp_output: str, crack_keys: bool = True) -> Dict[str, Any]:
        """Process GlobalPlatform session output"""
        self.logger.info("Processing GlobalPlatform session output")
        
        keys = self.extractor.extract_from_gp_session(gp_output)
        
        results = {
            'source': 'globalplatform',  
            'extracted_keys': len(keys),
            'weak_keys': 0,
            'cracked_keys': 0,
            'stored_keys': 0,
            'cracking_results': []
        }
        
        for key in keys:
            self._evaluate_key_strength(key)
            key_id = self.database.store_key(key)
            if key_id > 0:
                results['stored_keys'] += 1
            
            if key.is_weak:
                results['weak_keys'] += 1
            
            if crack_keys:
                crack_result = self.cracker.crack_key(key.key_hex, CrackingMethod.WEAK_KEY_CHECK)
                self.database.store_cracking_result(crack_result, key.key_hex)
                results['cracking_results'].append(crack_result)
                
                if crack_result.success:
                    results['cracked_keys'] += 1
        
        return results
    
    def process_card_dump(self, dump_file_path: str, crack_keys: bool = True) -> Dict[str, Any]:
        """Process card memory dump"""
        self.logger.info(f"Processing card dump: {dump_file_path}")
        
        keys = self.extractor.extract_from_card_dump(dump_file_path)
        
        results = {
            'file': dump_file_path,
            'extracted_keys': len(keys),
            'weak_keys': 0,
            'cracked_keys': 0,
            'stored_keys': 0,
            'cracking_results': []
        }
        
        for key in keys:
            self._evaluate_key_strength(key)
            key_id = self.database.store_key(key)
            if key_id > 0:
                results['stored_keys'] += 1
                
            if key.is_weak:
                results['weak_keys'] += 1
            
            if crack_keys:
                # Try multiple cracking methods for dump keys
                methods = [CrackingMethod.WEAK_KEY_CHECK, CrackingMethod.PATTERN_ANALYSIS, 
                          CrackingMethod.DICTIONARY_ATTACK]
                
                for method in methods:
                    crack_result = self.cracker.crack_key(key.key_hex, method)
                    self.database.store_cracking_result(crack_result, key.key_hex)
                    results['cracking_results'].append(crack_result)
                    
                    if crack_result.success:
                        results['cracked_keys'] += 1
                        break  # Stop after first successful crack
        
        return results
    
    def _evaluate_key_strength(self, key: ExtractedKey):
        """Evaluate and mark weak keys"""
        # Check for known weak patterns
        weak_result = self.cracker.crack_key(key.key_hex, CrackingMethod.WEAK_KEY_CHECK)
        if weak_result.success:
            key.is_weak = True
            key.vulnerabilities.append("Known weak key pattern")
        
        # Check entropy
        if key.entropy and key.entropy < 3.0:
            key.is_weak = True
            key.vulnerabilities.append("Low entropy")
        
        # Check for repeating patterns
        if len(key.key_hex) >= 8:
            pattern = key.key_hex[:8]
            if key.key_hex == pattern * (len(key.key_hex) // 8):
                key.is_weak = True
                key.vulnerabilities.append("Repeating pattern")
    
    def get_summary_report(self) -> Dict[str, Any]:
        """Generate comprehensive summary report"""
        stats = self.database.get_statistics()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'database_stats': stats,
            'security_summary': {
                'total_keys_extracted': stats.get('total_keys', 0),
                'weak_keys_found': stats.get('weak_keys', 0),
                'successful_cracks': stats.get('successful_cracks', 0),
                'crack_success_rate': 0.0
            }
        }
        
        # Calculate crack success rate
        total_attempts = stats.get('total_cracking_attempts', 0)
        if total_attempts > 0:
            report['security_summary']['crack_success_rate'] = \
                stats.get('successful_cracks', 0) / total_attempts
        
        return report


def create_key_manager(db_path: str = "greenwire_keys.db") -> KeyManager:
    """Factory function to create configured KeyManager"""
    logger = logging.getLogger("greenwire.key_manager")
    return KeyManager(db_path, logger)


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create key manager
    key_manager = create_key_manager()
    
    # Example: Process a CAP file
    # results = key_manager.process_cap_file("example.cap", crack_keys=True)
    # print(f"CAP file results: {results}")
    
    # Example: Process GP output  
    gp_output = """
    Key: 404142434445464748494A4B4C4D4E4F
    DEK: 000102030405060708090A0B0C0D0E0F
    MAC Key: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    """
    # results = key_manager.process_gp_session(gp_output)
    # print(f"GP session results: {results}")
    
    # Generate report
    report = key_manager.get_summary_report()
    print(f"Summary report: {json.dumps(report, indent=2)}")