#!/usr/bin/env python3
"""
EMV RFID Security Testing Module for GREENWIRE

This module provides comprehensive security testing for EMV contactless (RFID/NFC) cards,
focusing on vulnerabilities specific to contactless payment systems.
"""

import hashlib
import hmac
import json
import os
import random
import secrets
import struct
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

from core.logging_system import get_logger, handle_errors


class EMVRFIDSecurityTester:
    """Comprehensive EMV RFID security testing framework."""

    def __init__(self, verbose: bool = False):
        self.logger = get_logger()
        self.verbose = verbose

        # EMV RFID security test vectors and constants
        self.contactless_limits = {
            'visa': {'daily': 10000, 'single': 5000},  # cents
            'mastercard': {'daily': 10000, 'single': 5000},
            'amex': {'daily': 10000, 'single': 5000}
        }

        # Known EMV RFID vulnerabilities and test cases
        self.security_test_cases = {
            'relay_attack': self._test_relay_attack_protection,
            'transaction_velocity': self._test_transaction_velocity,
            'cryptogram_integrity': self._test_cryptogram_integrity,
            'cda_verification': self._test_cda_verification,
            'unpredictable_number': self._test_unpredictable_number,
            'offline_limits': self._test_offline_limits,
            'cvm_bypass': self._test_cvm_bypass_attempts,
            'skimming_protection': self._test_skimming_protection,
            'amount_manipulation': self._test_amount_manipulation_vectors,
            'cryptographic_downgrade': self._test_cryptographic_downgrade_paths,
            'cvv_bypass': self._test_cvv_bypass_resilience,
            'offline_data_auth_bypass': self._test_offline_data_authentication_bypass,
            'pin_bypass': self._test_pin_bypass_vulnerability
        }

    @handle_errors
    def run_comprehensive_security_test(self, device_info: Dict[str, Any],
                                      transaction_history: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run comprehensive EMV RFID security assessment.

        Args:
            device_info: Card/device information
            transaction_history: Previous transaction data for velocity testing

        Returns:
            Security assessment results
        """
        self.logger.info("Starting comprehensive EMV RFID security assessment")

        results = {
            'timestamp': datetime.now().isoformat(),
            'device_info': device_info,
            'test_results': {},
            'vulnerabilities': [],
            'recommendations': [],
            'risk_score': 0,
            'overall_security_rating': 'unknown'
        }

        # Run all security test cases
        for test_name, test_func in self.security_test_cases.items():
            try:
                if self.verbose:
                    print(f"Running {test_name} test...")

                test_result = test_func(device_info, transaction_history or [])
                results['test_results'][test_name] = test_result

                if test_result.get('vulnerable', False):
                    results['vulnerabilities'].append({
                        'test': test_name,
                        'severity': test_result.get('severity', 'medium'),
                        'description': test_result.get('description', ''),
                        'recommendation': test_result.get('recommendation', '')
                    })

                # Accumulate risk score
                results['risk_score'] += test_result.get('risk_score', 0)

            except Exception as e:
                self.logger.error(f"Error in {test_name} test: {e}")
                results['test_results'][test_name] = {
                    'error': str(e),
                    'vulnerable': False,
                    'risk_score': 0
                }

        # Calculate overall security rating
        results['overall_security_rating'] = self._calculate_security_rating(results['risk_score'])

        # Generate recommendations
        results['recommendations'] = self._generate_security_recommendations(results['vulnerabilities'])

        self.logger.info(f"Security assessment complete. Risk score: {results['risk_score']}")
        return results

    def _test_relay_attack_protection(self, device_info: Dict[str, Any],
                                    transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test protection against relay attacks."""
        result = {
            'vulnerable': False,
            'severity': 'high',
            'risk_score': 0,
            'description': 'Relay attack protection assessment',
            'recommendation': ''
        }

        # Check for transaction timing anomalies
        if len(transaction_history) >= 2:
            timings = [t.get('timestamp') for t in transaction_history[-10:] if t.get('timestamp')]
            if len(timings) >= 2:
                # Look for suspiciously regular timing (potential relay)
                intervals = []
                for i in range(1, len(timings)):
                    try:
                        t1 = datetime.fromisoformat(timings[i-1])
                        t2 = datetime.fromisoformat(timings[i])
                        intervals.append((t2 - t1).total_seconds())
                    except:
                        continue

                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)

                    # Low variance suggests automated/relay behavior
                    if variance < 10:  # seconds squared
                        result['vulnerable'] = True
                        result['risk_score'] = 8
                        result['description'] = 'Potential relay attack detected - suspicious transaction timing'
                        result['recommendation'] = 'Implement transaction time randomization and velocity checks'

        # Check for duplicate transaction patterns
        amounts = [t.get('amount', 0) for t in transaction_history[-20:]]
        if len(set(amounts)) <= 3 and len(amounts) >= 5:
            result['vulnerable'] = True
            result['risk_score'] = 6
            result['description'] = 'Limited transaction amount variety - potential automated attacks'
            result['recommendation'] = 'Enable amount randomization and pattern detection'

        return result

    def _test_transaction_velocity(self, device_info: Dict[str, Any],
                                transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test transaction velocity limits and enforcement."""
        result = {
            'vulnerable': False,
            'severity': 'medium',
            'risk_score': 0,
            'description': 'Transaction velocity limit assessment',
            'recommendation': ''
        }

        if not transaction_history:
            return result

        # Analyze transaction frequency
        recent_transactions = transaction_history[-50:]  # Last 50 transactions
        if len(recent_transactions) < 5:
            return result

        # Group by time windows
        now = datetime.now()
        windows = {
            '1_hour': 0,
            '24_hours': 0,
            '7_days': 0
        }

        for tx in recent_transactions:
            try:
                tx_time = datetime.fromisoformat(tx.get('timestamp', ''))
                age_hours = (now - tx_time).total_seconds() / 3600

                if age_hours <= 1:
                    windows['1_hour'] += 1
                if age_hours <= 24:
                    windows['24_hours'] += 1
                if age_hours <= 168:  # 7 days
                    windows['7_days'] += 1
            except:
                continue

        # Check velocity limits
        card_scheme = device_info.get('scheme', 'visa').lower()
        limits = self.contactless_limits.get(card_scheme, self.contactless_limits['visa'])

        # Flag suspicious velocity
        if windows['1_hour'] > 10:  # More than 10 transactions per hour
            result['vulnerable'] = True
            result['risk_score'] = 7
            result['description'] = f'High transaction velocity: {windows["1_hour"]} transactions in last hour'
            result['recommendation'] = 'Implement stricter velocity controls and temporary card blocking'

        elif windows['24_hours'] > 50:  # More than 50 transactions per day
            result['vulnerable'] = True
            result['risk_score'] = 5
            result['description'] = f'Elevated daily transaction count: {windows["24_hours"]} in last 24 hours'
            result['recommendation'] = 'Monitor for unusual spending patterns'

        return result

    def _test_cryptogram_integrity(self, device_info: Dict[str, Any],
                                 transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test application cryptogram integrity."""
        result = {
            'vulnerable': False,
            'severity': 'critical',
            'risk_score': 0,
            'description': 'Cryptogram integrity assessment',
            'recommendation': ''
        }

        # Check for cryptogram data in device info
        cryptogram_data = device_info.get('cryptogram_data', {})
        if not cryptogram_data:
            result['vulnerable'] = True
            result['risk_score'] = 9
            result['description'] = 'No cryptogram data available for verification'
            result['recommendation'] = 'Ensure cryptogram generation and verification is properly implemented'
            return result

        # Verify cryptogram format and consistency
        ac = cryptogram_data.get('application_cryptogram', '')
        cid = cryptogram_data.get('cryptogram_info_data', '')

        if len(ac) != 16:  # Should be 8 bytes hex
            result['vulnerable'] = True
            result['risk_score'] = 8
            result['description'] = f'Invalid cryptogram length: {len(ac)} (expected 16 hex chars)'
            result['recommendation'] = 'Verify cryptogram generation algorithm'

        # Check CID format
        if cid and len(cid) != 2:
            result['vulnerable'] = True
            result['risk_score'] = 6
            result['description'] = f'Invalid CID length: {len(cid)} (expected 2 hex chars)'
            result['recommendation'] = 'Check cryptogram information data format'

        # Test for predictable patterns (weak randomness)
        if ac and self._has_predictable_patterns(ac):
            result['vulnerable'] = True
            result['risk_score'] = 7
            result['description'] = 'Cryptogram shows predictable patterns - weak randomness'
            result['recommendation'] = 'Improve random number generation for cryptogram creation'

        return result

    def _test_cda_verification(self, device_info: Dict[str, Any],
                             transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test Combined Data Authentication (CDA) verification."""
        result = {
            'vulnerable': False,
            'severity': 'high',
            'risk_score': 0,
            'description': 'CDA verification assessment',
            'recommendation': ''
        }

        # Check if CDA is supported and enabled
        security_features = device_info.get('security_features', {})
        cda_enabled = security_features.get('cda', False)

        if not cda_enabled:
            result['vulnerable'] = True
            result['risk_score'] = 6
            result['description'] = 'Combined Data Authentication (CDA) not enabled'
            result['recommendation'] = 'Enable CDA for enhanced security in contactless transactions'
            return result

        # Verify CDA-related data is present
        cda_data = device_info.get('cda_data', {})
        if not cda_data:
            result['vulnerable'] = True
            result['risk_score'] = 7
            result['description'] = 'CDA enabled but no CDA data available'
            result['recommendation'] = 'Ensure CDA data structures are properly populated'

        # Check for required CDA elements
        required_elements = ['icc_public_key', 'signed_dynamic_data', 'ddol']
        missing_elements = [elem for elem in required_elements if elem not in cda_data]

        if missing_elements:
            result['vulnerable'] = True
            result['risk_score'] = 5
            result['description'] = f'Missing CDA elements: {", ".join(missing_elements)}'
            result['recommendation'] = 'Implement complete CDA data structure'

        return result

    def _test_unpredictable_number(self, device_info: Dict[str, Any],
                                 transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test unpredictable number generation quality."""
        result = {
            'vulnerable': False,
            'severity': 'medium',
            'risk_score': 0,
            'description': 'Unpredictable number quality assessment',
            'recommendation': ''
        }

        # Collect unpredictable numbers from transaction history
        un_numbers = []
        for tx in transaction_history[-20:]:  # Last 20 transactions
            un = tx.get('unpredictable_number', '')
            if un:
                try:
                    un_numbers.append(int(un, 16))
                except:
                    continue

        if len(un_numbers) < 5:
            result['vulnerable'] = True
            result['risk_score'] = 4
            result['description'] = 'Insufficient unpredictable number samples for analysis'
            result['recommendation'] = 'Ensure unpredictable numbers are generated for all transactions'
            return result

        # Test for randomness quality
        if self._detect_weak_randomness(un_numbers):
            result['vulnerable'] = True
            result['risk_score'] = 6
            result['description'] = 'Unpredictable numbers show weak randomness characteristics'
            result['recommendation'] = 'Improve random number generation algorithm'

        # Check for duplicates (should be extremely rare)
        if len(set(un_numbers)) < len(un_numbers):
            result['vulnerable'] = True
            result['risk_score'] = 8
            result['description'] = 'Duplicate unpredictable numbers detected'
            result['recommendation'] = 'Fix unpredictable number generation to ensure uniqueness'

        return result

    def _test_offline_limits(self, device_info: Dict[str, Any],
                           transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test offline transaction limits enforcement."""
        result = {
            'vulnerable': False,
            'severity': 'medium',
            'risk_score': 0,
            'description': 'Offline limits enforcement assessment',
            'recommendation': ''
        }

        card_scheme = device_info.get('scheme', 'visa').lower()
        limits = self.contactless_limits.get(card_scheme, self.contactless_limits['visa'])

        # Analyze offline transactions
        offline_transactions = [tx for tx in transaction_history if tx.get('online', True) == False]

        if not offline_transactions:
            return result  # No offline transactions to analyze

        # Check cumulative amounts
        total_offline_amount = sum(tx.get('amount', 0) for tx in offline_transactions[-20:])

        if total_offline_amount > limits['daily']:
            result['vulnerable'] = True
            result['risk_score'] = 5
            result['description'] = f'Offline transaction total exceeds daily limit: ${total_offline_amount/100:.2f}'
            result['recommendation'] = 'Strengthen offline transaction amount controls'

        # Check for large individual offline transactions
        max_offline = max((tx.get('amount', 0) for tx in offline_transactions), default=0)
        if max_offline > limits['single']:
            result['vulnerable'] = True
            result['risk_score'] = 4
            result['description'] = f'Large offline transaction detected: ${max_offline/100:.2f}'
            result['recommendation'] = 'Implement per-transaction offline limits'

        return result

    def _test_cvm_bypass_attempts(self, device_info: Dict[str, Any],
                                transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test for Cardholder Verification Method (CVM) bypass attempts."""
        result = {
            'vulnerable': False,
            'severity': 'high',
            'risk_score': 0,
            'description': 'CVM bypass attempt detection',
            'recommendation': ''
        }

        # Analyze CVM results in transaction history
        cvm_bypass_indicators = []

        for tx in transaction_history[-50:]:
            cvm_result = tx.get('cvm_result', '')
            amount = tx.get('amount', 0)
            cvm_list = tx.get('cvm_list', '')

            # Check for suspicious CVM results
            if cvm_result == '00':  # No CVM performed
                if amount > 2500:  # High-value transaction without CVM
                    cvm_bypass_indicators.append('high_value_no_cvm')

            # Check for CVM bypass patterns
            if 'signature' in cvm_list.lower() and amount < 2500:
                cvm_bypass_indicators.append('unnecessary_signature')

        if cvm_bypass_indicators:
            result['vulnerable'] = True
            result['risk_score'] = 7
            result['description'] = f'CVM bypass patterns detected: {len(set(cvm_bypass_indicators))} unique indicators'
            result['recommendation'] = 'Review CVM policy and ensure proper enforcement'

        return result

    def _test_skimming_protection(self, device_info: Dict[str, Any],
                                transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test protection against skimming attacks."""
        result = {
            'vulnerable': False,
            'severity': 'high',
            'risk_score': 0,
            'description': 'Skimming protection assessment',
            'recommendation': ''
        }

        # Check for physical security features
        physical_security = device_info.get('physical_security', {})

        # Verify chip protection
        if not physical_security.get('chip_protection', False):
            result['vulnerable'] = True
            result['risk_score'] = 6
            result['description'] = 'Chip not protected against physical attacks'
            result['recommendation'] = 'Implement chip shielding and tamper detection'

        # Check for contactless shielding
        if not physical_security.get('nfc_shielding', False):
            result['vulnerable'] = True
            result['risk_score'] = 5
            result['description'] = 'No NFC shielding detected'
            result['recommendation'] = 'Add Faraday shielding for contactless interface'

        # Analyze transaction patterns for skimming indicators
        locations = [tx.get('location', '') for tx in transaction_history[-20:]]
        unique_locations = set(locations)

        # Suspiciously few unique locations might indicate cloned card usage
        if len(unique_locations) <= 2 and len(locations) >= 10:
            result['vulnerable'] = True
            result['risk_score'] = 4
            result['description'] = 'Limited transaction locations - possible cloned card usage'
            result['recommendation'] = 'Monitor for unusual geographic patterns'

        return result

    def _test_amount_manipulation_vectors(self, device_info: Dict[str, Any],
                                          transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess transaction streams for amount and currency manipulation attempts."""
        result = {
            'vulnerable': False,
            'severity': 'high',
            'risk_score': 0,
            'description': 'Amount & currency manipulation analysis',
            'recommendation': ''
        }

        if not transaction_history:
            result['description'] = 'No transaction history available for analysis'
            result['recommendation'] = 'Capture recent transactions before running this test'
            return result

        anomalies: List[str] = []
        base_currency = device_info.get('currency_code', '').upper()
        amounts = [tx.get('amount', 0) for tx in transaction_history if isinstance(tx.get('amount', 0), (int, float))]
        positive_amounts = [amt for amt in amounts if amt > 0]
        baseline = (sum(positive_amounts) / len(positive_amounts)) if positive_amounts else 0

        for tx in transaction_history[-40:]:
            amount = tx.get('amount', 0)
            currency = str(tx.get('currency_code', '')).upper()

            if amount == 0:
                anomalies.append('zero_amount')
            elif amount < 0:
                anomalies.append('negative_amount')
            elif baseline and amount > baseline * 3:
                anomalies.append('inflated_amount')
            elif baseline and amount < baseline * 0.2:
                anomalies.append('deflated_amount')

            if tx.get('converted_amount') or (base_currency and currency and currency != base_currency):
                anomalies.append('currency_swap')

            if tx.get('forced_authorization'):
                anomalies.append('forced_authorization')

            if abs(amount) > 999_999:
                anomalies.append('overflow_amount')

        anomalies = list(dict.fromkeys(anomalies))

        if anomalies:
            result['vulnerable'] = True
            result['risk_score'] = min(9, 4 + len(anomalies))
            high_severity_indicators = {'overflow_amount', 'forced_authorization', 'currency_swap', 'negative_amount'}
            if high_severity_indicators.intersection(anomalies):
                result['severity'] = 'critical'
            result['description'] = f"Detected amount manipulation indicators: {', '.join(anomalies)}"
            result['recommendation'] = 'Enable terminal-side amount verification and enforce currency locking'
        else:
            result['description'] = 'No amount manipulation indicators detected'
            result['recommendation'] = 'Continue monitoring for anomalous amount patterns'

        return result

    def _test_cryptographic_downgrade_paths(self, device_info: Dict[str, Any],
                                            transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check whether transactions are downgrading to weaker cryptographic paths."""
        result = {
            'vulnerable': False,
            'severity': 'critical',
            'risk_score': 0,
            'description': 'Cryptographic downgrade assessment',
            'recommendation': ''
        }

        security_features = device_info.get('security_features', {})
        protocol_info = device_info.get('protocol_negotiation', {})
        downgrade_indicators: List[str] = []

        if not security_features.get('dda', False):
            downgrade_indicators.append('dda_disabled')
        if not security_features.get('cda', False):
            downgrade_indicators.append('cda_disabled')
        if protocol_info.get('downgrade_allowed', False):
            downgrade_indicators.append('terminal_allows_downgrade')
        default_profile = str(protocol_info.get('default_profile', '')).lower()
        if default_profile in {'sda', 'magstripe'}:
            downgrade_indicators.append('defaulting_to_static_auth')

        downgraded_transactions = [
            tx for tx in transaction_history[-40:]
            if str(tx.get('auth_method', '')).lower() in {'sda', 'static', 'magstripe'}
            or tx.get('dynamic_data_auth', True) is False
        ]

        if downgraded_transactions:
            downgrade_indicators.append('transactions_using_static_auth')

        if downgrade_indicators:
            result['vulnerable'] = True
            result['risk_score'] = min(10, 6 + len(downgrade_indicators))
            result['description'] = f"Cryptographic downgrade paths detected: {', '.join(downgrade_indicators)}"
            result['recommendation'] = 'Enforce CDA/DDA for contactless operations and disable SDA fallbacks'
        else:
            result['description'] = 'No cryptographic downgrade behaviour detected'
            result['recommendation'] = 'Maintain CDA/DDA enforcement and monitor negotiated profiles'

        return result

    def _test_cvv_bypass_resilience(self, device_info: Dict[str, Any],
                                    transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect approvals that bypass CVV verification or expose weak CVV data."""
        result = {
            'vulnerable': False,
            'severity': 'high',
            'risk_score': 0,
            'description': 'CVV verification bypass assessment',
            'recommendation': ''
        }

        track_data = device_info.get('track_data', {})
        cvv_value = str(track_data.get('cvv', '')).strip()
        cvv_present = track_data.get('cvv_present', True)

        bypassed_approvals = [
            tx for tx in transaction_history[-40:]
            if not tx.get('cvv_verified', True) and str(tx.get('auth_response', '')).lower() == 'approved'
        ]

        weak_cvv_values = {'000', '999', '123', '     '}
        if bypassed_approvals or not cvv_present or cvv_value in weak_cvv_values:
            result['vulnerable'] = True
            result['risk_score'] = 6 + min(len(bypassed_approvals), 4)
            result['description'] = 'Contactless approvals bypassed CVV verification'
            if cvv_value in weak_cvv_values or not cvv_present:
                result['description'] += ' and track CVV data appears weak'
            result['recommendation'] = 'Require CVV verification for card-not-present mirroring and refresh track data'
        else:
            result['description'] = 'CVV verification behaviour appears normal'
            result['recommendation'] = 'Continue enforcing CVV checks for fallback scenarios'

        return result

    def _test_offline_data_authentication_bypass(self, device_info: Dict[str, Any],
                                                 transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check if offline transactions skip data authentication requirements."""
        result = {
            'vulnerable': False,
            'severity': 'high',
            'risk_score': 0,
            'description': 'Offline data authentication enforcement',
            'recommendation': ''
        }

        security_features = device_info.get('security_features', {})
        offline_transactions = [tx for tx in transaction_history if tx.get('online', True) is False]

        if not offline_transactions:
            result['description'] = 'No offline transactions detected for analysis'
            result['recommendation'] = 'Capture offline samples to verify authentication behaviour'
            return result

        bypass_count = sum(
            1 for tx in offline_transactions
            if not tx.get('offline_auth_performed', True)
            or str(tx.get('auth_method', '')).lower() in {'none', 'skip'}
        )

        if (not security_features.get('dda', False) and not security_features.get('cda', False)) or bypass_count:
            result['vulnerable'] = True
            result['risk_score'] = min(9, 5 + bypass_count)
            result['description'] = 'Offline transactions detected without data authentication'
            result['recommendation'] = 'Enable DDA/CDA and prevent approvals when offline authentication is skipped'
        else:
            result['description'] = 'Offline transactions performed with proper authentication'
            result['recommendation'] = 'Keep monitoring offline approval paths'

        return result

    def _test_pin_bypass_vulnerability(self, device_info: Dict[str, Any],
                                       transaction_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess whether high-value transactions avoid required PIN CVM."""
        result = {
            'vulnerable': False,
            'severity': 'high',
            'risk_score': 0,
            'description': 'PIN bypass assessment',
            'recommendation': ''
        }

        cvm_capabilities = device_info.get('cvm_capabilities', {})
        pin_supported = cvm_capabilities.get('pin_supported', True)
        pin_attempts = cvm_capabilities.get('pin_attempts_remaining', 3)

        high_value_transactions = [tx for tx in transaction_history[-40:] if tx.get('amount', 0) >= 4000]
        bypass_transactions = [
            tx for tx in high_value_transactions
            if tx.get('cvm_required', False)
            and str(tx.get('cvm_result', '')).upper() in {'00', 'NO_CVM'}
        ]

        if not pin_supported or pin_attempts == 0:
            bypass_transactions.append({'reason': 'pin_not_supported'})

        if bypass_transactions:
            result['vulnerable'] = True
            result['risk_score'] = min(8, 4 + len(bypass_transactions))
            result['description'] = 'High-value transactions completed without PIN verification'
            result['recommendation'] = 'Require PIN CVM or CDCVM for elevated contactless amounts'
        else:
            result['description'] = 'PIN verification paths appear enforced for high-value taps'
            result['recommendation'] = 'Maintain PIN thresholds and monitor CDCVM fallbacks'

        return result

    def _has_predictable_patterns(self, hex_string: str) -> bool:
        """Check if hex string has predictable patterns."""
        if len(hex_string) < 8:
            return False

        # Convert to bytes for analysis
        try:
            data = bytes.fromhex(hex_string)
        except:
            return True  # Invalid hex is considered predictable

        # Check for sequential patterns
        for i in range(len(data) - 3):
            if data[i:i+4] == bytes(range(data[i], data[i] + 4)):
                return True

        # Check for repeated patterns
        if len(set(data)) < len(data) * 0.7:  # Less than 70% unique bytes
            return True

        # Check entropy
        entropy = self._calculate_entropy(data)
        if entropy < 3.5:  # Low entropy threshold
            return True

        return False

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0

        entropy = 0.0
        for i in range(256):
            p = data.count(i) / len(data)
            if p > 0:
                entropy -= p * (p.bit_length() - 1)  # Approximation of log2

        return entropy

    def _detect_weak_randomness(self, numbers: List[int]) -> bool:
        """Detect weak randomness in a sequence of numbers."""
        if len(numbers) < 10:
            return False

        # Check for sequential patterns
        for i in range(len(numbers) - 2):
            if numbers[i+1] - numbers[i] == numbers[i+2] - numbers[i+1]:
                return True

        # Check for low entropy
        entropy = self._calculate_entropy(bytes(str(n) for n in numbers))
        if entropy < 2.0:
            return True

        return False

    def _calculate_security_rating(self, risk_score: int) -> str:
        """Calculate overall security rating from risk score."""
        if risk_score >= 25:
            return 'critical'
        elif risk_score >= 15:
            return 'high'
        elif risk_score >= 8:
            return 'medium'
        elif risk_score >= 3:
            return 'low'
        else:
            return 'excellent'

    def _generate_security_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on vulnerabilities found."""
        recommendations = []

        severity_groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }

        for vuln in vulnerabilities:
            severity_groups[vuln['severity']].append(vuln)

        # Critical recommendations first
        if severity_groups['critical']:
            recommendations.append("🚨 CRITICAL: Address critical vulnerabilities immediately:")
            for vuln in severity_groups['critical']:
                recommendations.append(f"  • {vuln['recommendation']}")

        # High priority
        if severity_groups['high']:
            recommendations.append("⚠️ HIGH PRIORITY: Implement these security improvements:")
            for vuln in severity_groups['high']:
                recommendations.append(f"  • {vuln['recommendation']}")

        # Medium priority
        if severity_groups['medium']:
            recommendations.append("📋 MEDIUM PRIORITY: Consider these enhancements:")
            for vuln in severity_groups['medium']:
                recommendations.append(f"  • {vuln['recommendation']}")

        # General recommendations
        if not vulnerabilities:
            recommendations.append("✅ No significant vulnerabilities detected. Continue monitoring.")
        else:
            recommendations.append("🔍 Regular security assessments recommended.")

        return recommendations


def run_emv_rfid_security_assessment(device_info: Dict[str, Any] = None,
                                   transaction_history: List[Dict[str, Any]] = None,
                                   verbose: bool = False) -> Dict[str, Any]:
    """Run EMV RFID security assessment with sample data if none provided."""

    if device_info is None:
        # Sample device info for testing
        device_info = {
            'scheme': 'visa',
            'card_type': 'contactless',
            'currency_code': 'USD',
            'security_features': {
                'sda': True,
                'dda': False,
                'cda': False
            },
            'physical_security': {
                'chip_protection': False,
                'nfc_shielding': False
            },
            'cryptogram_data': {
                'application_cryptogram': 'A1B2C3D4E5F6G7H8',
                'cryptogram_info_data': '80'
            },
            'track_data': {
                'cvv': '000',
                'cvv_present': False
            },
            'protocol_negotiation': {
                'supported_profiles': ['SDA', 'DDA'],
                'default_profile': 'SDA',
                'downgrade_allowed': True
            },
            'cvm_capabilities': {
                'pin_supported': False,
                'offline_pin': False,
                'pin_attempts_remaining': 0
            }
        }

    if transaction_history is None:
        # Generate sample transaction history
        transaction_history = []
        base_time = datetime.now()

        for i in range(30):
            transaction = {
                'timestamp': (base_time + timedelta(minutes=i * 2)).isoformat(),
                'amount': random.choice([0, -500, random.randint(100, 12000)]),
                'online': random.choice([True, False]),
                'location': random.choice(['Store A', 'Store B']),
                'unpredictable_number': secrets.token_hex(4),
                'cvm_result': random.choice(['00', '01', 'NO_CVM']),
                'cvm_list': random.choice(['signature', 'pin', 'cdcvm']),
                'currency_code': random.choice(['USD', 'JPY']),
                'converted_amount': random.choice([None, 45000]),
                'cvv_verified': random.choice([True, False]),
                'auth_response': random.choice(['approved', 'declined']),
                'offline_auth_performed': random.choice([True, False]),
                'auth_method': random.choice(['sda', 'cda', 'none']),
                'cvm_required': random.choice([True, False]),
                'forced_authorization': random.choice([True, False])
            }
            transaction_history.append(transaction)

    tester = EMVRFIDSecurityTester(verbose=verbose)
    return tester.run_comprehensive_security_test(device_info, transaction_history)


if __name__ == '__main__':
    # Example usage
    results = run_emv_rfid_security_assessment(verbose=True)
    print(json.dumps(results, indent=2, default=str))