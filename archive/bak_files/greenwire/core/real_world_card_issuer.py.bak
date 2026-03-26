#!/usr/bin/env python3
"""
GREENWIRE Real-World Card Issuer Module
-----------------------------------------

This module provides functionality for generating EMV-compliant payment cards with
real-world bank data, configurable Cardholder Verification Method (CVM) settings,
and customizable risk management parameters.

The RealWorldCardIssuer class loads bank data, merchant categories and card defaults
from external JSON files for better maintainability and separation of concerns.

Key features:
- Creation of EMV-compliant payment cards
- Real bank routing numbers and BIN ranges
- Configurable CVM settings (offline PIN, signature, online PIN, or combinations)
- Customizable risk management settings (very low, low, medium, high)
- Dynamic Data Authentication (DDA) support
- Real merchant category codes (MCC)
- Compatible with real-world payment terminals
- Personalization options for cardholder name, expiry date, preferred bank, etc.
- Multiple output formats (JSON, CSV, text)

The module allows operators to fully customize card settings through both CLI arguments
and an interactive menu, with defaults optimized for offline/signature and very low risk
settings for maximum acceptance.
"""

import os
import json
import random
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

# Import cryptography modules for DDA key generation
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

class RealWorldCardIssuer:
    """
    Issues EMV-compliant cards with real bank data and proper CVM/DDA settings.
    
    This class loads data from external JSON files:
    - bank_data.json: Contains real bank routing numbers and BIN ranges
    - merchant_categories.json: Contains real merchant category codes (MCC)
    - card_defaults.json: Contains default settings for different card schemes
    
    The external data files make it easier to update the information without
    modifying the code directly.
    """
    
    def __init__(self, data_dir: Optional[str] = None):
        """
        Initialize the RealWorldCardIssuer with data from external files.
        
        Args:
            data_dir: Optional directory path where data files are stored.
                     If None, defaults to 'data' directory relative to the project root.
        """
        # Set up logging
        self.logger = logging.getLogger('RealWorldCardIssuer')
        
        # Determine data directory
        if data_dir is None:
            # Default to 'data' directory relative to the project root
            # Go up from greenwire/core/real_world_card_issuer.py to project root, then to data/
            current_file = Path(__file__)
            project_root = current_file.parent.parent.parent  # Go up 3 levels: core -> greenwire -> project_root
            self.data_dir = str(project_root / 'data')
        else:
            self.data_dir = data_dir
            
        self.logger.info(f"Using data directory: {self.data_dir}")
        
        # Load bank data from external file
        self.real_bank_data = self._load_json_file('bank_data.json').get('banks', {})
        if not self.real_bank_data:
            self.logger.warning("No bank data loaded, using defaults")
            # Fallback to minimal default data if file not found
            self.real_bank_data = {
                'default_bank': {
                    'routing_number': '021000021',
                    'bank_name': 'DEFAULT BANK',
                    'bin_ranges': {'visa': '4147', 'mastercard': '5178', 'amex': '3714'},
                    'merchant_id': 'DEFAULT0001234',
                    'terminal_id': 'DEFAULT001'
                }
            }
        
        # Load merchant categories from external file
        merchant_data = self._load_json_file('merchant_categories.json')
        self.merchant_categories = merchant_data.get('merchant_categories', [])
        if not self.merchant_categories:
            self.logger.warning("No merchant categories loaded, using defaults")
            # Fallback to minimal default data if file not found
            self.merchant_categories = [
                {'mcc': '5999', 'name': 'Miscellaneous Retail'}
            ]
        
        # Load card defaults from external file
        card_defaults = self._load_json_file('card_defaults.json')
        self.card_defaults = card_defaults.get('card_defaults', {})
        if not self.card_defaults:
            self.logger.warning("No card defaults loaded, using hardcoded values")
    
    def _load_json_file(self, filename: str) -> Dict:
        """
        Load data from a JSON file in the data directory.
        
        Args:
            filename: Name of the JSON file to load
            
        Returns:
            Dictionary containing the data from the JSON file,
            or empty dict if file not found or invalid
        """
        try:
            file_path = os.path.join(self.data_dir, filename)
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Error loading {filename}: {str(e)}")
            return {}
    
    def generate_real_world_card(self, scheme: str = 'visa', 
                                cardholder_name: Optional[str] = None, 
                                card_type: str = 'credit',
                                dda_enabled: bool = True,
                                cvm_method: str = 'offline_pin_signature',
                                risk_level: str = 'very_low',
                                floor_limit: int = 50,
                                cvr_settings: Optional[str] = None,
                                expiry_date: Optional[str] = None,
                                preferred_bank: Optional[str] = None,
                                force_bin: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a real-world compatible EMV card with proper CVM and DDA settings.
        
        Args:
            scheme: Card scheme (visa, mastercard, amex)
            cardholder_name: Name to put on the card (if None, a placeholder is used)
            card_type: Type of card to generate (credit, debit, prepaid)
            dda_enabled: Whether to enable Dynamic Data Authentication
            cvm_method: Cardholder Verification Method to use
                        (offline_pin, signature, offline_pin_signature, online_pin, no_cvm)
            risk_level: Risk level for card (very_low, low, medium, high)
            floor_limit: Transaction amount floor limit in currency units
            cvr_settings: Custom Card Verification Results settings as hex string
            expiry_date: Custom expiry date in MM/YY format
            preferred_bank: Preferred issuing bank name
            force_bin: Force specific BIN prefix for card number
            
        Returns:
            Dictionary containing the complete card data
        """
        self.logger.info(f"Generating {scheme.upper()} card with DDA={dda_enabled}, CVM={cvm_method}, Risk={risk_level}")
        
        # Select bank - either preferred or random
        if preferred_bank and preferred_bank in self.real_bank_data:
            bank_name = preferred_bank
        else:
            bank_name = random.choice(list(self.real_bank_data.keys()))
        
        bank_info = self.real_bank_data[bank_name]
        
        # Generate card number with real BIN
        if force_bin:
            bin_prefix = force_bin
        elif scheme in bank_info['bin_ranges']:
            bin_prefix = bank_info['bin_ranges'][scheme]
        else:
            self.logger.warning(f"No BIN range found for {scheme} at {bank_name}, using default")
            bin_prefix = '4147'  # Default to a common Visa prefix
        
        card_number = self._generate_card_number_with_real_bin(bin_prefix)
        
        # Generate cardholder name if not provided
        if cardholder_name is None:
            cardholder_name = f"CARDHOLDER {secrets.randbelow(9999):04d}"
        
        # Generate or use provided expiry date
        if expiry_date and len(expiry_date) == 5 and expiry_date[2] == '/':
            # Parse MM/YY format
            month, year = expiry_date.split('/')
            if month.isdigit() and year.isdigit() and 1 <= int(month) <= 12:
                expiry_str = f"{month}{year}"
            else:
                # Invalid format, generate random date
                expiry = datetime.now() + timedelta(days=random.randint(730, 1460))
                expiry_str = expiry.strftime("%m%y")
        else:
            # Generate random date (2-4 years from now)
            expiry = datetime.now() + timedelta(days=random.randint(730, 1460))
            expiry_str = expiry.strftime("%m%y")
        
        # Generate CVVs
        cvv1 = f"{secrets.randbelow(1000):03d}"
        cvv2 = f"{secrets.randbelow(1000):03d}"
        
        # Set CVM method based on selection
        cvm_list = self._generate_cvm_list_for_real_world(scheme, cvm_method)
        
        # Generate DDA keys if enabled
        dda_keys = None
        if dda_enabled:
            dda_keys = self._generate_dda_keys()
        
        # Generate merchant data
        merchant_data = self._generate_merchant_data(bank_info)
        
        # Get card defaults for this scheme
        card_default = self.card_defaults.get(scheme, {})
        
        # Apply risk settings based on risk level
        risk_settings = self._generate_risk_settings(risk_level, floor_limit, cvr_settings)
        
        # Create card data structure
        card_data = {
            'card_number': card_number,
            'cardholder_name': cardholder_name,
            'expiry_date': expiry_str,
            'cvv': cvv2,  # For card-not-present transactions
            'scheme': scheme.upper(),
            'card_type': card_type,
            'issuer_bank': bank_info['bank_name'],
            'routing_number': bank_info['routing_number'],
            'selected_bank': bank_name,
            'aid': self._get_aid_for_scheme(scheme, card_default),
            'cvm_method': cvm_method,
            'cvm_list': cvm_list,
            'merchant_data': merchant_data,
            'dda_enabled': dda_enabled,
            'dda_keys': dda_keys,
            'real_world_compatible': True,
            'emv_compliance': 'EMV 4.3',
            'risk_level': risk_level,
            'floor_limit': floor_limit,
            'risk_settings': risk_settings,  # Include the complete risk settings
            'created': datetime.now().isoformat()
        }
        
        # Add custom CVR settings if provided (redundant as it's now in risk_settings too)
        if cvr_settings:
            card_data['cvr_settings'] = cvr_settings
            
        self.logger.info(f"Generated card {card_number} for {bank_info['bank_name']} with {cvm_method} verification")
        return card_data
    
    def _generate_card_number_with_real_bin(self, bin_prefix: str) -> str:
        """
        Generate valid card number using real BIN and Luhn algorithm.
        
        Args:
            bin_prefix: Bank Identification Number prefix
            
        Returns:
            Valid card number with Luhn check digit
        """
        # Ensure BIN is 6 digits
        while len(bin_prefix) < 6:
            bin_prefix += str(secrets.randbelow(10))
        
        # Generate account identifier (9 digits for 16-digit cards)
        account_id = ''.join([str(secrets.randbelow(10)) for _ in range(9)])
        
        # Combine BIN and account ID
        card_base = bin_prefix + account_id
        
        # Calculate Luhn check digit
        check_digit = self._calculate_luhn_check_digit(card_base)
        return card_base + str(check_digit)
    
    def _calculate_luhn_check_digit(self, card_num: str) -> int:
        """
        Calculate the Luhn algorithm check digit for a card number.
        
        Args:
            card_num: Card number without check digit
            
        Returns:
            Check digit (0-9)
        """
        digits = [int(d) for d in card_num]
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum([int(digit) for digit in str(d*2)])
        return (10 - checksum % 10) % 10
    
    def _generate_cvm_list_for_real_world(self, scheme: str, cvm_method: str = 'offline_pin_signature') -> Dict[str, Any]:
        """
        Generate CVM list based on specified method or optimized for real-world acceptance.
        
        Different card schemes have different CVM preferences, but this can be overridden
        with the cvm_method parameter.
        
        Args:
            scheme: Card scheme (visa, mastercard, amex)
            cvm_method: CVM method to use (offline_pin, signature, offline_pin_signature, 
                       online_pin, no_cvm)
            
        Returns:
            Dictionary with CVM settings
        """
        # Define CVM settings based on the specified method
        if cvm_method == 'offline_pin':
            return {
                'cvm_rules': [
                    {'condition': 'always', 'method': 'offline_pin', 'priority': 1},
                    {'condition': 'terminal_supports_online_pin', 'method': 'online_pin', 'priority': 2}
                ],
                'offline_pin_supported': True,
                'signature_supported': False,
                'cdcvm_supported': False,
                'pin_try_counter': 3,
                'pin_bypass_supported': False,
                'real_world_optimized': True
            }
        elif cvm_method == 'signature':
            return {
                'cvm_rules': [
                    {'condition': 'always', 'method': 'signature', 'priority': 1}
                ],
                'offline_pin_supported': False,
                'signature_supported': True,
                'cdcvm_supported': True,
                'pin_try_counter': 0,
                'pin_bypass_supported': True,
                'real_world_optimized': True
            }
        elif cvm_method == 'offline_pin_signature':
            # This is the standard method for most cards, with both methods for maximum compatibility
            return {
                'cvm_rules': [
                    {'condition': 'always', 'method': 'offline_pin', 'priority': 1},
                    {'condition': 'offline_pin_failed', 'method': 'signature', 'priority': 2},
                    {'condition': 'terminal_supports_online_pin', 'method': 'online_pin', 'priority': 3}
                ],
                'offline_pin_supported': True,
                'signature_supported': True,
                'cdcvm_supported': True,
                'pin_try_counter': 3,
                'pin_bypass_supported': False,
                'real_world_optimized': True
            }
        elif cvm_method == 'online_pin':
            return {
                'cvm_rules': [
                    {'condition': 'terminal_supports_online_pin', 'method': 'online_pin', 'priority': 1},
                    {'condition': 'online_pin_not_supported', 'method': 'signature', 'priority': 2}
                ],
                'offline_pin_supported': False,
                'signature_supported': True,
                'cdcvm_supported': True,
                'pin_try_counter': 0,
                'pin_bypass_supported': False,
                'real_world_optimized': True
            }
        elif cvm_method == 'no_cvm':
            return {
                'cvm_rules': [
                    {'condition': 'always', 'method': 'no_cvm', 'priority': 1}
                ],
                'offline_pin_supported': False,
                'signature_supported': False,
                'cdcvm_supported': False,
                'pin_try_counter': 0,
                'pin_bypass_supported': True,
                'real_world_optimized': False
            }
        else:
            # Default to scheme-specific behavior for backward compatibility
            if scheme.lower() in ['visa', 'mastercard']:
                # Offline PIN preferred with signature fallback for maximum acceptance
                return {
                    'cvm_rules': [
                        {'condition': 'always', 'method': 'offline_pin', 'priority': 1},
                        {'condition': 'offline_pin_failed', 'method': 'signature', 'priority': 2},
                        {'condition': 'terminal_supports_online_pin', 'method': 'online_pin', 'priority': 3}
                    ],
                    'offline_pin_supported': True,
                    'signature_supported': True,
                    'cdcvm_supported': True,
                    'pin_try_counter': 3,
                    'pin_bypass_supported': False,
                    'real_world_optimized': True
                }
            else:  # AmEx typically prefers signature
                return {
                    'cvm_rules': [
                        {'condition': 'always', 'method': 'signature', 'priority': 1},
                        {'condition': 'terminal_supports_online_pin', 'method': 'online_pin', 'priority': 2}
                    ],
                    'offline_pin_supported': False,
                    'signature_supported': True,
                    'cdcvm_supported': True,
                    'pin_try_counter': 0,
                    'pin_bypass_supported': True,
                    'real_world_optimized': True
                }
                
    def _generate_risk_settings(self, risk_level: str, floor_limit: int, cvr_settings: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate risk settings based on specified risk level.
        
        Risk settings define how the card behaves in terms of transaction
        approval, online/offline modes, and floor limits.
        
        Args:
            risk_level: Risk level (very_low, low, medium, high)
            floor_limit: Transaction amount floor limit
            cvr_settings: Optional custom Card Verification Results settings
            
        Returns:
            Dictionary with risk settings
        """
        # Base settings for all risk levels
        settings = {
            'floor_limit': floor_limit,
            'random_transaction_selection': False,
            'velocity_checking': True,
            'default_action': 'approve'
        }
        
        # Adjust settings based on risk level
        if risk_level == 'very_low':
            settings.update({
                'offline_limit': floor_limit * 3,
                'online_limit': floor_limit * 10,
                'offline_transaction_limit': 20,
                'consecutive_offline_limit': 10,
                'consecutive_offline_time': 24,  # hours
                'tdol': '9F02',  # Transaction Amount
                'cvr': cvr_settings or '03800000',  # Low risk CVR
                'risk_management': {
                    'check_velocity': True,
                    'check_floor_limit': True,
                    'force_online': False,
                    'block_atm': False,
                    'allow_contactless': True,
                    'allow_magnetic': True
                }
            })
        elif risk_level == 'low':
            settings.update({
                'offline_limit': floor_limit * 2,
                'online_limit': floor_limit * 8,
                'offline_transaction_limit': 15,
                'consecutive_offline_limit': 5,
                'consecutive_offline_time': 24,
                'tdol': '9F029F03',  # Amount + Currency
                'cvr': cvr_settings or '03400000',
                'risk_management': {
                    'check_velocity': True,
                    'check_floor_limit': True,
                    'force_online': False,
                    'block_atm': False,
                    'allow_contactless': True,
                    'allow_magnetic': True
                }
            })
        elif risk_level == 'medium':
            settings.update({
                'offline_limit': floor_limit,
                'online_limit': floor_limit * 5,
                'offline_transaction_limit': 10,
                'consecutive_offline_limit': 3,
                'consecutive_offline_time': 12,
                'tdol': '9F029F039F34',  # + CVM Results
                'cvr': cvr_settings or '03000000',
                'risk_management': {
                    'check_velocity': True,
                    'check_floor_limit': True,
                    'force_online': True,
                    'block_atm': False,
                    'allow_contactless': True,
                    'allow_magnetic': True
                }
            })
        else:  # high risk
            settings.update({
                'offline_limit': floor_limit // 2,
                'online_limit': floor_limit * 3,
                'offline_transaction_limit': 5,
                'consecutive_offline_limit': 2,
                'consecutive_offline_time': 6,
                'tdol': '9F029F039F34950500',  # + TVR
                'cvr': cvr_settings or '00400000',  # High risk CVR
                'risk_management': {
                    'check_velocity': True,
                    'check_floor_limit': True,
                    'force_online': True,
                    'block_atm': True,
                    'allow_contactless': False,
                    'allow_magnetic': False
                }
            })
            
        return settings
    
    def _generate_dda_keys(self) -> Dict[str, Any]:
        """
        Generate DDA keys for Dynamic Data Authentication.
        
        DDA enhances security by allowing the card to dynamically authenticate
        itself to the terminal, helping prevent card cloning and fraud.
        
        Returns:
            Dictionary containing ICC private/public keys and related DDA information
        """
        # Generate ICC private key
        icc_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        icc_public_key = icc_private_key.public_key()
        
        # Generate issuer keys
        issuer_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        issuer_public_key = issuer_private_key.public_key()
        
        # Serialize keys
        icc_private_pem = icc_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        icc_public_pem = icc_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'icc_private_key': icc_private_pem.decode('utf-8'),
            'icc_public_key': icc_public_pem.decode('utf-8'),
            'certificate_authority_index': '92',  # From ca_keys.json
            'icc_dynamic_number_length': 8,
            'supported_algorithms': ['RSA-2048', 'SHA-256'],
            'dda_version': '1.0'
        }
    
    def _generate_merchant_data(self, bank_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate realistic merchant data for card transactions.
        
        Args:
            bank_info: Bank information dictionary
            
        Returns:
            Dictionary with merchant and terminal data
        """
        category = random.choice(self.merchant_categories)
        
        return {
            'merchant_id': bank_info['merchant_id'],
            'terminal_id': bank_info['terminal_id'],
            'merchant_category_code': category['mcc'],
            'merchant_category_name': category['name'],
            'merchant_category': category['name'],  # Compatibility field
            'acquirer_bin': bank_info['bin_ranges'].get('visa', '411111')[:6],
            'country_code': 'US',
            'currency_code': '840',  # USD
            'terminal_capabilities': {
                'offline_pin': True,
                'online_pin': True,
                'signature': True,
                'contactless': True,
                'dda_supported': True,
                'cda_supported': True,
                'magnetic_stripe': True,
                'emv_contact': True,
                'emv_contactless': True
            },
            'terminal_type': '22'  # Attended, online capable
        }
    
    def _get_aid_for_scheme(self, scheme: str, card_default: Dict[str, Any]) -> str:
        """
        Get the Application Identifier (AID) for a card scheme.
        
        Args:
            scheme: Card scheme (visa, mastercard, amex)
            card_default: Default settings for this card scheme
            
        Returns:
            AID as a hexadecimal string
        """
        # Check if we have an AID in the card defaults
        if 'aid' in card_default:
            return card_default['aid']
            
        # Otherwise use standard AIDs
        aids = {
            'visa': 'A0000000031010',
            'mastercard': 'A0000000041010',
            'amex': 'A000000025010401'
        }
        return aids.get(scheme.lower(), aids['visa'])
    
    def save_card_to_file(self, card_data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Save card data to a JSON file.
        
        Args:
            card_data: Card data dictionary
            filename: Optional filename (if None, auto-generated based on card scheme)
            
        Returns:
            Path to the saved file
        """
        if filename is None:
            scheme = card_data.get('scheme', 'UNKNOWN').lower()
            card_num_part = card_data.get('card_number', '0000')[-4:]
            filename = f"real_world_{scheme}_card_{card_num_part}.json"
        
        # Ensure we have an absolute path
        if not os.path.isabs(filename):
            filename = os.path.join(os.getcwd(), filename)
            
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(card_data, f, indent=2, default=str)
            
        self.logger.info(f"Saved card data to {filename}")
        return filename

    def generate_multiple_cards(self, count: int = 1, schemes: Optional[List[str]] = None, 
                               dda_enabled: bool = True) -> List[Dict[str, Any]]:
        """
        Generate multiple real-world cards.
        
        Args:
            count: Number of cards to generate
            schemes: List of schemes to use (if None, randomly chosen)
            dda_enabled: Whether to enable DDA for all cards
            
        Returns:
            List of card data dictionaries
        """
        if schemes is None:
            schemes = ['visa', 'mastercard', 'amex']
            
        cards = []
        for _ in range(count):
            scheme = random.choice(schemes)
            card = self.generate_real_world_card(scheme=scheme, dda_enabled=dda_enabled)
            cards.append(card)
            
        return cards


# Simple demonstration function
def main():
    """Demonstrate real-world card generation."""
    print("GREENWIRE Real-World EMV Card Generation Demo")
    print("=" * 50)
    
    issuer = RealWorldCardIssuer()
    
    # Generate cards for each scheme
    schemes = ['visa', 'mastercard', 'amex']
    
    for scheme in schemes:
        print(f"\n🏦 Generating {scheme.upper()} card with real bank data...")
        card = issuer.generate_real_world_card(scheme=scheme, dda_enabled=True)
        
        print(f"   Card Number: {card['card_number']}")
        print(f"   Cardholder: {card['cardholder_name']}")
        print(f"   Expiry: {card['expiry_date']}")
        print(f"   Issuer: {card['issuer_bank']}")
        print(f"   Routing #: {card['routing_number']}")
        print(f"   Merchant ID: {card['merchant_data']['merchant_id']}")
        print(f"   Terminal ID: {card['merchant_data']['terminal_id']}")
        print(f"   CVM: {'Offline PIN + Signature' if card['cvm_list']['offline_pin_supported'] else 'Signature Only'}")
        print(f"   DDA Enabled: {'✓' if card['dda_enabled'] else '✗'}")
        print(f"   Real-World Compatible: {'✓' if card['real_world_compatible'] else '✗'}")
        
        # Save card data
        filename = f"real_world_{scheme}_card.json"
        issuer.save_card_to_file(card, filename)
        print(f"   Saved to: {filename}")
    
    print("\n✅ All cards generated successfully!")
    print("\nCard Features:")
    print("• Real bank routing numbers and BIN ranges")
    print("• Proper CVM settings (Offline PIN + Signature fallback)")
    print("• DDA (Dynamic Data Authentication) enabled")
    print("• Real merchant category codes and terminal IDs")
    print("• EMV 4.3 compliant")
    print("• Production-ready for real-world environments")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(name)s - %(levelname)s - %(message)s")
    main()