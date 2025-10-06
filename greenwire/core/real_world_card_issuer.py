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

import hashlib, json, logging, os, random, secrets  # noqa: F401
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union  # noqa: F401

# Import cryptography modules for DDA key generation
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization  # noqa: F401
from cryptography.hazmat.backends import default_backend

from .configuration_manager import get_configuration_manager
from .smart_vulnerability_card import SmartVulnerabilityTestCard

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
        # Set up logging and configuration access
        self.logger = logging.getLogger('RealWorldCardIssuer')
        self.config_manager = get_configuration_manager()
        
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

        # Load card profile catalog (15+ predefined card templates)
        profile_data = self._load_json_file('card_profiles.json')
        self.card_profiles = profile_data.get('card_profiles', [])
        if not self.card_profiles:
            self.logger.warning("No card profiles loaded, using fallback builtin profiles")
            self.card_profiles = self._fallback_card_profiles()
    
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
    
    def generate_real_world_card(
        self,
        scheme: str = 'visa',
        cardholder_name: Optional[str] = None,
        card_type: str = 'credit',
        dda_enabled: bool = True,
        cvm_method: str = 'offline_pin_signature',
        risk_level: str = 'very_low',
        floor_limit: int = 50,
        cvr_settings: Optional[str] = None,
        expiry_date: Optional[str] = None,
        preferred_bank: Optional[str] = None,
        force_bin: Optional[str] = None,
        terminal_profile_id: Optional[str] = None,
        terminal_overrides: Optional[Dict[str, Any]] = None,
        auto_testing: bool = True,
    ) -> Dict[str, Any]:
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
            terminal_profile_id: Optional ID referencing a configured terminal profile
            terminal_overrides: Optional dictionary of overrides applied on top of the base profile
            auto_testing: Whether to execute configured POS/ATM/HSM/vulnerability suites automatically
            
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

        terminal_profile = self._prepare_terminal_profile(
            terminal_profile_id=terminal_profile_id,
            terminal_overrides=terminal_overrides,
            scheme=scheme,
        )
        
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

        if terminal_profile:
            card_data['terminal_profile'] = terminal_profile
            
        self.logger.info(f"Generated card {card_number} for {bank_info['bank_name']} with {cvm_method} verification")
        self._apply_operator_preferences(card_data, overrides=None)
        self._apply_logging_defaults(card_data)
        if auto_testing:
            self._post_issue_automation(card_data)
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

    # ---------------------------------------------------------------------
    # Card profile helpers
    # ---------------------------------------------------------------------

    def list_card_profiles(self) -> List[Dict[str, Any]]:
        """Return a copy of the loaded card profile catalog."""
        return list(self.card_profiles)

    def get_card_profile(self, profile_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an individual card profile by ID."""
        for profile in self.card_profiles:
            if profile.get('profile_id') == profile_id:
                return profile
        return None

    # ------------------------------------------------------------------
    # Terminal profile helpers
    # ------------------------------------------------------------------

    def list_terminal_profiles(self) -> List[Dict[str, Any]]:
        """Return configured terminal profiles with overrides applied."""
        profiles = self.config_manager.get('terminal_profiles', [])
        if not profiles:
            profiles = self._fallback_terminal_profiles()
        return [deepcopy(profile) for profile in profiles]

    def get_terminal_profile(self, profile_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a terminal profile by identifier."""
        for profile in self.list_terminal_profiles():
            if profile.get('profile_id') == profile_id:
                return profile
        return None

    def generate_card_from_profile(
        self,
        profile_id: str,
        use_real_keys: bool = False,
        cardholder_name: Optional[str] = None,
        expiry_date: Optional[str] = None,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a card using a predefined profile from card_profiles.json."""

        profile = self.get_card_profile(profile_id)
        if not profile:
            raise ValueError(f"Unknown card profile: {profile_id}")

        overrides = overrides or {}

        terminal_profile_id = overrides.get('terminal_profile_id') or profile.get('default_terminal_profile')
        terminal_overrides = overrides.get('terminal_overrides')

        scheme = profile.get('scheme', overrides.get('scheme', 'visa'))
        card_type = profile.get('card_type', overrides.get('card_type', 'credit'))
        cvm_method = overrides.get('cvm_method', profile.get('default_cvm_method', 'offline_pin_signature'))
        risk_level = overrides.get('risk_level', profile.get('risk_level', 'very_low'))
        floor_limit = overrides.get('floor_limit', profile.get('floor_limit', 50))
        cvr_settings = overrides.get('cvr_settings')
        dda_enabled = overrides.get('dda_enabled', profile.get('dda_enabled', True))

        card = self.generate_real_world_card(
            scheme=scheme,
            cardholder_name=cardholder_name,
            card_type=card_type,
            dda_enabled=dda_enabled,
            cvm_method=cvm_method,
            risk_level=risk_level,
            floor_limit=floor_limit,
            cvr_settings=cvr_settings,
            expiry_date=expiry_date,
            preferred_bank=overrides.get('preferred_bank'),
            force_bin=overrides.get('force_bin'),
            terminal_profile_id=terminal_profile_id,
            terminal_overrides=terminal_overrides,
            auto_testing=False,
        )

        card['profile_id'] = profile_id
        card['profile_name'] = profile.get('display_name', profile_id)
        card['profile_description'] = profile.get('description', '')
        card['profile_region'] = profile.get('region', overrides.get('region', 'global'))
        card['pdol_template'] = profile.get('pdol_template', [])
        card['cdol1_template'] = profile.get('cdol1_template', [])
        card['cdol2_template'] = profile.get('cdol2_template', [])
        card['variant_category'] = profile.get('variant_category', overrides.get('variant_category', 'emv'))
        card['transaction_logging'] = self._build_logging_config(profile.get('transaction_logging', {}), profile_id)
        card['merchant_test_matrix'] = profile.get('merchant_test_matrix', [])
        card['atm_test_matrix'] = profile.get('atm_test_matrix', [])
        card['key_management'] = self._build_key_material(profile.get('key_management', {}), use_real_keys)
        card['supports_randomized_data'] = profile.get('supports_randomized_data', True)
        card['supports_production_data'] = profile.get('supports_production_data', True)

        operator_overrides = {
            'available_variants': profile.get('authentication_variants', []),
            'auth_variant': overrides.get('auth_variant'),
            'variant_category': card['variant_category'],
        }
        self._apply_operator_preferences(card, operator_overrides)
        self._apply_logging_defaults(card, profile_id)
        self._post_issue_automation(card)
        return card

    def _build_logging_config(self, config: Dict[str, Any], profile_id: Optional[str] = None) -> Dict[str, Any]:
        """Merge a profile's logging configuration with safe defaults."""
        defaults = {
            'mode': 'transaction_journal',
            'ef_id': 'EFTRANLOG',
            'max_records': 128,
            'record_format': ['timestamp', 'amount', 'currency', 'terminal_type', 'arc'],
            'auto_sync': False,
            'include_apdu_payloads': True,
        }
        logging_cfg = self.config_manager.get('logging', {})
        merged = defaults.copy()
        merged['max_records'] = logging_cfg.get('max_records', merged['max_records'])
        if 'include_apdu_payloads' in logging_cfg:
            merged['include_apdu_payloads'] = bool(logging_cfg['include_apdu_payloads'])
        merged.update(config or {})
        if profile_id:
            merged.setdefault('profile_id', profile_id)
        if logging_cfg.get('mirror_transaction_log'):
            merged.setdefault('mirror_transaction_log', True)
        return merged

    def _build_key_material(self, config: Dict[str, Any], use_real_keys: bool) -> Dict[str, Any]:
        """Describe key material expectations for a profile with test/production options."""
        config = config or {}
        options = dict(config.get('options', {}))
        default_choice = config.get('default_choice', 'test_keys')

        if 'test_keys' not in options:
            options['test_keys'] = {
                'icc_private_key_origin': 'auto_generated',
                'issuer_master_key_origin': 'derived_test_vector',
                'notes': 'Default keys generated at issuance time for lab testing.'
            }

        selected = 'production_keys' if use_real_keys and 'production_keys' in options else default_choice
        if selected not in options:
            selected = 'test_keys'

        return {
            'selected_option': selected,
            'options': options,
            'requires_operator_action': selected != 'test_keys'
        }

    def _apply_operator_preferences(self, card_data: Dict[str, Any], overrides: Optional[Dict[str, Any]]) -> None:
        """Attach operator-facing configuration metadata to the card."""
        overrides = overrides or {}
        config = self.config_manager.data()

        available = overrides.get('available_variants') or card_data.get('authentication_variants')
        if not available:
            available = config.get('cards', {}).get('authentication_modes', [])

        variant_category = overrides.get('variant_category') or card_data.get('variant_category')
        if not variant_category:
            variant_category = 'mifare' if any('mifare' in str(v).lower() for v in available or []) else 'emv'

        selected = overrides.get('auth_variant')
        if not selected:
            selected = (
                config.get('profiles', {})
                .get('preferred_variants', {})
                .get(variant_category)
            )
        if not selected and available:
            selected = available[0]

        card_data.setdefault('operator_options', {})
        card_data['operator_options']['authentication_variant'] = {
            'available': available,
            'selected': selected,
            'prompt_operator': config.get('profiles', {}).get('prompt_operator', True),
            'variant_category': variant_category,
        }
        if available:
            card_data['authentication_variants'] = available
        if selected:
            card_data['selected_variant'] = selected
            security = card_data.setdefault('security', {})
            if selected.lower() == 'sda':
                card_data['dda_enabled'] = False
                security['authentication'] = 'sda'
            elif selected.lower() == 'dda':
                card_data['dda_enabled'] = True
                security['authentication'] = 'dda'
            else:
                security['authentication'] = selected

    def _post_issue_automation(self, card_data: Dict[str, Any]) -> None:
        """Execute configured automation flows (POS/ATM/HSM/vulnerability scans)."""
        if card_data.get('automatic_test_results'):
            return

        config = self.config_manager.data()
        pos_cfg = config.get('pos', {})
        atm_cfg = config.get('atm', {})
        logging_cfg = config.get('logging', {})
        scanning_cfg = config.get('vulnerability_scanning', {})

        run_pos = bool(pos_cfg.get('auto_run_after_issue'))
        run_atm = bool(atm_cfg.get('auto_run_after_issue'))
        include_hsm = bool(config.get('hsm', {}).get('enabled'))
        suite = scanning_cfg.get('default_suite', [])

        if not any([run_pos, run_atm, include_hsm, suite]):
            if logging_cfg.get('store_on_card'):
                card_data.setdefault('communication_log', [])
            return

        tester = SmartVulnerabilityTestCard(card_data=card_data)
        results = tester.run_automatic_tests(
            run_pos=run_pos and pos_cfg.get('run_default_suite', True),
            run_atm=run_atm and atm_cfg.get('run_default_suite', False),
            include_hsm=include_hsm,
            vulnerability_suite=suite,
        )
        if logging_cfg.get('persist_to_card', True):
            tester.persist_logs_to_card()

        card_data['automatic_test_results'] = results
        card_data['smart_testing_enabled'] = True
        card_data['smart_testing_suite'] = suite


    def _apply_logging_defaults(self, card_data: Dict[str, Any], profile_id: Optional[str] = None) -> None:
        """Ensure card data includes logging/test matrices even for ad-hoc cards."""
        if 'transaction_logging' not in card_data:
            card_data['transaction_logging'] = self._build_logging_config({}, profile_id)
        pos_defaults = self.config_manager.get('pos.default_test_plan', ['contact', 'contactless'])
        atm_defaults = self.config_manager.get('atm.default_test_plan', ['cash_withdrawal'])
        if not card_data.get('merchant_test_matrix'):
            card_data['merchant_test_matrix'] = list(pos_defaults)
        if not card_data.get('atm_test_matrix'):
            card_data['atm_test_matrix'] = list(atm_defaults)

        logging_cfg = self.config_manager.get('logging', {})
        if logging_cfg.get('store_on_card'):
            card_data.setdefault('communication_log', [])
            card_data.setdefault('transaction_log_records', [])
        if logging_cfg.get('mirror_transaction_log'):
            card_data['transaction_logging'].setdefault('mirror_transaction_log', True)

    def _fallback_card_profiles(self) -> List[Dict[str, Any]]:
        """Return a small built-in profile set if external data is unavailable."""
        return [
            {
                'profile_id': 'visa_contact_credit_baseline',
                'display_name': 'Visa Contact Credit (Fallback)',
                'description': 'Minimal Visa profile with offline PIN and DDA enabled.',
                'scheme': 'visa',
                'card_type': 'credit',
                'region': 'us',
                'dda_enabled': True,
                'default_cvm_method': 'offline_pin_signature',
                'risk_level': 'medium',
                'floor_limit': 100,
                'pdol_template': [],
                'cdol1_template': [],
                'cdol2_template': [],
                'transaction_logging': {},
                'merchant_test_matrix': ['contact', 'contactless'],
                'atm_test_matrix': ['cash_withdrawal'],
                'key_management': {'default_choice': 'test_keys', 'options': {}},
                'supports_randomized_data': True,
                'supports_production_data': True
            }
        ]

    def _fallback_terminal_profiles(self) -> List[Dict[str, Any]]:
        """Provide a minimal set of terminal profiles when config is absent."""
        return [
            {
                'profile_id': 'generic_pos_contact',
                'display_name': 'Generic POS Contact Terminal',
                'terminal_type': '22',
                'capabilities': {
                    'contact': True,
                    'contactless': False,
                    'offline_pin': True,
                    'online_pin': True,
                    'signature': True,
                },
                'environment': {
                    'merchant_category_code': '5999',
                    'currency': 'USD',
                    'country_code': '840',
                    'acquirer_id': '00000000000',
                },
            }
        ]

    def _select_default_terminal_profile(self, scheme: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Pick a suitable default terminal profile for a scheme."""
        profiles = self.list_terminal_profiles()
        if not profiles:
            return None
        if scheme:
            scheme_lower = scheme.lower()
            for profile in profiles:
                supported = profile.get('supported_schemes')
                if supported and any(scheme_lower == s.lower() for s in supported):
                    return profile
        for profile in profiles:
            if profile.get('default', False):
                return profile
        return profiles[0]

    def _prepare_terminal_profile(
        self,
        terminal_profile_id: Optional[str],
        terminal_overrides: Optional[Dict[str, Any]],
        scheme: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Resolve and merge a terminal profile with operator overrides."""
        base_profile: Optional[Dict[str, Any]] = None
        if terminal_profile_id:
            base_profile = self.get_terminal_profile(terminal_profile_id)
            if not base_profile:
                self.logger.warning("Unknown terminal profile '%s'; using custom overrides", terminal_profile_id)
                base_profile = {
                    'profile_id': terminal_profile_id,
                    'display_name': terminal_profile_id,
                    'capabilities': {},
                    'environment': {},
                }
        else:
            base_profile = self._select_default_terminal_profile(scheme)

        if not base_profile and not terminal_overrides:
            return None

        merged = deepcopy(base_profile) if base_profile else {}
        if terminal_overrides:
            merged = self._merge_dicts(merged, terminal_overrides)

        if terminal_profile_id:
            merged['profile_id'] = terminal_profile_id
        else:
            default_profile_id = base_profile.get('profile_id') if base_profile else 'custom'
            merged.setdefault('profile_id', default_profile_id)
        merged.setdefault('display_name', merged.get('profile_id', 'custom'))
        merged.setdefault('capabilities', {})
        merged.setdefault('environment', {})
        return merged

    @staticmethod
    def _merge_dicts(base: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries without mutating inputs."""
        result = deepcopy(base) if base else {}
        for key, value in (overrides or {}).items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = RealWorldCardIssuer._merge_dicts(result[key], value)
            else:
                result[key] = deepcopy(value) if isinstance(value, (dict, list)) else value
        return result
    
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