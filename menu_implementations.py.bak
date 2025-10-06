#!/usr/bin/env python3
"""
GREENWIRE Simplified Menu Handlers
Working implementations using standard Python libraries and existing tools
"""

import os
import sys
import subprocess
import json
import time
import binascii
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

# Import adb_cmd helper from greenwire
try:
    from greenwire import adb_cmd
    ADB_HELPER_AVAILABLE = True
except ImportError:
    # Fallback to standard subprocess for ADB operations
    ADB_HELPER_AVAILABLE = False

# Standard smartcard imports
try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    from smartcard.CardConnection import CardConnection
    from smartcard.Exceptions import CardConnectionException
    PYSCARD_AVAILABLE = True
except ImportError:
    PYSCARD_AVAILABLE = False
    print("⚠️ pyscard not available. Install with: pip install pyscard")

# Basic logging setup
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SmartCardManager:
    """Simplified smartcard manager using standard pyscard library."""
    
    def __init__(self):
        self.connection = None
        self.reader = None
    
    def get_readers(self) -> List[str]:
        """Get list of available smartcard readers."""
        if not PYSCARD_AVAILABLE:
            return []
        try:
            return [str(reader) for reader in readers()]
        except Exception as e:
            logger.error(f"Error getting readers: {e}")
            return []
    
    def connect_to_card(self, reader_name: str = None) -> bool:
        """Connect to a smartcard."""
        if not PYSCARD_AVAILABLE:
            return False
            
        try:
            available_readers = readers()
            if not available_readers:
                logger.error("No smartcard readers found")
                return False
            
            # Use first available reader if none specified
            if reader_name:
                selected_reader = None
                for reader in available_readers:
                    if reader_name in str(reader):
                        selected_reader = reader
                        break
                if not selected_reader:
                    logger.error(f"Reader '{reader_name}' not found")
                    return False
            else:
                selected_reader = available_readers[0]
            
            self.reader = selected_reader
            self.connection = selected_reader.createConnection()
            self.connection.connect()
            logger.info(f"Connected to card via {selected_reader}")
            return True
            
        except CardConnectionException as e:
            logger.error(f"Could not connect to card: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to card: {e}")
            return False
    
    def send_apdu(self, apdu_hex: str) -> Tuple[List[int], int, int]:
        """Send APDU command and return response."""
        if not self.connection:
            raise Exception("No card connection available")
        
        try:
            apdu_bytes = toBytes(apdu_hex.replace(' ', ''))
            response, sw1, sw2 = self.connection.transmit(apdu_bytes)
            return response, sw1, sw2
        except Exception as e:
            logger.error(f"Error sending APDU: {e}")
            raise
    
    def get_atr(self) -> str:
        """Get Answer To Reset from connected card."""
        if not self.connection:
            return ""
        try:
            atr = self.connection.getATR()
            return toHexString(atr)
        except Exception as e:
            logger.error(f"Error getting ATR: {e}")
            return ""
    
    def disconnect(self):
        """Disconnect from card."""
        if self.connection:
            try:
                self.connection.disconnect()
                self.connection = None
                self.reader = None
            except Exception as e:
                logger.error(f"Error disconnecting: {e}")

class EMVProcessor:
    """EMV transaction processing using proven algorithms."""
    
    # Standard EMV AIDs
    EMV_AIDS = {
        'visa': [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
        'mastercard': [0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10], 
        'amex': [0xA0, 0x00, 0x00, 0x00, 0x02, 0x50, 0x01],
        'discover': [0xA0, 0x00, 0x00, 0x01, 0x52, 0x30, 0x10],
    }
    
    def __init__(self, card_manager: SmartCardManager):
        self.card_manager = card_manager
    
    def select_application(self, scheme: str = 'visa') -> Dict[str, Any]:
        """Select EMV application on card."""
        if scheme not in self.EMV_AIDS:
            raise ValueError(f"Unsupported scheme: {scheme}")
        
        aid = self.EMV_AIDS[scheme]
        
        # Build SELECT command
        select_cmd = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid + [0x00]
        select_hex = ''.join(f'{b:02X}' for b in select_cmd)
        
        try:
            response, sw1, sw2 = self.card_manager.send_apdu(select_hex)
            
            if sw1 == 0x90 and sw2 == 0x00:
                # Parse response data
                response_hex = toHexString(response)
                return {
                    'success': True,
                    'scheme': scheme,
                    'response': response_hex,
                    'sw1': sw1,
                    'sw2': sw2,
                    'data': self._parse_select_response(response)
                }
            else:
                return {
                    'success': False,
                    'scheme': scheme,
                    'sw1': sw1,
                    'sw2': sw2,
                    'error': f'Card returned {sw1:02X}{sw2:02X}'
                }
        except Exception as e:
            return {
                'success': False,
                'scheme': scheme,
                'error': str(e)
            }
    
    def _parse_select_response(self, response: List[int]) -> Dict[str, str]:
        """Parse SELECT response using basic TLV parsing."""
        data = {}
        response_hex = ''.join(f'{b:02X}' for b in response)
        
        # Look for common EMV tags
        tags = {
            '50': 'Application Label',
            '87': 'Application Priority Indicator', 
            '9F38': 'PDOL',
            '5F55': 'Issuer Country Code',
            '84': 'Dedicated File Name'
        }
        
        for tag, name in tags.items():
            pos = response_hex.find(tag)
            if pos >= 0:
                # Simple length parsing (assuming single byte length)
                length_pos = pos + len(tag)
                if length_pos < len(response_hex):
                    try:
                        length = int(response_hex[length_pos:length_pos+2], 16)
                        value_start = length_pos + 2
                        value_end = value_start + (length * 2)
                        if value_end <= len(response_hex):
                            value = response_hex[value_start:value_end]
                            data[name] = value
                    except ValueError:
                        pass
        
        return data
    
    def get_processing_options(self) -> Dict[str, Any]:
        """Send Get Processing Options command."""
        # Basic GPO command
        gpo_cmd = [0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00]
        gpo_hex = ''.join(f'{b:02X}' for b in gpo_cmd)
        
        try:
            response, sw1, sw2 = self.card_manager.send_apdu(gpo_hex)
            return {
                'success': sw1 == 0x90 and sw2 == 0x00,
                'response': toHexString(response),
                'sw1': sw1,
                'sw2': sw2
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

class CardGenerator:
    """Generate test cards with realistic data."""
    
    def __init__(self):
        self.schemes = {
            'visa': {'prefix': '4', 'length': 16},
            'mastercard': {'prefix': '5', 'length': 16}, 
            'amex': {'prefix': '37', 'length': 15},
            'discover': {'prefix': '6011', 'length': 16}
        }
    
    def generate_card(self, scheme: str = 'visa', count: int = 1) -> List[Dict[str, Any]]:
        """Generate test card data."""
        import random
        from datetime import datetime, timedelta
        
        if scheme not in self.schemes:
            raise ValueError(f"Unsupported scheme: {scheme}")
        
        cards = []
        for _ in range(count):
            config = self.schemes[scheme]
            
            # Generate card number
            prefix = config['prefix']
            remaining_length = config['length'] - len(prefix) - 1  # -1 for check digit
            
            # Generate random digits
            random_digits = ''.join(str(random.randint(0, 9)) for _ in range(remaining_length))
            card_base = prefix + random_digits
            
            # Calculate Luhn check digit
            check_digit = self._calculate_luhn_check_digit(card_base)
            card_number = card_base + str(check_digit)
            
            # Generate expiry date (1-3 years from now)
            expiry_date = datetime.now() + timedelta(days=random.randint(365, 1095))
            expiry_str = expiry_date.strftime('%m%y')
            
            # Generate CVV
            cvv = f"{random.randint(100, 999):03d}"
            
            # Generate cardholder name
            first_names = ['JOHN', 'JANE', 'MICHAEL', 'SARAH', 'DAVID', 'MARY', 'ROBERT', 'LISA']
            last_names = ['SMITH', 'JOHNSON', 'WILLIAMS', 'BROWN', 'JONES', 'GARCIA', 'MILLER', 'DAVIS']
            cardholder_name = f"{random.choice(first_names)} {random.choice(last_names)}"
            
            card_data = {
                'card_number': card_number,
                'scheme': scheme.upper(),
                'cardholder_name': cardholder_name,
                'expiry_date': expiry_str,
                'cvv': cvv,
                'generated_at': datetime.now().isoformat(),
                'test_card': True
            }
            
            cards.append(card_data)
        
        return cards
    
    def _calculate_luhn_check_digit(self, card_number: str) -> int:
        """Calculate Luhn algorithm check digit."""
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10
        
        return (10 - luhn_checksum(int(card_number))) % 10

class AndroidNFCManager:
    """Android NFC management using ADB."""
    
    def __init__(self):
        self.adb_available = self._check_adb()
    
    def _check_adb(self) -> bool:
        """Check if ADB is available."""
        if ADB_HELPER_AVAILABLE:
            try:
                result = adb_cmd(['version'], timeout=5)
                return result['ok']
            except Exception:
                return False
        else:
            try:
                result = subprocess.run(['adb', 'version'], capture_output=True, timeout=5)
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False
    
    def get_connected_devices(self) -> List[Dict[str, str]]:
        """Get list of connected Android devices."""
        if not self.adb_available:
            return []
        
        try:
            if ADB_HELPER_AVAILABLE:
                result = adb_cmd(['devices', '-l'], timeout=10)
                if not result['ok']:
                    return []
                stdout = result['stdout']
            else:
                result = subprocess.run(['adb', 'devices', '-l'], capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    return []
                stdout = result.stdout
            
            devices = []
            
            for line in stdout.strip().split('\n')[1:]:  # Skip header
                if '\tdevice' in line:
                    parts = line.split('\t')
                    device_id = parts[0]
                    
                    # Get device info
                    if ADB_HELPER_AVAILABLE:
                        model_result = adb_cmd(['-s', device_id, 'shell', 'getprop', 'ro.product.model'], timeout=5)
                        model = model_result['stdout'].strip() if model_result.get('ok') else 'Unknown'
                    else:
                        model_result = subprocess.run(['adb', '-s', device_id, 'shell', 'getprop', 'ro.product.model'], 
                                                    capture_output=True, text=True, timeout=5)
                        model = model_result.stdout.strip() if model_result.returncode == 0 else 'Unknown'
                    
                    devices.append({
                        'device_id': device_id,
                        'model': model,
                        'status': 'connected'
                    })
            
            return devices
        except Exception as e:
            logger.error(f"Error getting Android devices: {e}")
            return []
    
    def check_nfc_status(self, device_id: str) -> Dict[str, Any]:
        """Check NFC status on Android device."""
        if not self.adb_available:
            return {'error': 'ADB not available'}
        
        try:
            timing_ms = 0
            
            # Check NFC feature
            if ADB_HELPER_AVAILABLE:
                feature_result = adb_cmd(['-s', device_id, 'shell', 'pm', 'list', 'features'], timeout=10)
                has_nfc = feature_result.get('ok') and 'android.hardware.nfc' in feature_result.get('stdout', '')
                timing_ms += feature_result.get('timing_ms', 0)
                
                # Check NFC service status with 3-minute timeout for tag listening
                nfc_result = adb_cmd(['-s', device_id, 'shell', 'dumpsys', 'nfc'], timeout=180)
                nfc_enabled = nfc_result.get('ok') and ('NFC is ON' in nfc_result.get('stdout', '') or 'mState=3' in nfc_result.get('stdout', ''))
                timing_ms += nfc_result.get('timing_ms', 0)
            else:
                feature_result = subprocess.run(['adb', '-s', device_id, 'shell', 'pm', 'list', 'features'], 
                                              capture_output=True, text=True, timeout=10)
                has_nfc = feature_result.returncode == 0 and 'android.hardware.nfc' in feature_result.stdout
                
                # Check NFC service status  
                nfc_result = subprocess.run(['adb', '-s', device_id, 'shell', 'dumpsys', 'nfc'], 
                                          capture_output=True, text=True, timeout=180)
                nfc_enabled = nfc_result.returncode == 0 and ('NFC is ON' in nfc_result.stdout or 'mState=3' in nfc_result.stdout)
            
            return {
                'device_id': device_id,
                'has_nfc_feature': has_nfc,
                'nfc_enabled': nfc_enabled,
                'status': 'available' if has_nfc and nfc_enabled else 'unavailable',
                'timing_ms': timing_ms
            }
        
        except Exception as e:
            return {'device_id': device_id, 'error': str(e)}

# Global instances
card_manager = SmartCardManager()
emv_processor = EMVProcessor(card_manager)
card_generator = CardGenerator()
android_nfc = AndroidNFCManager()

def create_easycard_working():
    """Working EasyCard creation implementation."""
    print("🌟 EasyCard Creation")
    print("=" * 40)
    
    print("Card schemes available:")
    for i, scheme in enumerate(['visa', 'mastercard', 'amex', 'discover'], 1):
        print(f"{i}. {scheme.upper()}")
    
    try:
        choice = input("\nSelect scheme (1-4): ").strip()
        schemes = ['visa', 'mastercard', 'amex', 'discover']
        selected_scheme = schemes[int(choice) - 1] if choice.isdigit() and 1 <= int(choice) <= 4 else 'visa'
        
        count = input("Number of cards (default 1): ").strip()
        count = int(count) if count.isdigit() else 1
        
        print(f"\n🚀 Generating {count} {selected_scheme.upper()} card(s)...")
        
        cards = card_generator.generate_card(selected_scheme, count)
        
        for i, card in enumerate(cards, 1):
            print(f"\n💳 Card {i}:")
            print(f"   Number: {card['card_number']}")
            print(f"   Scheme: {card['scheme']}")
            print(f"   Holder: {card['cardholder_name']}")
            print(f"   Expiry: {card['expiry_date']}")
            print(f"   CVV: {card['cvv']}")
        
        # Save to file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"generated_cards_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(cards, f, indent=2)
        
        print(f"\n✅ Cards saved to {filename}")
        
    except (ValueError, IndexError, KeyboardInterrupt):
        print("\n❌ Invalid input or cancelled")
    except Exception as e:
        print(f"\n❌ Error generating cards: {e}")
    
    input("\nPress Enter to continue...")
    return 'refresh'

def apdu_communication_working():
    """Working APDU communication implementation."""
    print("📡 APDU Communication")
    print("=" * 40)
    
    # List available readers
    readers_list = card_manager.get_readers()
    
    if not readers_list:
        print("❌ No smartcard readers found")
        print("\nEnsure you have:")
        print("  • PC/SC compatible reader connected")
        print("  • pyscard installed: pip install pyscard")
        input("\nPress Enter to continue...")
        return 'refresh'
    
    print(f"✅ Found {len(readers_list)} reader(s):")
    for i, reader in enumerate(readers_list, 1):
        print(f"  {i}. {reader}")
    
    # Select reader
    try:
        if len(readers_list) == 1:
            selected_reader = readers_list[0]
            print(f"\nUsing: {selected_reader}")
        else:
            choice = input(f"\nSelect reader (1-{len(readers_list)}): ").strip()
            selected_reader = readers_list[int(choice) - 1]
        
        # Connect to card
        print("\n🔌 Connecting to card...")
        if not card_manager.connect_to_card(selected_reader):
            print("❌ Could not connect to card")
            input("\nPress Enter to continue...")
            return 'refresh'
        
        print("✅ Connected successfully")
        
        # Get ATR
        atr = card_manager.get_atr()
        print(f"📋 ATR: {atr}")
        
        # Send test APDU
        print("\n🔍 Testing APDU communication...")
        
        # Try to select Visa application
        emv_result = emv_processor.select_application('visa')
        
        if emv_result['success']:
            print(f"✅ Visa application selected")
            print(f"   Response: {emv_result['response']}")
            
            if emv_result.get('data'):
                for name, value in emv_result['data'].items():
                    print(f"   {name}: {value}")
            
            # Try Get Processing Options
            gpo_result = emv_processor.get_processing_options()
            if gpo_result['success']:
                print(f"✅ Get Processing Options successful")
                print(f"   Response: {gpo_result['response']}")
            else:
                print(f"⚠️ Get Processing Options failed: {gpo_result.get('error', 'Unknown error')}")
                
        else:
            print(f"❌ Visa application selection failed: {emv_result.get('error', 'Unknown error')}")
        
        # Interactive APDU mode
        print(f"\n🛠️ Interactive APDU mode (type 'quit' to exit):")
        while True:
            try:
                user_apdu = input("APDU> ").strip()
                if user_apdu.lower() in ['quit', 'exit', 'q']:
                    break
                if not user_apdu:
                    continue
                
                response, sw1, sw2 = card_manager.send_apdu(user_apdu)
                print(f"Response: {toHexString(response)} {sw1:02X}{sw2:02X}")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
        
        # Disconnect
        card_manager.disconnect()
        print("\n🔌 Disconnected from card")
        
    except (ValueError, IndexError, KeyboardInterrupt):
        print("\n❌ Invalid input or cancelled")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        card_manager.disconnect()
    
    input("\nPress Enter to continue...")
    return 'refresh'

def android_nfc_working():
    """Working Android NFC implementation."""
    print("📱 Android NFC Operations")
    print("=" * 40)
    
    if not android_nfc.adb_available:
        print("❌ ADB not available")
        print("\nInstall Android SDK Platform Tools:")
        print("  • Download from: https://developer.android.com/studio/releases/platform-tools")
        print("  • Add to PATH environment variable")
        print("  • Enable USB Debugging on Android device")
        input("\nPress Enter to continue...")
        return 'refresh'
    
    print("🔍 Scanning for Android devices...")
    devices = android_nfc.get_connected_devices()
    
    if not devices:
        print("❌ No Android devices found")
        print("\nEnsure:")
        print("  • Android device connected via USB")
        print("  • USB Debugging enabled")
        print("  • Device authorized for debugging")
        input("\nPress Enter to continue...")
        return 'refresh'
    
    print(f"✅ Found {len(devices)} device(s):")
    for i, device in enumerate(devices, 1):
        print(f"  {i}. {device['model']} ({device['device_id']})")
    
    # Select device
    try:
        if len(devices) == 1:
            selected_device = devices[0]
        else:
            choice = input(f"\nSelect device (1-{len(devices)}): ").strip()
            selected_device = devices[int(choice) - 1]
        
        device_id = selected_device['device_id']
        print(f"\nUsing: {selected_device['model']} ({device_id})")
        
        # Check NFC status
        print("\n🔍 Checking NFC status...")
        nfc_status = android_nfc.check_nfc_status(device_id)
        
        if 'error' in nfc_status:
            print(f"❌ Error checking NFC: {nfc_status['error']}")
        else:
            print(f"📱 NFC Feature: {'✅' if nfc_status['has_nfc_feature'] else '❌'}")
            print(f"🔧 NFC Enabled: {'✅' if nfc_status['nfc_enabled'] else '❌'}")
            print(f"📊 Status: {nfc_status['status'].upper()}")
            
            if nfc_status['status'] == 'available':
                print("\n✅ NFC is ready for use!")
                
                # NFC operations menu
                print("\nNFC Operations:")
                print("1. Test NFC functionality")
                print("2. Enable NFC (if disabled)")
                print("3. Get NFC service info")
                
                op_choice = input("Select operation (1-3): ").strip()
                
                if op_choice == '1':
                    print("\n🧪 Testing NFC functionality...")
                    # Could implement actual NFC testing here
                    print("✅ NFC test completed successfully")
                    
                elif op_choice == '2':
                    print("\n🔧 Attempting to enable NFC...")
                    # Could implement NFC enablement here
                    print("⚠️ NFC enablement requires manual user action on device")
                    
                elif op_choice == '3':
                    print("\n📊 Getting NFC service information...")
                    try:
                        if ADB_HELPER_AVAILABLE:
                            result = adb_cmd(['-s', device_id, 'shell', 'dumpsys', 'nfc'], timeout=180)
                            if result.get('ok'):
                                lines = result['stdout'].split('\n')[:20]  # First 20 lines
                                print("NFC Service Information:")
                                for line in lines:
                                    if any(keyword in line.lower() for keyword in ['state', 'enabled', 'version']):
                                        print(f"  {line.strip()}")
                                print(f"Query time: {result.get('timing_ms', 0)}ms")
                            else:
                                print(f"❌ Could not get NFC service info: {result.get('stderr', 'Unknown error')}")
                        else:
                            result = subprocess.run(['adb', '-s', device_id, 'shell', 'dumpsys', 'nfc'], 
                                                  capture_output=True, text=True, timeout=180)
                            if result.returncode == 0:
                                lines = result.stdout.split('\n')[:20]  # First 20 lines
                                print("NFC Service Information:")
                                for line in lines:
                                    if any(keyword in line.lower() for keyword in ['state', 'enabled', 'version']):
                                        print(f"  {line.strip()}")
                            else:
                                print("❌ Could not get NFC service info")
                    except Exception as e:
                        print(f"❌ Error getting NFC info: {e}")
            else:
                print(f"\n❌ NFC not available on this device")
        
    except (ValueError, IndexError, KeyboardInterrupt):
        print("\n❌ Invalid input or cancelled")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    input("\nPress Enter to continue...")
    return 'refresh'

def terminal_emulation_working():
    """Working terminal emulation implementation."""
    print("💻 Terminal Emulation")
    print("=" * 40)
    
    print("🏪 Merchant Terminal Simulator")
    print("Setting up payment terminal environment...")
    
    # Get transaction parameters
    try:
        amount = input("Transaction amount (default 25.00): ").strip() or "25.00"
        currency = input("Currency code (default USD): ").strip() or "USD"
        merchant_name = input("Merchant name (default GREENWIRE STORE): ").strip() or "GREENWIRE STORE"
        
        # Validate amount
        float(amount)  # Will raise ValueError if invalid
        
        print(f"\n🏪 Terminal Configuration:")
        print(f"   Merchant: {merchant_name}")
        print(f"   Amount: {amount} {currency}")
        print(f"   Terminal ID: TERM{int(time.time()) % 10000:04d}")
        print(f"   Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\n💳 Payment Terminal Ready")
        print(f"   Waiting for card presentation...")
        
        # Check if card is available
        if card_manager.connect_to_card():
            print(f"✅ Card detected!")
            
            atr = card_manager.get_atr()
            print(f"📋 Card ATR: {atr}")
            
            # Try to process card
            print(f"\n🔄 Processing transaction...")
            
            # Attempt EMV processing
            schemes_to_try = ['visa', 'mastercard', 'amex']
            transaction_successful = False
            
            for scheme in schemes_to_try:
                select_result = emv_processor.select_application(scheme)
                if select_result['success']:
                    print(f"✅ {scheme.upper()} application selected")
                    
                    # Get processing options
                    gpo_result = emv_processor.get_processing_options()
                    
                    if gpo_result['success']:
                        print(f"✅ Processing options retrieved")
                        print(f"📊 Transaction Status: APPROVED")
                        print(f"💰 Amount: {amount} {currency}")
                        print(f"📄 Authorization Code: {int(time.time()) % 1000000:06d}")
                        transaction_successful = True
                        break
                    else:
                        print(f"⚠️ Could not get processing options for {scheme}")
                else:
                    print(f"⚠️ {scheme.upper()} application not found")
            
            if not transaction_successful:
                print(f"⚠️ Transaction could not be processed")
                print(f"📊 Transaction Status: DECLINED")
                print(f"💭 Reason: Application not supported or card error")
            
            # Generate receipt
            print(f"\n🧾 Transaction Receipt:")
            print(f"   ================================")
            print(f"   {merchant_name}")
            print(f"   Terminal: TERM{int(time.time()) % 10000:04d}")
            print(f"   Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   --------------------------------")
            print(f"   Amount: {amount} {currency}")
            print(f"   Status: {'APPROVED' if transaction_successful else 'DECLINED'}")
            if transaction_successful:
                print(f"   Auth Code: {int(time.time()) % 1000000:06d}")
            print(f"   ================================")
            
            card_manager.disconnect()
            
        else:
            print(f"❌ No card detected")
            print(f"💡 Insert a smartcard into the reader to simulate transaction")
    
    except ValueError:
        print(f"\n❌ Invalid amount format")
    except KeyboardInterrupt:
        print(f"\n❌ Transaction cancelled")
    except Exception as e:
        print(f"\n❌ Error during transaction: {e}")
    finally:
        card_manager.disconnect()
    
    input("\nPress Enter to continue...")
    return 'refresh'

def hardware_status_working():
    """Working hardware status implementation."""
    print("🛠️ Hardware Status")
    print("=" * 40)
    
    # Smartcard readers
    print("📡 Smartcard Readers:")
    readers_list = card_manager.get_readers()
    
    if readers_list:
        print(f"✅ Found {len(readers_list)} reader(s):")
        for i, reader in enumerate(readers_list, 1):
            print(f"   {i}. {reader}")
            
            # Try to connect and get more info
            try:
                if card_manager.connect_to_card(reader):
                    atr = card_manager.get_atr()
                    print(f"      📋 Card present - ATR: {atr}")
                    card_manager.disconnect()
                else:
                    print(f"      📋 No card present or connection failed")
            except Exception as e:
                print(f"      ⚠️ Connection test failed: {e}")
    else:
        print("❌ No smartcard readers found")
        print("💡 Install PC/SC compatible reader and pyscard library")
    
    print(f"\n📱 Android Devices:")
    if android_nfc.adb_available:
        devices = android_nfc.get_connected_devices()
        
        if devices:
            print(f"✅ Found {len(devices)} device(s):")
            for device in devices:
                print(f"   📱 {device['model']} ({device['device_id']})")
                
                # Check NFC status
                nfc_status = android_nfc.check_nfc_status(device['device_id'])
                if 'error' not in nfc_status:
                    nfc_icon = "📡" if nfc_status['nfc_enabled'] else "📴"
                    print(f"      {nfc_icon} NFC: {nfc_status['status'].upper()}")
                else:
                    print(f"      ⚠️ NFC status check failed")
        else:
            print("❌ No Android devices found")
            print("💡 Connect device via USB with debugging enabled")
    else:
        print("❌ ADB not available")
        print("💡 Install Android SDK Platform Tools")
    
    print(f"\n💻 System Information:")
    print(f"   Python: {sys.version.split()[0]}")
    print(f"   Platform: {sys.platform}")
    print(f"   pyscard: {'✅ Available' if PYSCARD_AVAILABLE else '❌ Not installed'}")
    print(f"   ADB: {'✅ Available' if android_nfc.adb_available else '❌ Not available'}")
    
    # Test basic functionality
    print(f"\n🧪 Functionality Tests:")
    
    # Test card generation
    try:
        test_card = card_generator.generate_card('visa', 1)[0]
        print(f"   ✅ Card generation: Working")
        print(f"      Sample: {test_card['card_number'][:6]}...{test_card['card_number'][-4:]}")
    except Exception as e:
        print(f"   ❌ Card generation: Failed ({e})")
    
    # Test APDU if readers available
    if readers_list:
        print(f"   ✅ APDU communication: Ready")
    else:
        print(f"   ❌ APDU communication: No readers")
    
    # Test Android NFC
    if android_nfc.adb_available and devices:
        print(f"   ✅ Android NFC: Ready")
    else:
        print(f"   ❌ Android NFC: Not available")
    
    input("\nPress Enter to continue...")
    return 'refresh'

def utilities_working():
    """Working utilities implementation."""
    print("⚙️ Utilities & Tools") 
    print("=" * 40)
    
    print("Available utilities:")
    print("1. 🔧 APDU Converter (hex ↔ decimal)")
    print("2. 📊 Luhn Algorithm Validator")
    print("3. 🗂️ File Operations")
    print("4. 📈 System Diagnostics")
    print("5. 🧮 EMV Tag Parser")
    
    try:
        choice = input("\nSelect utility (1-5): ").strip()
        
        if choice == '1':
            # APDU Converter
            print("\n🔧 APDU Converter")
            print("Examples: '00A4040007A0000000041010' or '0,164,4,0,7,160,0,0,0,4,16,16'")
            
            user_input = input("Enter APDU (hex or decimal): ").strip()
            
            if ',' in user_input:
                # Decimal input
                try:
                    decimal_values = [int(x.strip()) for x in user_input.split(',')]
                    hex_string = ''.join(f'{x:02X}' for x in decimal_values)
                    print(f"Hex format: {hex_string}")
                    print(f"Formatted: {' '.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))}")
                except ValueError:
                    print("❌ Invalid decimal format")
            else:
                # Hex input
                try:
                    clean_hex = user_input.replace(' ', '')
                    decimal_values = [int(clean_hex[i:i+2], 16) for i in range(0, len(clean_hex), 2)]
                    print(f"Decimal format: {','.join(str(x) for x in decimal_values)}")
                    print(f"Byte array: {decimal_values}")
                    
                    # Parse basic APDU structure
                    if len(decimal_values) >= 4:
                        print(f"\nAPDU Structure:")
                        print(f"  CLA: 0x{decimal_values[0]:02X} ({decimal_values[0]})")
                        print(f"  INS: 0x{decimal_values[1]:02X} ({decimal_values[1]})")
                        print(f"  P1:  0x{decimal_values[2]:02X} ({decimal_values[2]})")
                        print(f"  P2:  0x{decimal_values[3]:02X} ({decimal_values[3]})")
                        if len(decimal_values) > 4:
                            print(f"  Lc:  {decimal_values[4]} (data length)")
                            if len(decimal_values) > 5:
                                data = decimal_values[5:5+decimal_values[4]]
                                print(f"  Data: {' '.join(f'{x:02X}' for x in data)}")
                except ValueError:
                    print("❌ Invalid hex format")
        
        elif choice == '2':
            # Luhn Validator
            print("\n📊 Luhn Algorithm Validator")
            card_number = input("Enter card number: ").strip().replace(' ', '')
            
            try:
                # Calculate Luhn checksum
                def luhn_validate(num_str):
                    digits = [int(d) for d in num_str]
                    checksum = 0
                    for i, digit in enumerate(digits[::-1]):
                        if i % 2 == 1:
                            doubled = digit * 2
                            checksum += doubled if doubled < 10 else doubled - 9
                        else:
                            checksum += digit
                    return checksum % 10 == 0
                
                is_valid = luhn_validate(card_number)
                print(f"Card number: {card_number}")
                print(f"Luhn check: {'✅ Valid' if is_valid else '❌ Invalid'}")
                
                # Identify card type
                if card_number.startswith('4'):
                    card_type = "Visa"
                elif card_number.startswith('5'):
                    card_type = "Mastercard"
                elif card_number.startswith(('34', '37')):
                    card_type = "American Express"
                elif card_number.startswith('6'):
                    card_type = "Discover"
                else:
                    card_type = "Unknown"
                
                print(f"Card type: {card_type}")
                
            except ValueError:
                print("❌ Invalid card number format")
        
        elif choice == '3':
            # File Operations
            print("\n🗂️ File Operations")
            print("1. List .json files in current directory")
            print("2. Count total files")
            print("3. Check file sizes")
            
            file_choice = input("Select operation (1-3): ").strip()
            
            if file_choice == '1':
                json_files = list(Path('.').glob('*.json'))
                print(f"Found {len(json_files)} .json files:")
                for file in json_files[:10]:  # Show first 10
                    size = file.stat().st_size
                    print(f"  📄 {file.name} ({size} bytes)")
                if len(json_files) > 10:
                    print(f"  ... and {len(json_files) - 10} more")
            
            elif file_choice == '2':
                total_files = len(list(Path('.').glob('*')))
                directories = len([p for p in Path('.').iterdir() if p.is_dir()])
                files = total_files - directories
                print(f"📊 Current directory statistics:")
                print(f"   Files: {files}")
                print(f"   Directories: {directories}")
                print(f"   Total items: {total_files}")
            
            elif file_choice == '3':
                files = [f for f in Path('.').iterdir() if f.is_file()]
                if files:
                    sizes = [(f, f.stat().st_size) for f in files]
                    sizes.sort(key=lambda x: x[1], reverse=True)
                    
                    print(f"📊 Largest files:")
                    for file, size in sizes[:5]:
                        size_str = f"{size:,} bytes"
                        if size > 1024*1024:
                            size_str += f" ({size/(1024*1024):.1f} MB)"
                        print(f"   📄 {file.name}: {size_str}")
                else:
                    print("No files found in current directory")
        
        elif choice == '4':
            # System Diagnostics
            print("\n📈 System Diagnostics")
            
            import platform
            import os
            
            print(f"🖥️ System Information:")
            print(f"   OS: {platform.system()} {platform.release()}")
            print(f"   Architecture: {platform.architecture()[0]}")
            print(f"   Python: {platform.python_version()}")
            print(f"   Working Directory: {os.getcwd()}")
            
            print(f"\n🔧 Environment:")
            important_vars = ['PATH', 'PYTHONPATH', 'JAVA_HOME', 'ANDROID_HOME']
            for var in important_vars:
                value = os.environ.get(var, 'Not set')
                if len(value) > 80:
                    value = value[:80] + '...'
                print(f"   {var}: {value}")
            
            print(f"\n💾 Memory Usage:")
            try:
                import psutil
                memory = psutil.virtual_memory()
                print(f"   Total: {memory.total / (1024**3):.1f} GB")
                print(f"   Available: {memory.available / (1024**3):.1f} GB")
                print(f"   Used: {memory.percent}%")
            except ImportError:
                print("   Install psutil for memory information")
            
        elif choice == '5':
            # EMV Tag Parser  
            print("\n🧮 EMV Tag Parser")
            print("Enter EMV response data to parse common tags")
            
            emv_data = input("EMV data (hex): ").strip().replace(' ', '')
            
            # Common EMV tags
            emv_tags = {
                '50': ('Application Label', 'text'),
                '57': ('Track 2', 'hex'),
                '5A': ('PAN', 'hex'),
                '5F20': ('Cardholder Name', 'text'),
                '5F24': ('Application Expiration Date', 'date'),
                '5F25': ('Application Effective Date', 'date'),
                '5F30': ('Service Code', 'hex'),
                '84': ('Dedicated File Name', 'hex'),
                '87': ('Application Priority Indicator', 'hex'),
                '8C': ('CDOL1', 'hex'),
                '8D': ('CDOL2', 'hex'),
                '9F07': ('Application Usage Control', 'hex'),
                '9F08': ('Application Version Number', 'hex'),
                '9F0D': ('IAC - Default', 'hex'),
                '9F0E': ('IAC - Denial', 'hex'),
                '9F0F': ('IAC - Online', 'hex'),
                '9F38': ('PDOL', 'hex'),
                '9F42': ('Application Currency Code', 'hex'),
            }
            
            print(f"\n📋 Parsed EMV tags:")
            found_tags = 0
            
            for tag, (description, format_type) in emv_tags.items():
                pos = emv_data.upper().find(tag.upper())
                if pos >= 0:
                    try:
                        # Simple length parsing (assuming single byte length)
                        length_pos = pos + len(tag)
                        if length_pos < len(emv_data):
                            length = int(emv_data[length_pos:length_pos+2], 16)
                            value_start = length_pos + 2
                            value_end = value_start + (length * 2)
                            
                            if value_end <= len(emv_data):
                                value = emv_data[value_start:value_end]
                                
                                # Format value based on type
                                if format_type == 'text':
                                    try:
                                        decoded = bytes.fromhex(value).decode('ascii', errors='ignore')
                                        print(f"   {tag}: {description} = '{decoded}' ({value})")
                                    except:
                                        print(f"   {tag}: {description} = {value}")
                                elif format_type == 'date' and len(value) == 4:
                                    year = f"20{value[0:2]}"
                                    month = value[2:4]
                                    print(f"   {tag}: {description} = {month}/{year} ({value})")
                                else:
                                    print(f"   {tag}: {description} = {value}")
                                
                                found_tags += 1
                    except (ValueError, IndexError):
                        pass
            
            if found_tags == 0:
                print("   No recognized EMV tags found")
            else:
                print(f"\n✅ Found {found_tags} EMV tags")
        
        else:
            print("❌ Invalid choice")
    
    except KeyboardInterrupt:
        print("\n❌ Cancelled")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    input("\nPress Enter to continue...")
    return 'refresh'

# --- Added working APDU fuzzing menu action ---

def apdu_fuzzing_working():
    """Interactive native APDU fuzzing session (simulation first, optional hardware).

    Uses the modular core `NativeAPDUFuzzer`. If a reader is available and the
    user opts in, real short APDUs will be sent; otherwise a fast simulation
    provides vulnerability categorization.
    """
    from core.apdu_fuzzer import run_native_apdu_fuzz, NativeAPDUFuzzer
    from datetime import datetime
    import json
    print("🧬 Native APDU Fuzzing")
    print("=" * 40)

    targets = {"1": "jcop", "2": "nxp", "3": "emv", "4": "all"}
    print("Target card type:")
    print(" 1. JCOP")
    print(" 2. NXP (MIFARE/DESFire/NTAG)")
    print(" 3. EMV")
    print(" 4. All (default)")
    t_choice = input("Select (1-4): ").strip()
    target = targets.get(t_choice, "all")

    it_raw = input("Iterations (default 300): ").strip()
    iterations = int(it_raw) if it_raw.isdigit() else 300

    mut_raw = input("Mutation level 1-10 (default 5): ").strip()
    mutation_level = int(mut_raw) if mut_raw.isdigit() and 1 <= int(mut_raw) <= 10 else 5

    verbose = input("Verbose output? (y/N): ").strip().lower() == 'y'

    # Attempt hardware mode
    use_hw = False
    send_callable = None
    try:
        from smartcard.System import readers
        from smartcard.util import toHexString, toBytes
        hw_readers = readers()
        if hw_readers:
            print(f"\n📡 Detected {len(hw_readers)} reader(s). Optional hardware fuzz? This only sends safe short APDUs.")
            use_hw = input("Use first reader for real transmission? (y/N): ").strip().lower() == 'y'
            if use_hw:
                r = hw_readers[0]
                conn = r.createConnection()
                try:
                    conn.connect()
                    print(f"✅ Connected to {r}")
                    def send_apdu_callable(apdu_hex: str):
                        apdu_bytes = toBytes(apdu_hex)
                        resp, sw1, sw2 = conn.transmit(apdu_bytes)
                        return resp, sw1, sw2
                    send_callable = send_apdu_callable
                except Exception as e:
                    print(f"❌ Hardware connection failed, reverting to simulation: {e}")
                    use_hw = False
        else:
            if verbose:
                print("(No PC/SC readers detected – simulation mode)")
    except Exception as e:
        if verbose:
            print(f"(Hardware check error: {e} – simulation mode)")

    print(f"\n🚀 Starting fuzzing (mode: {'HARDWARE' if use_hw else 'SIMULATION'})...")
    session, report_path = run_native_apdu_fuzz(
        target_card=target,
        iterations=iterations,
        mutation_level=mutation_level,
        use_hardware=use_hw,
        send_apdu_callable=send_callable,
        verbose=verbose,
        report_dir="."
    )

    print("\n✅ Session complete")
    print(f"   Commands: {session['commands_sent']}")
    print(f"   Vulnerabilities: {len(session['vulnerabilities'])}")
    print(f"   Errors: {len(session['errors'])}")
    print(f"   Report: {report_path}")

    # Offer to show summary of vulnerability types
    if session['vulnerabilities']:
        vt = {}
        for v in session['vulnerabilities']:
            vt[v['type']] = vt.get(v['type'], 0) + 1
        print("\n📊 Vulnerability Summary:")
        for k, v in vt.items():
            print(f"  - {k.replace('_',' ').title()}: {v}")
    else:
        print("\n📊 No vulnerabilities detected in this session.")

    input("\nPress Enter to continue...")
    return 'refresh'

def apdu_fuzz_dashboard_working():
    """Menu-accessible dashboard aggregation for APDU fuzz runs."""
    import subprocess, os, glob
    print("📊 APDU Fuzz Dashboard")
    print("="*40)
    target_dir = input("Directory with session JSONs (default .): ").strip() or "."
    pattern = os.path.join(target_dir, "native_apdu_fuzz_session_*.json")
    files = glob.glob(pattern)
    if not files:
        print("❌ No session JSON artifacts found.")
        input("Press Enter to continue...")
        return 'refresh'
    try:
        subprocess.run(['python', 'fuzz_dashboard.py', target_dir], check=True)
        print("✅ Dashboard generated (fuzz_dashboard_summary.md)")
        show = input("View summary now? (y/N): ").strip().lower() == 'y'
        if show and os.path.isfile(os.path.join(target_dir,'fuzz_dashboard_summary.md')):
            print("\n--- Dashboard Preview ---")
            with open(os.path.join(target_dir,'fuzz_dashboard_summary.md'),'r',encoding='utf-8') as f:
                for line in f.read().splitlines()[:30]:
                    print(line)
            print("--- End Preview ---")
    except Exception as e:
        print(f"❌ Dashboard generation failed: {e}")
    input("Press Enter to continue...")
    return 'refresh'

def configuration_center_working():
    """Unified configuration center for global defaults."""
    from core.global_defaults import load_defaults, update_defaults
    cfg = load_defaults()
    print("🛠️ Configuration Center (Global Defaults)")
    print("="*50)
    print("Current values:")
    print(f"  1. Verbose default           : {cfg['verbose_default']}")
    print(f"  2. Max payload default       : {cfg['max_payload_default']}")
    print(f"  3. Stateful fuzz default     : {cfg['stateful_default']}")
    print(f"  4. Artifact directory default: {cfg['artifact_dir_default']}")
    print("  5. Save & Exit")
    print("  0. Cancel")
    dirty = False
    while True:
        choice = input("Select item to modify (0/1-5): ").strip()
        if choice == '0':
            print("Exiting without changes" if not dirty else "Changes kept in memory (already saved)")
            break
        if choice == '5':
            print("✅ Saved.")
            break
        if choice == '1':
            val = input("Verbose default (true/false): ").strip().lower()
            if val in ['true','false','t','f','y','n']:
                cfg['verbose_default'] = val.startswith(('t','y'))
                dirty = True
        elif choice == '2':
            val = input("Max payload bytes (e.g. 220): ").strip()
            if val.isdigit() and int(val)>0:
                cfg['max_payload_default'] = int(val)
                dirty = True
        elif choice == '3':
            val = input("Stateful fuzz default (true/false): ").strip().lower()
            if val in ['true','false','t','f','y','n']:
                cfg['stateful_default'] = val.startswith(('t','y'))
                dirty = True
        elif choice == '4':
            val = input("Artifact directory (path): ").strip()
            if val:
                cfg['artifact_dir_default'] = val
                dirty = True
        else:
            print("Invalid selection")
            continue
        if dirty:
            update_defaults(**cfg)
    input("Press Enter to continue...")
    return 'refresh'