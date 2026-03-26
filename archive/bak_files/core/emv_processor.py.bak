"""
GREENWIRE EMV Processor
Handles EMV TLV parsing, tag interpretation, and transaction data processing.
"""

from typing import Dict, List, Optional, Tuple, Any, Union
import os
from .logging_system import get_logger, handle_errors

class EMVProcessor:
    """Processes EMV transaction data and TLV structures."""
    
    def __init__(self):
        self.logger = get_logger()
        self.emv_tags = self._load_emv_tags()
    
    def _load_emv_tags(self) -> Dict[str, str]:
        """Load EMV tag definitions."""
        return {
            '4F': 'Application Identifier (AID)',
            '50': 'Application Label',
            '57': 'Track 2 Equivalent Data',
            '5A': 'Application Primary Account Number (PAN)',
            '5F20': 'Cardholder Name',
            '5F24': 'Application Expiration Date',
            '5F25': 'Application Effective Date',
            '5F28': 'Issuer Country Code',
            '5F2A': 'Transaction Currency Code',
            '5F2D': 'Language Preference',
            '5F30': 'Service Code',
            '5F34': 'Application Primary Account Number (PAN) Sequence Number',
            '82': 'Application Interchange Profile',
            '84': 'Dedicated File (DF) Name',
            '87': 'Application Priority Indicator',
            '88': 'Short File Identifier (SFI)',
            '8A': 'Authorization Response Code',
            '8C': 'Card Risk Management Data Object List 1 (CDOL1)',
            '8D': 'Card Risk Management Data Object List 2 (CDOL2)',
            '8E': 'Cardholder Verification Method (CVM) List',
            '8F': 'Certification Authority Public Key Index',
            '90': 'Issuer Public Key Certificate',
            '92': 'Issuer Public Key Remainder',
            '93': 'Signed Static Application Data',
            '94': 'Application File Locator (AFL)',
            '95': 'Terminal Verification Results',
            '9A': 'Transaction Date',
            '9B': 'Transaction Status Information',
            '9C': 'Transaction Type',
            '9F01': 'Acquirer Identifier',
            '9F02': 'Amount, Authorized (Numeric)',
            '9F03': 'Amount, Other (Numeric)',
            '9F06': 'Application Identifier (AID) - terminal',
            '9F07': 'Application Usage Control',
            '9F08': 'Application Version Number',
            '9F09': 'Application Version Number',
            '9F0D': 'Issuer Action Code - Default',
            '9F0E': 'Issuer Action Code - Denial',
            '9F0F': 'Issuer Action Code - Online',
            '9F10': 'Issuer Application Data',
            '9F11': 'Issuer Code Table Index',
            '9F12': 'Application Preferred Name',
            '9F13': 'Last Online Application Transaction Counter (ATC) Register',
            '9F15': 'Merchant Category Code',
            '9F16': 'Merchant Identifier',
            '9F17': 'Personal Identification Number (PIN) Try Counter',
            '9F18': 'Issuer Script Identifier',
            '9F1A': 'Terminal Country Code',
            '9F1B': 'Terminal Floor Limit',
            '9F1C': 'Terminal Identification',
            '9F1D': 'Terminal Risk Management Data',
            '9F1E': 'Interface Device (IFD) Serial Number',
            '9F1F': 'Track 1 Discretionary Data',
            '9F20': 'Track 2 Discretionary Data',
            '9F21': 'Transaction Time',
            '9F22': 'Certification Authority Public Key Index',
            '9F23': 'Upper Consecutive Offline Limit',
            '9F26': 'Application Cryptogram',
            '9F27': 'Cryptogram Information Data',
            '9F32': 'Issuer Public Key Exponent',
            '9F33': 'Terminal Capabilities',
            '9F34': 'Cardholder Verification Method (CVM) Results',
            '9F35': 'Terminal Type',
            '9F36': 'Application Transaction Counter (ATC)',
            '9F37': 'Unpredictable Number',
            '9F38': 'Processing Options Data Object List (PDOL)',
            '9F39': 'Point-of-Service (POS) Entry Mode',
            '9F3A': 'Amount, Reference Currency',
            '9F3B': 'Application Reference Currency',
            '9F3C': 'Transaction Reference Currency Code',
            '9F3D': 'Transaction Reference Currency Exponent',
            '9F40': 'Additional Terminal Capabilities',
            '9F41': 'Transaction Sequence Counter',
            '9F42': 'Application Currency Code',
            '9F43': 'Application Reference Currency Exponent',
            '9F44': 'Application Currency Exponent',
            '9F45': 'Data Authentication Code',
            '9F46': 'ICC Public Key Certificate',
            '9F47': 'ICC Public Key Exponent',
            '9F48': 'ICC Public Key Remainder',
            '9F49': 'Dynamic Data Authentication Data Object List (DDOL)',
            '9F4A': 'Static Data Authentication Tag List',
            '9F4B': 'Signed Dynamic Application Data',
            '9F4C': 'ICC Dynamic Number',
            '9F4D': 'Log Entry',
            '9F4E': 'Merchant Name and Location',
            '9F53': 'Transaction Category Code',
            '9F6E': 'Unknown Tag',
            '9F74': 'VLP Issuer Authorization Code',
            '9F75': 'Cumulative Total Transaction Amount Limit',
            '9F76': 'Secondary PIN Try Counter',
            '9F77': 'VLP Funds Limit',
            '9F7F': 'Card Production Life Cycle (CPLC) History File Identifiers',
            'DF01': 'Reference Control Parameter',
        }
    
    @handle_errors("TLV parsing", return_on_error=[])
    def parse_tlv_data(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Parse TLV (Tag-Length-Value) data structures.
        
        Args:
            data: Raw bytes containing TLV data
            
        Returns:
            List of parsed TLV entries
        """
        entries = []
        offset = 0

        try:
            while offset < len(data):
                if offset + 1 >= len(data):
                    break

                # Parse tag (1 or 2 bytes)
                tag_byte1 = data[offset]
                offset += 1

                if (tag_byte1 & 0x1F) == 0x1F:  # Multi-byte tag
                    if offset >= len(data):
                        break
                    tag_byte2 = data[offset]
                    offset += 1
                    tag = f"{tag_byte1:02X}{tag_byte2:02X}"
                else:
                    tag = f"{tag_byte1:02X}"

                # Parse length
                if offset >= len(data):
                    break

                length_byte = data[offset]
                offset += 1

                if length_byte & 0x80:  # Long form length
                    length_bytes = length_byte & 0x7F
                    if length_bytes == 0 or offset + length_bytes > len(data):
                        break

                    length = 0
                    for i in range(length_bytes):
                        length = (length << 8) + data[offset + i]
                    offset += length_bytes
                else:
                    length = length_byte

                # Parse value
                if offset + length > len(data):
                    break

                value = data[offset:offset + length]
                offset += length

                entries.append({
                    'tag': tag,
                    'length': length,
                    'value': value
                })

                # Safety check to prevent infinite loops
                if len(entries) > 1000:
                    break

        except Exception as e:
            self.logger.warning(f"TLV parsing failed, attempting pattern search: {e}")
            # If parsing fails, try to find hex patterns in the data
            entries.extend(self._search_tlv_patterns(data))

        return entries
    
    def _search_tlv_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Search for TLV patterns when structured parsing fails."""
        entries = []
        hex_string = data.hex().upper()
        
        # Look for common EMV tag patterns
        common_tags = ['9F02', '9F03', '9F1A', '5F2A', '82', '95', '9A', '9C', '9F37', '5A']

        for tag in common_tags:
            pos = 0
            while pos < len(hex_string):
                pos = hex_string.find(tag, pos)
                if pos == -1:
                    break

                # Try to extract length and value
                try:
                    if pos + len(tag) + 2 < len(hex_string):
                        length_hex = hex_string[pos + len(tag):pos + len(tag) + 2]
                        length = int(length_hex, 16)

                        if length <= 128 and pos + len(tag) + 2 + (length * 2) <= len(hex_string):
                            value_hex = hex_string[pos + len(tag) + 2:pos + len(tag) + 2 + (length * 2)]
                            value = bytes.fromhex(value_hex)

                            entries.append({
                                'tag': tag,
                                'length': length,
                                'value': value
                            })
                except Exception:
                    pass

                pos += len(tag)

        return entries
    
    def get_emv_tag_description(self, tag: str) -> str:
        """Get description for EMV tag."""
        return self.emv_tags.get(tag, 'Unknown Tag')
    
    @handle_errors("EMV tag interpretation", return_on_error=None)
    def interpret_emv_tag(self, tag: str, value: bytes) -> Optional[str]:
        """
        Interpret EMV tag values based on their meaning.
        
        Args:
            tag: EMV tag identifier
            value: Tag value as bytes
            
        Returns:
            Human-readable interpretation or None
        """
        try:
            if tag == '9F02' or tag == '9F03':  # Amount fields
                if len(value) == 6:
                    amount = int.from_bytes(value, 'big')
                    return f"Amount: {amount/100:.2f}"
                    
            elif tag == '5F2A' or tag == '9F1A':  # Currency/Country codes
                if len(value) == 2:
                    code = int.from_bytes(value, 'big')
                    return f"Code: {code}"
                    
            elif tag == '9A':  # Transaction Date
                if len(value) == 3:
                    date_str = value.hex()
                    return f"Date: 20{date_str[0:2]}-{date_str[2:4]}-{date_str[4:6]}"
                    
            elif tag == '9C':  # Transaction Type
                if len(value) == 1:
                    trans_types = {0x00: 'Purchase', 0x01: 'Cash', 0x20: 'Refund'}
                    return trans_types.get(value[0], f'Type: {value[0]:02X}')
                    
            elif tag == '95':  # Terminal Verification Results
                if len(value) == 5:
                    return f"TVR: {value.hex().upper()}"
                    
            elif tag == '82':  # Application Interchange Profile
                if len(value) == 2:
                    aip = int.from_bytes(value, 'big')
                    features = []
                    if aip & 0x8000:
                        features.append('SDA')
                    if aip & 0x4000:
                        features.append('DDA')
                    if aip & 0x2000:
                        features.append('Cardholder Verification')
                    if aip & 0x1000:
                        features.append('Terminal Risk Management')
                    if aip & 0x0800:
                        features.append('Issuer Authentication')
                    if aip & 0x0400:
                        features.append('CDA')
                    return f"Features: {', '.join(features) if features else 'None'}"
                    
            elif tag in ['5F20']:  # Cardholder name
                try:
                    return f"Name: '{value.decode('utf-8').strip()}'"
                except Exception:
                    return f"Name: '{value.decode('latin-1').strip()}'"
                    
            elif tag in ['50', '9F12']:  # Application labels
                try:
                    return f"Label: '{value.decode('utf-8').strip()}'"
                except Exception:
                    return f"Label: '{value.decode('latin-1').strip()}'"
                    
        except Exception as e:
            self.logger.debug(f"Tag interpretation failed for {tag}: {e}")
            
        return None
    
    @handle_errors("TLV file processing", return_on_error=[])
    def process_tlv_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Process a TLV file and return parsed entries.
        
        Args:
            file_path: Path to TLV file
            
        Returns:
            List of parsed TLV entries with descriptions
        """
        if not os.path.exists(file_path):
            self.logger.error(f"File not found: {file_path}")
            return []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Try to decode as text first (for hex strings)
            try:
                text_content = content.decode('utf-8').strip()
                # Check if it looks like hex data
                if all(c in '0123456789ABCDEFabcdef \n\r\t' for c in text_content.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')):
                    # Convert hex string to bytes
                    hex_data = ''.join(text_content.split())
                    if len(hex_data) % 2 == 0:
                        content = bytes.fromhex(hex_data)
                        self.logger.info("Converted hex string to binary data")
            except UnicodeDecodeError:
                pass
            
            # Parse TLV data
            tlv_entries = self.parse_tlv_data(content)
            
            # Add descriptions and interpretations
            for entry in tlv_entries:
                entry['description'] = self.get_emv_tag_description(entry['tag'])
                entry['interpretation'] = self.interpret_emv_tag(entry['tag'], entry['value'])
            
            self.logger.info(f"Processed {len(tlv_entries)} TLV entries from {file_path}")
            return tlv_entries
            
        except Exception as e:
            self.logger.error(f"Error processing TLV file {file_path}: {e}")
            return []
    
    @handle_errors("Transaction analysis", return_on_error={})
    def analyze_transaction(self, tlv_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze a transaction from TLV entries.
        
        Args:
            tlv_entries: List of TLV entries from transaction
            
        Returns:
            Analysis results dictionary
        """
        analysis = {
            'card_info': {},
            'transaction_info': {},
            'security_features': {},
            'risk_assessment': 'unknown',
            'anomalies': []
        }
        
        for entry in tlv_entries:
            tag = entry['tag']
            value = entry['value']
            
            # Extract card information
            if tag == '5A':  # PAN
                analysis['card_info']['pan'] = value.hex()
            elif tag == '5F20':  # Cardholder name
                try:
                    analysis['card_info']['cardholder'] = value.decode('utf-8').strip()
                except:
                    analysis['card_info']['cardholder'] = value.decode('latin-1').strip()
            elif tag == '5F24':  # Expiry date
                analysis['card_info']['expiry'] = value.hex()
            
            # Extract transaction information
            elif tag == '9F02':  # Authorized amount
                if len(value) == 6:
                    amount = int.from_bytes(value, 'big')
                    analysis['transaction_info']['amount'] = amount / 100
            elif tag == '9A':  # Transaction date
                analysis['transaction_info']['date'] = value.hex()
            elif tag == '9C':  # Transaction type
                analysis['transaction_info']['type'] = value[0] if value else 0
            
            # Extract security features
            elif tag == '82':  # AIP
                aip = int.from_bytes(value, 'big') if len(value) == 2 else 0
                analysis['security_features']['sda'] = bool(aip & 0x8000)
                analysis['security_features']['dda'] = bool(aip & 0x4000)
                analysis['security_features']['cda'] = bool(aip & 0x0400)
            elif tag == '95':  # TVR
                analysis['security_features']['tvr'] = value.hex()
        
        # Risk assessment
        if 'amount' in analysis['transaction_info']:
            amount = analysis['transaction_info']['amount']
            if amount > 1000:
                analysis['risk_assessment'] = 'high'
            elif amount > 100:
                analysis['risk_assessment'] = 'medium'
            else:
                analysis['risk_assessment'] = 'low'
        
        # Check for anomalies
        if not analysis['security_features'].get('dda', False):
            analysis['anomalies'].append('DDA not enabled - potential replay risk')
        
        if 'tvr' in analysis['security_features']:
            tvr_hex = analysis['security_features']['tvr']
            if len(tvr_hex) >= 2 and tvr_hex[:2] != '00':
                analysis['anomalies'].append('Terminal verification failures detected')
        
        return analysis
    
    def format_hex_dump(self, data: bytes, offset: int = 0, width: int = 16) -> str:
        """
        Format binary data as hex dump.
        
        Args:
            data: Binary data to format
            offset: Starting offset for display
            width: Bytes per line
            
        Returns:
            Formatted hex dump string
        """
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i + width]
            hex_part = ' '.join([f'{b:02X}' for b in chunk])
            ascii_part = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
            
            line = f"{offset + i:08X}: {hex_part:<{width*3}} |{ascii_part}|"
            lines.append(line)
        
        return '\n'.join(lines)