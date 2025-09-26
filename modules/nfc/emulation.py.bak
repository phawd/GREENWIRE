"""
GREENWIRE NFC Emulation
=======================
EMV card emulation and testing utilities.
"""

import logging
from typing import Dict, List, Optional, Tuple
from .core import NFCTarget, NFCProtocol
from .protocols import APDU, EMVProtocol


class EMVEmulator:
    """EMV card emulator for testing."""
    
    def __init__(self, card_profile: str = "visa"):
        """Initialize EMV emulator with card profile."""
        self.card_profile = card_profile.lower()
        self.logger = logging.getLogger("greenwire_emv")
        self.emv = EMVProtocol()
        self._initialize_card_data()
    
    def _initialize_card_data(self):
        """Initialize card data based on profile."""
        if self.card_profile == "visa":
            self.aid = EMVProtocol.AIDS['VISA']
            self.pan = "4111111111111111"
            self.expiry = "1225"
            self.cardholder_name = "GREENWIRE TEST CARD"
            self.application_label = "VISA CREDIT"
        elif self.card_profile == "mastercard":
            self.aid = EMVProtocol.AIDS['MASTERCARD'] 
            self.pan = "5555555555554444"
            self.expiry = "1225"
            self.cardholder_name = "GREENWIRE TEST CARD"
            self.application_label = "MASTERCARD"
        elif self.card_profile == "amex":
            self.aid = EMVProtocol.AIDS['AMEX']
            self.pan = "378282246310005"
            self.expiry = "1225"
            self.cardholder_name = "GREENWIRE TEST CARD"
            self.application_label = "AMERICAN EXPRESS"
        else:
            # Default to Visa
            self.aid = EMVProtocol.AIDS['VISA']
            self.pan = "4111111111111111"
            self.expiry = "1225"
            self.cardholder_name = "GREENWIRE TEST CARD"
            self.application_label = "VISA CREDIT"
    
    def process_apdu(self, apdu: APDU) -> Tuple[bytes, int, int]:
        """
        Process APDU command and return response.
        
        Returns:
            Tuple of (data, sw1, sw2)
        """
        cmd_type = apdu.get_type()
        
        if cmd_type is None:
            self.logger.warning(f"Unknown APDU command: {apdu.ins:02X}")
            return b'', 0x6D, 0x00  # Instruction not supported
        
        try:
            if apdu.ins == 0xA4:  # SELECT
                return self._handle_select(apdu)
            elif apdu.ins == 0xA8:  # GET PROCESSING OPTIONS
                return self._handle_gpo(apdu)
            elif apdu.ins == 0xB2:  # READ RECORD
                return self._handle_read_record(apdu)
            elif apdu.ins == 0xCA:  # GET DATA
                return self._handle_get_data(apdu)
            elif apdu.ins == 0xAE:  # GENERATE AC
                return self._handle_generate_ac(apdu)
            else:
                return b'', 0x6D, 0x00  # Instruction not supported
                
        except Exception as e:
            self.logger.error(f"Error processing APDU: {e}")
            return b'', 0x6F, 0x00  # Unknown error
    
    def _handle_select(self, apdu: APDU) -> Tuple[bytes, int, int]:
        """Handle SELECT APDU."""
        if apdu.p1 == 0x04 and apdu.p2 == 0x00:  # Select by name (AID)
            if apdu.data == self.aid:
                # Return FCI template
                fci_data = (
                    b'\x84' + bytes([len(self.aid)]) + self.aid +  # AID
                    b'\x50' + bytes([len(self.application_label)]) + self.application_label.encode('ascii')  # Application Label
                )
                fci = b'\x6F' + bytes([len(fci_data)]) + fci_data
                return fci, 0x90, 0x00
            else:
                return b'', 0x6A, 0x82  # File not found
        else:
            return b'', 0x6A, 0x86  # Incorrect parameters P1-P2
    
    def _handle_gpo(self, apdu: APDU) -> Tuple[bytes, int, int]:
        """Handle GET PROCESSING OPTIONS."""
        # Simple GPO response
        aip = b'\x78\x00'  # Application Interchange Profile
        afl = b'\x08\x01\x01\x00\x10\x01\x01\x01'  # Application File Locator
        
        response_data = b'\x77' + bytes([len(aip) + len(afl) + 4]) + \
                       b'\x82' + bytes([len(aip)]) + aip + \
                       b'\x94' + bytes([len(afl)]) + afl
        
        return response_data, 0x90, 0x00
    
    def _handle_read_record(self, apdu: APDU) -> Tuple[bytes, int, int]:
        """Handle READ RECORD."""
        record_num = apdu.p1
        sfi = (apdu.p2 >> 3) & 0x1F
        
        # Simulate record data based on SFI and record number
        if sfi == 1 and record_num == 1:
            # Main application record
            pan_data = b'\x5A' + bytes([len(self.pan)//2]) + bytes.fromhex(self.pan)
            exp_data = b'\x5F\x24' + b'\x03' + bytes.fromhex(self.expiry + '01')
            name_data = b'\x5F\x20' + bytes([len(self.cardholder_name)]) + self.cardholder_name.encode('ascii')
            
            record_data = pan_data + exp_data + name_data
            return b'\x70' + bytes([len(record_data)]) + record_data, 0x90, 0x00
        else:
            return b'', 0x6A, 0x83  # Record not found
    
    def _handle_get_data(self, apdu: APDU) -> Tuple[bytes, int, int]:
        """Handle GET DATA."""
        tag = (apdu.p1 << 8) | apdu.p2
        
        if tag == 0x9F13:  # Last online ATC register
            return b'\x9F\x13\x02\x00\x01', 0x90, 0x00
        elif tag == 0x9F17:  # PIN Try Counter
            return b'\x9F\x17\x01\x03', 0x90, 0x00
        elif tag == 0x9F36:  # Application Transaction Counter
            return b'\x9F\x36\x02\x00\x01', 0x90, 0x00
        else:
            return b'', 0x6A, 0x88  # Referenced data not found
    
    def _handle_generate_ac(self, apdu: APDU) -> Tuple[bytes, int, int]:
        """Handle GENERATE AC (Application Cryptogram)."""
        # Simulate cryptogram generation
        cryptogram = b'\x12\x34\x56\x78\x9A\xBC\xDE\xF0'
        atc = b'\x00\x01'
        
        response_data = (
            b'\x77\x0E' +
            b'\x9F\x26\x08' + cryptogram +  # Application Cryptogram
            b'\x9F\x36\x02' + atc           # ATC
        )
        
        return response_data, 0x90, 0x00
    
    def get_uid(self) -> bytes:
        """Get emulated card UID."""
        # Generate UID based on card profile
        if self.card_profile == "visa":
            return bytes([0x04, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11])
        elif self.card_profile == "mastercard":
            return bytes([0x04, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55])
        elif self.card_profile == "amex":
            return bytes([0x04, 0x37, 0x82, 0x82, 0x24, 0x63, 0x10])
        else:
            return bytes([0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])


def create_emulated_target(card_profile: str = "visa") -> Tuple[NFCTarget, EMVEmulator]:
    """Create an emulated NFC target with EMV emulator."""
    emulator = EMVEmulator(card_profile)
    uid = emulator.get_uid()
    target = NFCTarget(uid, NFCProtocol.ISO14443A)
    return target, emulator