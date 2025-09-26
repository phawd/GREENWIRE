#!/usr/bin/env python3
"""APDU4J Command Definitions for GREENWIRE Integration.

Hardcoded APDU command structures and constants extracted from martinpaljak/apdu4j
CommandAPDU.java implementation with full ISO 7816-4 compliance.

Source: https://github.com/martinpaljak/apdu4j
License: MIT (following original project)
"""

from typing import Dict, List, Optional, Tuple, Union  # noqa: F401
import logging

logger = logging.getLogger(__name__)

# ISO 7816-4 APDU Cases (from CommandAPDU.java)
APDU_CASE_1 = 1  # No data, no response expected
APDU_CASE_2S = 2  # No data, response expected (short Le)
APDU_CASE_2E = 22  # No data, response expected (extended Le)
APDU_CASE_3S = 3  # Data sent, no response expected (short Lc)
APDU_CASE_3E = 33  # Data sent, no response expected (extended Lc)
APDU_CASE_4S = 4  # Data sent, response expected (short Lc, Le)
APDU_CASE_4E = 44  # Data sent, response expected (extended Lc, Le)

# ISO 7816-4 Status Words
SW_SUCCESS = 0x9000
SW_MORE_DATA = 0x6100
SW_WRONG_LENGTH = 0x6700
SW_SECURITY_NOT_SATISFIED = 0x6982
SW_FILE_NOT_FOUND = 0x6A82
SW_WRONG_PARAMETERS = 0x6A86
SW_INSTRUCTION_NOT_SUPPORTED = 0x6D00
SW_CLASS_NOT_SUPPORTED = 0x6E00

# Common CLA (Class) bytes
CLA_ISO = 0x00      # ISO 7816-4 standard class
CLA_PROPRIETARY = 0x80  # Proprietary class
CLA_SECURE_MSG = 0x04   # Secure messaging

# Common INS (Instruction) bytes
INS_SELECT = 0xA4       # SELECT command
INS_READ_BINARY = 0xB0  # READ BINARY
INS_UPDATE_BINARY = 0xD6 # UPDATE BINARY
INS_READ_RECORD = 0xB2   # READ RECORD
INS_UPDATE_RECORD = 0xDC # UPDATE RECORD
INS_APPEND_RECORD = 0xE2 # APPEND RECORD
INS_GET_DATA = 0xCA      # GET DATA
INS_PUT_DATA = 0xDA      # PUT DATA
INS_VERIFY = 0x20        # VERIFY PIN
INS_CHANGE_PIN = 0x24    # CHANGE PIN
INS_UNBLOCK_PIN = 0x2C   # UNBLOCK PIN
INS_INTERNAL_AUTH = 0x88 # INTERNAL AUTHENTICATE
INS_EXTERNAL_AUTH = 0x82 # EXTERNAL AUTHENTICATE
INS_GET_CHALLENGE = 0x84 # GET CHALLENGE

class APDU4JCommand:
    """APDU command structure based on martinpaljak/apdu4j CommandAPDU implementation."""
    
    def __init__(self, cla: int, ins: int, p1: int, p2: int, 
                 data: Optional[bytes] = None, le: Optional[int] = None):
        """Initialize APDU command.
        
        Args:
            cla: Class byte (0x00-0xFF)
            ins: Instruction byte (0x00-0xFF) 
            p1: Parameter 1 (0x00-0xFF)
            p2: Parameter 2 (0x00-0xFF)
            data: Command data (optional)
            le: Expected response length (optional)
        """
        self.cla = cla & 0xFF
        self.ins = ins & 0xFF
        self.p1 = p1 & 0xFF
        self.p2 = p2 & 0xFF
        self.data = data if data else b''
        self.le = le
        
        # Determine APDU case based on parameters
        self.case = self._determine_case()
        
    def _determine_case(self) -> int:
        """Determine APDU case based on data and expected response length."""
        has_data = len(self.data) > 0
        has_le = self.le is not None
        is_extended = len(self.data) > 255 or (self.le is not None and self.le > 256)
        
        if not has_data and not has_le:
            return APDU_CASE_1
        elif not has_data and has_le:
            return APDU_CASE_2E if is_extended else APDU_CASE_2S
        elif has_data and not has_le:
            return APDU_CASE_3E if is_extended else APDU_CASE_3S
        else:  # has_data and has_le
            return APDU_CASE_4E if is_extended else APDU_CASE_4S
            
    def to_bytes(self) -> bytes:
        """Convert APDU command to byte array following ISO 7816-4 encoding."""
        apdu = bytes([self.cla, self.ins, self.p1, self.p2])
        
        if self.case == APDU_CASE_1:
            # Case 1: No Lc, no Le, no data
            return apdu
            
        elif self.case == APDU_CASE_2S:
            # Case 2S: No Lc, short Le
            le = 0 if self.le == 256 else self.le
            return apdu + bytes([le])
            
        elif self.case == APDU_CASE_2E:
            # Case 2E: No Lc, extended Le
            if self.le == 65536:
                return apdu + b'\x00\x00\x00'
            else:
                return apdu + b'\x00' + self.le.to_bytes(2, 'big')
                
        elif self.case == APDU_CASE_3S:
            # Case 3S: Short Lc, no Le
            lc = len(self.data)
            return apdu + bytes([lc]) + self.data
            
        elif self.case == APDU_CASE_3E:
            # Case 3E: Extended Lc, no Le
            lc = len(self.data)
            return apdu + b'\x00' + lc.to_bytes(2, 'big') + self.data
            
        elif self.case == APDU_CASE_4S:
            # Case 4S: Short Lc, short Le
            lc = len(self.data)
            le = 0 if self.le == 256 else (self.le if self.le is not None else 0)
            return apdu + bytes([lc]) + self.data + bytes([le])
            
        elif self.case == APDU_CASE_4E:
            # Case 4E: Extended Lc, extended Le
            lc = len(self.data)
            apdu += b'\x00' + lc.to_bytes(2, 'big') + self.data
            if self.le == 65536:
                apdu += b'\x00\x00'
            else:
                apdu += self.le.to_bytes(2, 'big')
            return apdu
            
        return apdu
        
    def to_hex(self) -> str:
        """Convert APDU command to hex string."""
        return self.to_bytes().hex().upper()
        
    def __str__(self) -> str:
        """String representation of APDU command."""
        return f"APDU(CLA={self.cla:02X}, INS={self.ins:02X}, P1={self.p1:02X}, P2={self.p2:02X}, Case={self.case})"
        
    def __repr__(self) -> str:
        """Detailed representation of APDU command."""
        return f"APDU4JCommand(cla=0x{self.cla:02X}, ins=0x{self.ins:02X}, p1=0x{self.p1:02X}, p2=0x{self.p2:02X}, data={self.data.hex() if self.data else 'None'}, le={self.le})"

# Predefined APDU Commands from apdu4j usage patterns
APDU_COMMANDS = {
    # File System Commands
    'SELECT_MF': APDU4JCommand(CLA_ISO, INS_SELECT, 0x00, 0x0C),  # Select Master File
    'SELECT_ADF': APDU4JCommand(CLA_ISO, INS_SELECT, 0x04, 0x00),  # Select by AID
    'SELECT_EF': APDU4JCommand(CLA_ISO, INS_SELECT, 0x02, 0x0C),   # Select Elementary File
    'SELECT_DF': APDU4JCommand(CLA_ISO, INS_SELECT, 0x01, 0x0C),   # Select Dedicated File
    
    # Data Access Commands
    'READ_BINARY': APDU4JCommand(CLA_ISO, INS_READ_BINARY, 0x00, 0x00, le=256),
    'UPDATE_BINARY': APDU4JCommand(CLA_ISO, INS_UPDATE_BINARY, 0x00, 0x00),
    'READ_RECORD': APDU4JCommand(CLA_ISO, INS_READ_RECORD, 0x01, 0x04, le=256),
    'UPDATE_RECORD': APDU4JCommand(CLA_ISO, INS_UPDATE_RECORD, 0x01, 0x04),
    'APPEND_RECORD': APDU4JCommand(CLA_ISO, INS_APPEND_RECORD, 0x00, 0x04),
    
    # Security Commands  
    'VERIFY_PIN': APDU4JCommand(CLA_ISO, INS_VERIFY, 0x00, 0x80),
    'CHANGE_PIN': APDU4JCommand(CLA_ISO, INS_CHANGE_PIN, 0x00, 0x80),
    'UNBLOCK_PIN': APDU4JCommand(CLA_ISO, INS_UNBLOCK_PIN, 0x00, 0x80),
    'GET_CHALLENGE': APDU4JCommand(CLA_ISO, INS_GET_CHALLENGE, 0x00, 0x00, le=8),
    'INTERNAL_AUTH': APDU4JCommand(CLA_ISO, INS_INTERNAL_AUTH, 0x00, 0x00),
    'EXTERNAL_AUTH': APDU4JCommand(CLA_ISO, INS_EXTERNAL_AUTH, 0x00, 0x00),
    
    # Data Object Commands
    'GET_DATA': APDU4JCommand(CLA_ISO, INS_GET_DATA, 0x00, 0x00, le=256),
    'PUT_DATA': APDU4JCommand(CLA_ISO, INS_PUT_DATA, 0x00, 0x00),
    
    # GlobalPlatform Commands (from apdu4j tool integration)
    'GP_GET_STATUS': APDU4JCommand(0x80, 0xF2, 0x80, 0x00, le=256),
    'GP_SELECT': APDU4JCommand(CLA_ISO, INS_SELECT, 0x04, 0x00),
    'GP_INSTALL': APDU4JCommand(0x80, 0xE6, 0x02, 0x00),
    'GP_LOAD': APDU4JCommand(0x80, 0xE8, 0x00, 0x00),
    'GP_DELETE': APDU4JCommand(0x80, 0xE4, 0x00, 0x00),
    'GP_GET_DATA': APDU4JCommand(0x80, 0xCA, 0x00, 0x00, le=256),
}

# PC/SC Reader Commands (from apdu4j RemoteTerminal)
PCSC_COMMANDS = {
    'PCSC_GET_UID': APDU4JCommand(0xFF, 0xCA, 0x00, 0x00, le=10),  # Get card UID
    'PCSC_LOAD_KEY': APDU4JCommand(0xFF, 0x82, 0x00, 0x00),        # Load authentication key
    'PCSC_AUTH': APDU4JCommand(0xFF, 0x86, 0x00, 0x00),            # Authenticate
    'PCSC_READ_BLOCK': APDU4JCommand(0xFF, 0xB0, 0x00, 0x00, le=16), # Read block
    'PCSC_WRITE_BLOCK': APDU4JCommand(0xFF, 0xD6, 0x00, 0x00),     # Write block
}

def create_select_aid_command(aid: Union[str, bytes]) -> APDU4JCommand:
    """Create SELECT command for specific Application ID.
    
    Args:
        aid: Application ID as hex string or bytes
        
    Returns:
        APDU4JCommand for selecting the application
    """
    if isinstance(aid, str):
        aid_bytes = bytes.fromhex(aid.replace(' ', ''))
    else:
        aid_bytes = aid
        
    return APDU4JCommand(CLA_ISO, INS_SELECT, 0x04, 0x00, aid_bytes, le=256)

def create_pin_verify_command(pin: Union[str, bytes], pin_id: int = 0x80) -> APDU4JCommand:
    """Create PIN verification command.
    
    Args:
        pin: PIN value as string or bytes
        pin_id: PIN identifier (default 0x80)
        
    Returns:
        APDU4JCommand for PIN verification
    """
    if isinstance(pin, str):
        pin_bytes = pin.encode('ascii')
    else:
        pin_bytes = pin
        
    return APDU4JCommand(CLA_ISO, INS_VERIFY, 0x00, pin_id, pin_bytes)

def create_get_data_command(tag: int, le: int = 256) -> APDU4JCommand:
    """Create GET DATA command for specific tag.
    
    Args:
        tag: Data object tag (16-bit)
        le: Expected response length
        
    Returns:
        APDU4JCommand for getting data object
    """
    p1 = (tag >> 8) & 0xFF
    p2 = tag & 0xFF
    return APDU4JCommand(CLA_ISO, INS_GET_DATA, p1, p2, le=le)

def parse_apdu_response(response: bytes) -> Dict[str, any]:
    """Parse APDU response following ISO 7816-4 format.
    
    Args:
        response: Response bytes from card
        
    Returns:
        Dictionary with parsed response data
    """
    if len(response) < 2:
        return {'error': 'Invalid response length'}
        
    data = response[:-2]
    sw1 = response[-2]
    sw2 = response[-1]
    sw = (sw1 << 8) | sw2
    
    # Handle special cases for status word interpretation
    if sw1 == 0x61:
        status_text = f'More data available ({sw2} bytes)'
    else:
        status_info = {
            SW_SUCCESS: 'Success',
            SW_WRONG_LENGTH: 'Wrong length',
            SW_SECURITY_NOT_SATISFIED: 'Security condition not satisfied',
            SW_FILE_NOT_FOUND: 'File not found',
            SW_WRONG_PARAMETERS: 'Wrong parameters',
            SW_INSTRUCTION_NOT_SUPPORTED: 'Instruction not supported',
            SW_CLASS_NOT_SUPPORTED: 'Class not supported'
        }
        status_text = status_info.get(sw, f'Unknown status (0x{sw:04X})')
    
    return {
        'data': data,
        'sw1': sw1,
        'sw2': sw2,
        'sw': sw,
        'success': sw == SW_SUCCESS,
        'status': status_text
    }

class APDU4JInterface:
    """High-level interface for APDU4J command operations."""
    
    def __init__(self, communicator=None):
        """Initialize with APDU communicator.
        
        Args:
            communicator: APDU communication handler
        """
        self.communicator = communicator
        self.logger = logging.getLogger(__name__)
        
    def send_command(self, command: APDU4JCommand) -> Dict[str, any]:
        """Send APDU command and parse response.
        
        Args:
            command: APDU4JCommand to send
            
        Returns:
            Parsed response dictionary
        """
        if not self.communicator:
            return {'error': 'No communicator configured'}
            
        try:
            command_hex = command.to_hex()
            self.logger.debug(f"Sending APDU: {command_hex}")
            
            # Use existing APDU communicator interface
            response_data, sw = self.communicator.send_apdu(command_hex)
            
            if response_data is None:
                return {'error': 'Communication failed'}
                
            # Combine data and status word
            if sw:
                sw_bytes = bytes.fromhex(sw)
                full_response = bytes.fromhex(response_data) + sw_bytes if response_data else sw_bytes
            else:
                full_response = bytes.fromhex(response_data) if response_data else b''
                
            return parse_apdu_response(full_response)
            
        except Exception as e:
            self.logger.error(f"APDU command failed: {e}")
            return {'error': str(e)}
    
    def select_application(self, aid: Union[str, bytes]) -> Dict[str, any]:
        """Select application by AID.
        
        Args:
            aid: Application ID
            
        Returns:
            Selection response
        """
        command = create_select_aid_command(aid)
        return self.send_command(command)
        
    def verify_pin(self, pin: Union[str, bytes], pin_id: int = 0x80) -> Dict[str, any]:
        """Verify PIN.
        
        Args:
            pin: PIN value
            pin_id: PIN identifier
            
        Returns:
            Verification response
        """
        command = create_pin_verify_command(pin, pin_id)
        return self.send_command(command)
        
    def get_data(self, tag: int, le: int = 256) -> Dict[str, any]:
        """Get data object by tag.
        
        Args:
            tag: Data object tag
            le: Expected length
            
        Returns:
            Data object response
        """
        command = create_get_data_command(tag, le)
        return self.send_command(command)

# Export main classes and functions
__all__ = [
    'APDU4JCommand',
    'APDU4JInterface', 
    'APDU_COMMANDS',
    'PCSC_COMMANDS',
    'create_select_aid_command',
    'create_pin_verify_command',
    'create_get_data_command',
    'parse_apdu_response'
]