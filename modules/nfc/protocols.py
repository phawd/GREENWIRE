"""
GREENWIRE NFC Protocols
=======================
Implementation of NFC protocols (ISO14443, etc.).
"""

from typing import Dict, List, Optional, Union  # noqa: F401
from dataclasses import dataclass
from enum import Enum


class APDUType(Enum):
    """APDU command types."""
    SELECT = "SELECT"
    READ_RECORD = "READ_RECORD" 
    GET_DATA = "GET_DATA"
    VERIFY = "VERIFY"
    GET_CHALLENGE = "GET_CHALLENGE"
    EXTERNAL_AUTHENTICATE = "EXTERNAL_AUTHENTICATE"
    INTERNAL_AUTHENTICATE = "INTERNAL_AUTHENTICATE"
    GENERATE_AC = "GENERATE_AC"
    GET_PROCESSING_OPTIONS = "GET_PROCESSING_OPTIONS"


@dataclass
class APDU:
    """APDU command structure."""
    cla: int  # Class byte
    ins: int  # Instruction byte
    p1: int   # Parameter 1
    p2: int   # Parameter 2
    lc: Optional[int] = None  # Length of command data
    data: Optional[bytes] = None  # Command data
    le: Optional[int] = None  # Expected length of response data
    
    def to_bytes(self) -> bytes:
        """Convert APDU to bytes."""
        result = bytes([self.cla, self.ins, self.p1, self.p2])
        
        if self.data is not None:
            result += bytes([len(self.data)]) + self.data
        elif self.lc is not None:
            result += bytes([self.lc])
        
        if self.le is not None:
            result += bytes([self.le])
        
        return result
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'APDU':
        """Parse APDU from bytes."""
        if len(data) < 4:
            raise ValueError("APDU must be at least 4 bytes")
        
        cla, ins, p1, p2 = data[:4]
        
        if len(data) == 4:
            return cls(cla, ins, p1, p2)
        elif len(data) == 5:
            return cls(cla, ins, p1, p2, le=data[4])
        else:
            lc = data[4]
            if len(data) == 5 + lc:
                return cls(cla, ins, p1, p2, lc=lc, data=data[5:5+lc])
            elif len(data) == 5 + lc + 1:
                return cls(cla, ins, p1, p2, lc=lc, data=data[5:5+lc], le=data[5+lc])
            else:
                raise ValueError("Invalid APDU length")
    
    def get_type(self) -> Optional[APDUType]:
        """Determine APDU command type."""
        if self.ins == 0xA4:
            return APDUType.SELECT
        elif self.ins == 0xB2:
            return APDUType.READ_RECORD
        elif self.ins == 0xCA:
            return APDUType.GET_DATA
        elif self.ins == 0x20:
            return APDUType.VERIFY
        elif self.ins == 0x84:
            return APDUType.GET_CHALLENGE
        elif self.ins == 0x82:
            return APDUType.EXTERNAL_AUTHENTICATE
        elif self.ins == 0x88:
            return APDUType.INTERNAL_AUTHENTICATE
        elif self.ins == 0xAE:
            return APDUType.GENERATE_AC
        elif self.ins == 0xA8:
            return APDUType.GET_PROCESSING_OPTIONS
        else:
            return None


class ISO14443A:
    """ISO 14443 Type A protocol implementation."""
    
    def __init__(self):
        """Initialize ISO14443A protocol."""
        self.anticollision_levels = {
            1: b'\x93',  # CL1
            2: b'\x95',  # CL2
            3: b'\x97',  # CL3
        }
    
    def anticollision(self, level: int = 1) -> bytes:
        """Perform anticollision at specified level."""
        if level not in self.anticollision_levels:
            raise ValueError(f"Invalid anticollision level: {level}")
        
        return self.anticollision_levels[level] + b'\x20'
    
    def select(self, uid: bytes, level: int = 1) -> bytes:
        """Select card with given UID."""
        if level not in self.anticollision_levels:
            raise ValueError(f"Invalid select level: {level}")
        
        cmd = self.anticollision_levels[level] + b'\x70' + uid
        return cmd
    
    def halt(self) -> bytes:
        """Send HALT command."""
        return b'\x50\x00'


class EMVProtocol:
    """EMV protocol implementation."""
    
    # Common EMV AIDs
    AIDS = {
        'VISA': bytes([0xA0, 0x00, 0x00, 0x00, 0x03]),
        'MASTERCARD': bytes([0xA0, 0x00, 0x00, 0x00, 0x04]),
        'AMEX': bytes([0xA0, 0x00, 0x00, 0x00, 0x25]),
        'DISCOVER': bytes([0xA0, 0x00, 0x00, 0x01, 0x52]),
    }
    
    # EMV tags
    TAGS = {
        'AID': 0x84,
        'APPLICATION_LABEL': 0x50,
        'CARD_HOLDER_NAME': 0x5F20,
        'PAN': 0x5A,
        'EXPIRY_DATE': 0x5F24,
        'TRACK2_DATA': 0x57,
        'AFL': 0x94,
        'ATC': 0x9F36,
        'CVM_LIST': 0x8E,
    }
    
    def __init__(self):
        """Initialize EMV protocol."""
        pass
    
    def select_aid(self, aid: Union[str, bytes]) -> APDU:
        """Create SELECT AID APDU."""
        if isinstance(aid, str):
            if aid.upper() in self.AIDS:
                aid_bytes = self.AIDS[aid.upper()]
            else:
                raise ValueError(f"Unknown AID: {aid}")
        else:
            aid_bytes = aid
        
        return APDU(0x00, 0xA4, 0x04, 0x00, lc=len(aid_bytes), data=aid_bytes, le=0)
    
    def get_processing_options(self, pdol_data: bytes = None) -> APDU:
        """Create GET PROCESSING OPTIONS APDU."""
        if pdol_data is None:
            pdol_data = b'\x83\x00'  # Empty PDOL
        
        return APDU(0x80, 0xA8, 0x00, 0x00, lc=len(pdol_data), data=pdol_data, le=0)
    
    def read_record(self, record: int, sfi: int) -> APDU:
        """Create READ RECORD APDU."""
        return APDU(0x00, 0xB2, record, (sfi << 3) | 0x04, le=0)
    
    def get_data(self, tag: Union[int, str]) -> APDU:
        """Create GET DATA APDU."""
        if isinstance(tag, str):
            if tag.upper() in self.TAGS:
                tag_value = self.TAGS[tag.upper()]
            else:
                raise ValueError(f"Unknown tag: {tag}")
        else:
            tag_value = tag
        
        # Convert tag to bytes (assuming 2-byte tags)
        tag_bytes = tag_value.to_bytes(2, 'big')
        return APDU(0x00, 0xCA, tag_bytes[0], tag_bytes[1], le=0)
    
    def generate_ac(self, ac_type: int, cdol_data: bytes) -> APDU:
        """Create GENERATE AC APDU."""
        return APDU(0x80, 0xAE, ac_type, 0x00, lc=len(cdol_data), data=cdol_data, le=0)