"""
GREENWIRE NFC Core
==================
Core NFC device and communication functionality.
"""

import logging, time
from typing import Any, Dict, List, Optional  # noqa: F401
from enum import Enum


class NFCProtocol(Enum):
    """NFC protocol types."""
    ISO14443A = "ISO14443A"
    ISO14443B = "ISO14443B" 
    ISO15693 = "ISO15693"
    FELICA = "FeliCa"


class GreenwireNFCError(Exception):
    """Base exception for GREENWIRE NFC operations."""
    pass


class NFCTarget:
    """Represents an NFC target/card."""
    
    def __init__(self, uid: bytes, protocol: NFCProtocol, atr: Optional[bytes] = None):
        """Initialize NFC target."""
        self.uid = uid
        self.protocol = protocol
        self.atr = atr
        self.connected = False
        self._responses = {}
    
    def __str__(self):
        return f"NFCTarget(uid={self.uid.hex()}, protocol={self.protocol.value})"


class NFCDevice:
    """GREENWIRE NFC device emulator."""
    
    def __init__(self, device_path: str = "greenwire:emulated"):
        """Initialize NFC device."""
        self.device_path = device_path
        self.connected = False
        self.targets = []
        self.logger = logging.getLogger("greenwire_nfc")
    
    def open(self):
        """Open connection to NFC device."""
        self.logger.info(f"Opening NFC device: {self.device_path}")
        # In static mode, we simulate device opening
        if "emulated" in self.device_path:
            self.connected = True
            return True
        
        # For real devices, attempt to connect
        try:
            # Placeholder for actual device opening
            self.connected = True
            return True
        except Exception as e:
            self.logger.error(f"Failed to open NFC device: {e}")
            return False
    
    def close(self):
        """Close connection to NFC device."""
        if self.connected:
            self.logger.info("Closing NFC device")
            self.connected = False
            self.targets.clear()
    
    def sense(self, protocols: List[NFCProtocol] = None) -> List[NFCTarget]:
        """Sense for NFC targets."""
        if not self.connected:
            raise GreenwireNFCError("NFC device not connected")
        
        if protocols is None:
            protocols = [NFCProtocol.ISO14443A]
        
        self.logger.debug(f"Sensing for targets with protocols: {[p.value for p in protocols]}")
        
        # In emulation mode, return simulated targets
        if "emulated" in self.device_path:
            return self._simulate_targets(protocols)
        
        # For real devices, perform actual sensing
        return []
    
    def _simulate_targets(self, protocols: List[NFCProtocol]) -> List[NFCTarget]:
        """Simulate NFC targets for testing."""
        targets = []
        
        if NFCProtocol.ISO14443A in protocols:
            # Simulate EMV card
            emv_uid = bytes([0x04, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12])
            emv_target = NFCTarget(emv_uid, NFCProtocol.ISO14443A)
            targets.append(emv_target)
        
        self.targets = targets
        return targets
    
    def connect(self, target: NFCTarget) -> bool:
        """Connect to an NFC target."""
        if not self.connected:
            raise GreenwireNFCError("NFC device not connected")
        
        try:
            target.connected = True
            self.logger.info(f"Connected to target: {target}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to target: {e}")
            return False
    
    def disconnect(self, target: NFCTarget):
        """Disconnect from an NFC target."""
        if target.connected:
            target.connected = False
            self.logger.info(f"Disconnected from target: {target}")
    
    def transceive(self, target: NFCTarget, command: bytes, timeout: float = 1.0) -> bytes:
        """Send command to target and receive response."""
        if not target.connected:
            raise GreenwireNFCError("Target not connected")
        
        self.logger.debug(f"Sending command: {command.hex()}")
        
        # In emulation mode, simulate responses
        if "emulated" in self.device_path:
            response = self._simulate_response(target, command)
        else:
            # For real devices, send actual command
            response = self._send_command(command, timeout)
        
        self.logger.debug(f"Received response: {response.hex()}")
        return response
    
    def _simulate_response(self, target: NFCTarget, command: bytes) -> bytes:
        """Simulate responses for common commands."""
        # SELECT AID command
        if command.startswith(bytes([0x00, 0xA4, 0x04, 0x00])):
            aid_len = command[4]
            aid = command[5:5+aid_len]
            
            if aid == bytes([0xA0, 0x00, 0x00, 0x00, 0x04]):  # Mastercard AID
                return bytes([0x6F, 0x32]) + b'\x84\x07\xA0\x00\x00\x00\x04\x10\x10' + bytes([0x90, 0x00])
            elif aid == bytes([0xA0, 0x00, 0x00, 0x00, 0x03]):  # Visa AID  
                return bytes([0x6F, 0x32]) + b'\x84\x07\xA0\x00\x00\x00\x03\x10\x10' + bytes([0x90, 0x00])
            else:
                return bytes([0x6A, 0x82])  # File not found
        
        # GET PROCESSING OPTIONS
        elif command[:4] == bytes([0x80, 0xA8, 0x00, 0x00]):
            return bytes([0x77, 0x12, 0x82, 0x02, 0x78, 0x00, 0x94, 0x0C]) + \
                   bytes([0x08, 0x01, 0x01, 0x00, 0x10, 0x01, 0x01, 0x01, 0x18, 0x01, 0x02, 0x00]) + \
                   bytes([0x90, 0x00])
        
        # Default response
        return bytes([0x90, 0x00])
    
    def _send_command(self, command: bytes, timeout: float) -> bytes:
        """Send command to real NFC device."""
        # Placeholder for actual device communication
        time.sleep(0.01)  # Simulate communication delay
        return bytes([0x90, 0x00])  # Default success response