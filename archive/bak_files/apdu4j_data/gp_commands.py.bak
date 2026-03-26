#!/usr/bin/env python3
"""APDU4J GlobalPlatform Integration for GREENWIRE.

Hardcoded GlobalPlatform commands and utilities extracted from martinpaljak/apdu4j
and GlobalPlatformPro implementations for smartcard application management.

Source: https://github.com/martinpaljak/apdu4j
Related: https://github.com/martinpaljak/GlobalPlatformPro
License: MIT
"""

from typing import Dict, List, Optional, Union, Tuple
import logging
from .apdu_commands import APDU4JCommand, CLA_ISO

logger = logging.getLogger(__name__)

# GlobalPlatform specific constants
GP_CLA = 0x80  # GlobalPlatform class byte

# GlobalPlatform INS codes
GP_INS_SELECT = 0xA4
GP_INS_GET_STATUS = 0xF2
GP_INS_INSTALL = 0xE6
GP_INS_LOAD = 0xE8  
GP_INS_DELETE = 0xE4
GP_INS_GET_DATA = 0xCA
GP_INS_PUT_KEY = 0xD8
GP_INS_SET_STATUS = 0xF0
GP_INS_STORE_DATA = 0xE2

# GlobalPlatform Application States
GP_APP_INSTALLED = 0x03
GP_APP_SELECTABLE = 0x07
GP_APP_LOCKED = 0x83

# Well-known AIDs
GP_CARD_MANAGER_AID = "A000000151000000"
GP_ISD_AID = "A000000003000000"

# Install parameters
GP_INSTALL_FOR_LOAD = 0x02
GP_INSTALL_FOR_INSTALL = 0x04
GP_INSTALL_FOR_MAKE_SELECTABLE = 0x08
GP_INSTALL_FOR_PERSONALIZATION = 0x20

class GPCommand:
    """GlobalPlatform command builder following apdu4j patterns."""
    
    @staticmethod
    def select_card_manager() -> APDU4JCommand:
        """Select GlobalPlatform Card Manager."""
        aid_bytes = bytes.fromhex(GP_CARD_MANAGER_AID)
        return APDU4JCommand(CLA_ISO, GP_INS_SELECT, 0x04, 0x00, aid_bytes)
    
    @staticmethod
    def select_isd() -> APDU4JCommand:
        """Select Issuer Security Domain."""
        aid_bytes = bytes.fromhex(GP_ISD_AID)
        return APDU4JCommand(CLA_ISO, GP_INS_SELECT, 0x04, 0x00, aid_bytes)
        
    @staticmethod
    def get_status(element_type: int = 0x80) -> APDU4JCommand:
        """Get status of card elements.
        
        Args:
            element_type: 0x80=ISD, 0x40=Apps and SDs, 0x20=Executable Load Files
        """
        return APDU4JCommand(GP_CLA, GP_INS_GET_STATUS, element_type, 0x00, b'', le=256)
    
    @staticmethod  
    def get_card_data(tag: int = 0x0066) -> APDU4JCommand:
        """Get card data by tag.
        
        Args:
            tag: Data tag (0x0066=Card Data, 0x006E=Application Info)
        """
        p1 = (tag >> 8) & 0xFF
        p2 = tag & 0xFF
        return APDU4JCommand(GP_CLA, GP_INS_GET_DATA, p1, p2, le=256)
        
    @staticmethod
    def delete_aid(aid: Union[str, bytes]) -> APDU4JCommand:
        """Delete application by AID.
        
        Args:
            aid: Application ID to delete
        """
        if isinstance(aid, str):
            aid_bytes = bytes.fromhex(aid.replace(' ', ''))
        else:
            aid_bytes = aid
            
        # TLV: Tag=0x4F (AID), Length, Value
        data = b'\x4F' + bytes([len(aid_bytes)]) + aid_bytes
        return APDU4JCommand(GP_CLA, GP_INS_DELETE, 0x00, 0x00, data)
    
    @staticmethod
    def install_for_load(package_aid: Union[str, bytes], 
                        security_domain_aid: Union[str, bytes] = None) -> APDU4JCommand:
        """Install for Load command.
        
        Args:
            package_aid: Package AID to load
            security_domain_aid: Security Domain AID (optional)
        """
        if isinstance(package_aid, str):
            pkg_aid_bytes = bytes.fromhex(package_aid.replace(' ', ''))
        else:
            pkg_aid_bytes = package_aid
            
        if security_domain_aid:
            if isinstance(security_domain_aid, str):
                sd_aid_bytes = bytes.fromhex(security_domain_aid.replace(' ', ''))
            else:
                sd_aid_bytes = security_domain_aid
        else:
            sd_aid_bytes = b''
            
        # Build install data: Package AID length + AID + SD AID length + SD AID + Hash length (0) + Parameters length (0)
        data = bytes([len(pkg_aid_bytes)]) + pkg_aid_bytes
        data += bytes([len(sd_aid_bytes)]) + sd_aid_bytes
        data += b'\x00\x00'  # Hash length and parameters length
        
        return APDU4JCommand(GP_CLA, GP_INS_INSTALL, GP_INSTALL_FOR_LOAD, 0x00, data)
    
    @staticmethod
    def load_component(block_number: int, data: bytes, last_block: bool = False) -> APDU4JCommand:
        """Load CAP file component.
        
        Args:
            block_number: Block sequence number
            data: Block data
            last_block: True if this is the last block
        """
        p1 = 0x80 if last_block else 0x00
        p2 = block_number & 0xFF
        return APDU4JCommand(GP_CLA, GP_INS_LOAD, p1, p2, data)
    
    @staticmethod
    def install_for_install(package_aid: Union[str, bytes],
                           applet_aid: Union[str, bytes],
                           instance_aid: Union[str, bytes] = None,
                           privileges: bytes = b'\x00',
                           install_params: bytes = b'') -> APDU4JCommand:
        """Install for Install and Make Selectable command.
        
        Args:
            package_aid: Package AID containing the applet
            applet_aid: Applet class AID  
            instance_aid: Instance AID (defaults to applet_aid)
            privileges: Application privileges
            install_params: Installation parameters
        """
        if isinstance(package_aid, str):
            pkg_aid_bytes = bytes.fromhex(package_aid.replace(' ', ''))
        else:
            pkg_aid_bytes = package_aid
            
        if isinstance(applet_aid, str):
            app_aid_bytes = bytes.fromhex(applet_aid.replace(' ', ''))
        else:
            app_aid_bytes = applet_aid
            
        if instance_aid:
            if isinstance(instance_aid, str):
                inst_aid_bytes = bytes.fromhex(instance_aid.replace(' ', ''))
            else:
                inst_aid_bytes = instance_aid
        else:
            inst_aid_bytes = app_aid_bytes
            
        # Build install data
        data = bytes([len(pkg_aid_bytes)]) + pkg_aid_bytes  # Package AID
        data += bytes([len(app_aid_bytes)]) + app_aid_bytes  # Applet AID
        data += bytes([len(inst_aid_bytes)]) + inst_aid_bytes  # Instance AID  
        data += bytes([len(privileges)]) + privileges  # Privileges
        data += bytes([len(install_params)]) + install_params  # Install parameters
        data += b'\x00'  # Token length
        
        p1 = GP_INSTALL_FOR_INSTALL | GP_INSTALL_FOR_MAKE_SELECTABLE
        return APDU4JCommand(GP_CLA, GP_INS_INSTALL, p1, 0x00, data)

# Hardcoded GlobalPlatform command templates
GP_COMMANDS = {
    'SELECT_CARD_MANAGER': GPCommand.select_card_manager(),
    'SELECT_ISD': GPCommand.select_isd(),
    'GET_STATUS_ISD': GPCommand.get_status(0x80),
    'GET_STATUS_APPS': GPCommand.get_status(0x40), 
    'GET_STATUS_LOAD_FILES': GPCommand.get_status(0x20),
    'GET_CARD_DATA': GPCommand.get_card_data(0x0066),
    'GET_APPLICATION_INFO': GPCommand.get_card_data(0x006E),
}

class GPCapFileLoader:
    """CAP file loader following GlobalPlatformPro patterns."""
    
    def __init__(self, communicator=None):
        """Initialize CAP loader.
        
        Args:
            communicator: APDU communication interface
        """
        self.communicator = communicator
        self.logger = logging.getLogger(__name__)
        
    def install_cap_file(self, cap_file_path: str, 
                        package_aid: str,
                        applet_aid: str, 
                        instance_aid: str = None) -> Dict[str, any]:
        """Install CAP file to card.
        
        Args:
            cap_file_path: Path to CAP file
            package_aid: Package AID
            applet_aid: Applet class AID
            instance_aid: Instance AID (optional)
            
        Returns:
            Installation result
        """
        if not self.communicator:
            return {'error': 'No communicator configured'}
            
        try:
            # Step 1: Install for Load
            self.logger.info(f"Installing for load: {package_aid}")
            load_cmd = GPCommand.install_for_load(package_aid)
            result = self._send_gp_command(load_cmd)
            
            if not result.get('success'):
                return {'error': f'Install for load failed: {result.get("status")}'}
            
            # Step 2: Load CAP file components  
            self.logger.info(f"Loading CAP file: {cap_file_path}")
            load_result = self._load_cap_components(cap_file_path)
            
            if not load_result.get('success'):
                return {'error': f'CAP load failed: {load_result.get("error")}'}
            
            # Step 3: Install for Install and Make Selectable
            self.logger.info(f"Installing applet: {applet_aid}")
            install_cmd = GPCommand.install_for_install(package_aid, applet_aid, instance_aid)
            result = self._send_gp_command(install_cmd)
            
            if not result.get('success'):
                return {'error': f'Install failed: {result.get("status")}'}
                
            return {'success': True, 'message': 'CAP file installed successfully'}
            
        except Exception as e:
            self.logger.error(f"CAP installation failed: {e}")
            return {'error': str(e)}
            
    def _send_gp_command(self, command: APDU4JCommand) -> Dict[str, any]:
        """Send GlobalPlatform command."""
        try:
            command_hex = command.to_hex()
            self.logger.debug(f"Sending GP command: {command_hex}")
            
            response_data, sw = self.communicator.send_apdu(command_hex)
            
            if response_data is None:
                return {'error': 'Communication failed'}
                
            # Parse response
            if sw:
                sw_int = int(sw, 16)
                success = sw_int == 0x9000
            else:
                success = False
                
            return {
                'success': success,
                'data': response_data,
                'status': sw,
                'response_data': response_data
            }
            
        except Exception as e:
            return {'error': str(e)}
            
    def _load_cap_components(self, cap_file_path: str) -> Dict[str, any]:
        """Load CAP file components to card."""
        try:
            with open(cap_file_path, 'rb') as f:
                cap_data = f.read()
                
            # Simple block-based loading (production would parse CAP structure)
            block_size = 200  # Typical APDU data limit
            block_number = 0
            
            for i in range(0, len(cap_data), block_size):
                block_data = cap_data[i:i+block_size]
                is_last = (i + block_size >= len(cap_data))
                
                load_cmd = GPCommand.load_component(block_number, block_data, is_last)
                result = self._send_gp_command(load_cmd)
                
                if not result.get('success'):
                    return {'error': f'Load block {block_number} failed: {result.get("status")}'}
                    
                block_number += 1
                
            return {'success': True, 'blocks_loaded': block_number}
            
        except Exception as e:
            return {'error': f'CAP file loading failed: {e}'}

class GPManager:
    """High-level GlobalPlatform management interface."""
    
    def __init__(self, communicator=None):
        """Initialize GP manager.
        
        Args:
            communicator: APDU communication interface
        """
        self.communicator = communicator  
        self.cap_loader = GPCapFileLoader(communicator)
        self.logger = logging.getLogger(__name__)
        
    def list_applications(self) -> Dict[str, any]:
        """List installed applications."""
        if not self.communicator:
            return {'error': 'No communicator configured'}
            
        try:
            # Select Card Manager first
            select_cmd = GPCommand.select_card_manager()
            result = self._send_command(select_cmd)
            
            if not result.get('success'):
                return {'error': f'Card Manager selection failed: {result.get("status")}'}
            
            # Get application status
            status_cmd = GPCommand.get_status(0x40)  # Applications and Security Domains
            result = self._send_command(status_cmd)
            
            if result.get('success'):
                return {
                    'success': True,
                    'applications': self._parse_status_response(result.get('data', ''))
                }
            else:
                return {'error': f'Get status failed: {result.get("status")}'}
                
        except Exception as e:
            return {'error': str(e)}
            
    def delete_application(self, aid: str) -> Dict[str, any]:
        """Delete application by AID."""
        if not self.communicator:
            return {'error': 'No communicator configured'}
            
        try:
            delete_cmd = GPCommand.delete_aid(aid)
            result = self._send_command(delete_cmd)
            
            if result.get('success'):
                return {'success': True, 'message': f'Application {aid} deleted'}
            else:
                return {'error': f'Delete failed: {result.get("status")}'}
                
        except Exception as e:
            return {'error': str(e)}
            
    def get_card_info(self) -> Dict[str, any]:
        """Get card information."""
        if not self.communicator:
            return {'error': 'No communicator configured'}
            
        try:
            # Select Card Manager
            select_cmd = GPCommand.select_card_manager()
            select_result = self._send_command(select_cmd)
            
            if not select_result.get('success'):
                return {'error': f'Card Manager selection failed'}
            
            # Get card data
            data_cmd = GPCommand.get_card_data()
            data_result = self._send_command(data_cmd)
            
            return {
                'success': True,
                'card_manager_selected': True,
                'card_data': data_result.get('data', ''),
                'select_response': select_result.get('data', '')
            }
            
        except Exception as e:
            return {'error': str(e)}
            
    def _send_command(self, command: APDU4JCommand) -> Dict[str, any]:
        """Send APDU command and parse response."""
        try:
            command_hex = command.to_hex()
            response_data, sw = self.communicator.send_apdu(command_hex)
            
            if response_data is None:
                return {'error': 'Communication failed'}
                
            success = sw == '9000' if sw else False
            
            return {
                'success': success,
                'data': response_data or '',
                'status': sw or 'Unknown'
            }
            
        except Exception as e:
            return {'error': str(e)}
            
    def _parse_status_response(self, response_hex: str) -> List[Dict[str, str]]:
        """Parse GET STATUS response data."""
        applications = []
        
        try:
            data = bytes.fromhex(response_hex)
            offset = 0
            
            while offset < len(data):
                if offset + 1 >= len(data):
                    break
                    
                aid_len = data[offset]
                offset += 1
                
                if offset + aid_len > len(data):
                    break
                    
                aid = data[offset:offset + aid_len]
                offset += aid_len
                
                if offset + 1 >= len(data):
                    break
                    
                state = data[offset]
                offset += 1
                
                # Skip privileges if present
                if offset < len(data) and data[offset] == 0x01:
                    offset += 2  # Skip length and privileges byte
                    
                state_desc = {
                    0x01: 'LOADED',
                    0x03: 'INSTALLED', 
                    0x07: 'SELECTABLE',
                    0x83: 'LOCKED'
                }.get(state, f'UNKNOWN(0x{state:02X})')
                
                applications.append({
                    'aid': aid.hex().upper(),
                    'state': state_desc,
                    'state_code': f'0x{state:02X}'
                })
                
        except Exception as e:
            self.logger.error(f"Status response parsing failed: {e}")
            
        return applications

# Export main classes
__all__ = [
    'GPCommand',
    'GPCapFileLoader', 
    'GPManager',
    'GP_COMMANDS'
]