#!/usr/bin/env python3
"""APDU4J Integration Module for GREENWIRE.

Main integration interface that combines APDU4J command structures with GREENWIRE's
existing EMV and smartcard infrastructure. Provides unified access to hardcoded
APDU commands from the martinpaljak/apdu4j library.

Source: https://github.com/martinpaljak/apdu4j
License: MIT
"""

import logging
from typing import Dict, List, Optional, Union, Any
from .apdu_commands import (
    APDU4JCommand, APDU4JInterface, APDU_COMMANDS, PCSC_COMMANDS,
    create_select_aid_command, create_pin_verify_command, create_get_data_command,
    parse_apdu_response
)
from .gp_commands import GPCommand, GPManager, GPCapFileLoader, GP_COMMANDS

logger = logging.getLogger(__name__)

class GREENWIREAPDU4JInterface:
    """Main APDU4J integration interface for GREENWIRE."""
    
    def __init__(self, apdu_communicator=None):
        """Initialize APDU4J interface.
        
        Args:
            apdu_communicator: GREENWIRE APDUCommunicator instance
        """
        self.communicator = apdu_communicator
        self.apdu_interface = APDU4JInterface(apdu_communicator)
        self.gp_manager = GPManager(apdu_communicator)
        self.logger = logging.getLogger(__name__)
        
        # Load all available commands
        self.commands = {}
        self.commands.update(APDU_COMMANDS)
        self.commands.update(PCSC_COMMANDS)
        self.commands.update(GP_COMMANDS)
        
    def get_available_commands(self) -> List[str]:
        """Get list of all available APDU4J commands.
        
        Returns:
            List of command names
        """
        return list(self.commands.keys())
        
    def get_command_info(self, command_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific command.
        
        Args:
            command_name: Name of the command
            
        Returns:
            Command information dictionary
        """
        if command_name not in self.commands:
            return None
            
        command = self.commands[command_name]
        return {
            'name': command_name,
            'cla': f'0x{command.cla:02X}',
            'ins': f'0x{command.ins:02X}',
            'p1': f'0x{command.p1:02X}',
            'p2': f'0x{command.p2:02X}',
            'case': command.case,
            'hex': command.to_hex(),
            'description': self._get_command_description(command_name)
        }
        
    def execute_command(self, command_name: str, **kwargs) -> Dict[str, Any]:
        """Execute a predefined APDU4J command.
        
        Args:
            command_name: Name of command to execute
            **kwargs: Command-specific parameters
            
        Returns:
            Command execution result
        """
        if not self.communicator:
            return {'error': 'No communicator configured'}
            
        if command_name not in self.commands:
            return {'error': f'Unknown command: {command_name}'}
            
        try:
            command = self.commands[command_name]
            
            # Handle parameterized commands
            if command_name in ['SELECT_ADF', 'GP_SELECT'] and 'aid' in kwargs:
                command = create_select_aid_command(kwargs['aid'])
            elif command_name == 'VERIFY_PIN' and 'pin' in kwargs:
                pin_id = kwargs.get('pin_id', 0x80)
                command = create_pin_verify_command(kwargs['pin'], pin_id)
            elif command_name == 'GET_DATA' and 'tag' in kwargs:
                le = kwargs.get('le', 256)
                command = create_get_data_command(kwargs['tag'], le)
                
            return self.apdu_interface.send_command(command)
            
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            return {'error': str(e)}
            
    def select_application(self, aid: Union[str, bytes]) -> Dict[str, Any]:
        """Select application by AID using APDU4J SELECT command.
        
        Args:
            aid: Application ID
            
        Returns:
            Selection result
        """
        return self.apdu_interface.select_application(aid)
        
    def verify_pin(self, pin: Union[str, bytes], pin_id: int = 0x80) -> Dict[str, Any]:
        """Verify PIN using APDU4J VERIFY command.
        
        Args:
            pin: PIN value
            pin_id: PIN identifier
            
        Returns:
            Verification result  
        """
        return self.apdu_interface.verify_pin(pin, pin_id)
        
    def get_data_object(self, tag: int, le: int = 256) -> Dict[str, Any]:
        """Get data object using APDU4J GET DATA command.
        
        Args:
            tag: Data object tag
            le: Expected length
            
        Returns:
            Data object response
        """
        return self.apdu_interface.get_data(tag, le)
        
    def list_gp_applications(self) -> Dict[str, Any]:
        """List GlobalPlatform applications using APDU4J GP commands.
        
        Returns:
            List of installed applications
        """
        return self.gp_manager.list_applications()
        
    def install_cap_file(self, cap_file_path: str, package_aid: str, 
                        applet_aid: str, instance_aid: str = None) -> Dict[str, Any]:
        """Install CAP file using APDU4J GP commands.
        
        Args:
            cap_file_path: Path to CAP file
            package_aid: Package AID
            applet_aid: Applet class AID
            instance_aid: Instance AID (optional)
            
        Returns:
            Installation result
        """
        return self.gp_manager.cap_loader.install_cap_file(
            cap_file_path, package_aid, applet_aid, instance_aid
        )
        
    def delete_gp_application(self, aid: str) -> Dict[str, Any]:
        """Delete GlobalPlatform application.
        
        Args:
            aid: Application AID to delete
            
        Returns:
            Deletion result
        """
        return self.gp_manager.delete_application(aid)
        
    def get_card_info(self) -> Dict[str, Any]:
        """Get card information using GP commands.
        
        Returns:
            Card information
        """
        return self.gp_manager.get_card_info()
        
    def send_raw_apdu(self, cla: int, ins: int, p1: int, p2: int,
                     data: bytes = None, le: int = None) -> Dict[str, Any]:
        """Send raw APDU command using APDU4J structure.
        
        Args:
            cla: Class byte
            ins: Instruction byte  
            p1: Parameter 1
            p2: Parameter 2
            data: Command data
            le: Expected response length
            
        Returns:
            Command response
        """
        command = APDU4JCommand(cla, ins, p1, p2, data, le)
        return self.apdu_interface.send_command(command)
        
    def send_apdu_hex(self, apdu_hex: str) -> Dict[str, Any]:
        """Send APDU from hex string and parse with APDU4J.
        
        Args:
            apdu_hex: APDU as hex string
            
        Returns:
            Parsed response
        """
        if not self.communicator:
            return {'error': 'No communicator configured'}
            
        try:
            response_data, sw = self.communicator.send_apdu(apdu_hex)
            
            if response_data is None:
                return {'error': 'Communication failed'}
                
            # Build full response for parsing
            if sw:
                sw_bytes = bytes.fromhex(sw)
                if response_data:
                    full_response = bytes.fromhex(response_data) + sw_bytes
                else:
                    full_response = sw_bytes
            else:
                full_response = bytes.fromhex(response_data) if response_data else b''
                
            return parse_apdu_response(full_response)
            
        except Exception as e:
            return {'error': str(e)}
            
    def _get_command_description(self, command_name: str) -> str:
        """Get human-readable description for command."""
        descriptions = {
            'SELECT_MF': 'Select Master File (root directory)',
            'SELECT_ADF': 'Select Application Dedicated File by AID',
            'SELECT_EF': 'Select Elementary File by file ID', 
            'SELECT_DF': 'Select Dedicated File by file ID',
            'READ_BINARY': 'Read binary data from transparent file',
            'UPDATE_BINARY': 'Update binary data in transparent file',
            'READ_RECORD': 'Read record from linear/cyclic file',
            'UPDATE_RECORD': 'Update record in linear/cyclic file',
            'APPEND_RECORD': 'Append record to cyclic file',
            'VERIFY_PIN': 'Verify PIN for authentication',
            'CHANGE_PIN': 'Change PIN value',
            'UNBLOCK_PIN': 'Unblock PIN after failed attempts',
            'GET_CHALLENGE': 'Get random challenge for authentication',
            'INTERNAL_AUTH': 'Perform internal authentication',
            'EXTERNAL_AUTH': 'Perform external authentication',
            'GET_DATA': 'Get data object by tag',
            'PUT_DATA': 'Put data object by tag',
            'PCSC_GET_UID': 'Get card UID via PC/SC',
            'PCSC_LOAD_KEY': 'Load authentication key via PC/SC',
            'PCSC_AUTH': 'Authenticate with loaded key',
            'PCSC_READ_BLOCK': 'Read block via PC/SC',
            'PCSC_WRITE_BLOCK': 'Write block via PC/SC',
            'SELECT_CARD_MANAGER': 'Select GlobalPlatform Card Manager',
            'SELECT_ISD': 'Select Issuer Security Domain',
            'GET_STATUS_ISD': 'Get status of Issuer Security Domain',
            'GET_STATUS_APPS': 'Get status of applications and security domains',
            'GET_STATUS_LOAD_FILES': 'Get status of executable load files',
            'GET_CARD_DATA': 'Get card production lifecycle data',
            'GET_APPLICATION_INFO': 'Get application information'
        }
        
        return descriptions.get(command_name, 'APDU4J command')

# Convenience functions for GREENWIRE integration
def create_apdu4j_interface(apdu_communicator) -> GREENWIREAPDU4JInterface:
    """Create APDU4J interface with GREENWIRE communicator.
    
    Args:
        apdu_communicator: GREENWIRE APDUCommunicator instance
        
    Returns:
        Configured APDU4J interface
    """
    return GREENWIREAPDU4JInterface(apdu_communicator)

def get_apdu4j_command_list() -> Dict[str, str]:
    """Get list of all APDU4J commands with descriptions.
    
    Returns:
        Dictionary mapping command names to descriptions
    """
    interface = GREENWIREAPDU4JInterface()
    commands = {}
    
    for cmd_name in interface.get_available_commands():
        info = interface.get_command_info(cmd_name)
        if info:
            commands[cmd_name] = info['description']
            
    return commands

# Export main classes and functions
__all__ = [
    'GREENWIREAPDU4JInterface',
    'APDU4JCommand',
    'APDU4JInterface', 
    'GPCommand',
    'GPManager',
    'create_apdu4j_interface',
    'get_apdu4j_command_list'
]