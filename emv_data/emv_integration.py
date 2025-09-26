#!/usr/bin/env python3
"""
GREENWIRE EMV Integration Module
===============================
Main interface for EMV/Mifare operational data
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional  # noqa: F401

# Import all EMV modules
try:
    from .commands.emv_commands import EMV_COMMANDS, get_emv_command, list_emv_commands
    from .commands.apdu_responses import APDU_RESPONSES, get_apdu_response, is_success
    from .commands.hsm_commands import HSM_COMMANDS, get_hsm_command, list_vendors
except ImportError:
    # Handle relative imports when run directly
    import sys
    sys.path.append(str(Path(__file__).parent))
    from commands.emv_commands import EMV_COMMANDS, get_emv_command, list_emv_commands
    from commands.apdu_responses import APDU_RESPONSES, get_apdu_response, is_success
    from commands.hsm_commands import HSM_COMMANDS, get_hsm_command

class GREENWIREEMVInterface:
    """Main EMV interface for GREENWIRE"""
    
    def __init__(self):
        self.data_path = Path(__file__).parent / "reference"
        self.reference_data = self._load_reference_data()
    
    def _load_reference_data(self) -> Dict[str, Any]:
        """Load reference data from JSON"""
        ref_file = self.data_path / "emv_reference_data.json"
        try:
            with open(ref_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def execute_emv_command(self, command_name: str, **kwargs) -> Dict[str, Any]:
        """Execute EMV command with parameters"""
        cmd = get_emv_command(command_name)
        if not cmd:
            return {"error": f"Command {command_name} not found"}
        
        # Validate parameters
        missing_params = []
        for param in cmd.parameters:
            if param not in kwargs:
                missing_params.append(param)
        
        if missing_params:
            return {"error": f"Missing parameters: {missing_params}"}
        
        # Build APDU
        apdu = cmd.apdu
        for param, value in kwargs.items():
            if param in cmd.parameters:
                apdu += str(value)
        
        return {
            "command": cmd.name,
            "apdu": apdu,
            "description": cmd.description,
            "category": cmd.category,
            "expected_responses": cmd.response_codes
        }
    
    def get_emv_command(self, command_name: str):
        """Get EMV command by name"""
        return get_emv_command(command_name)
    
    def get_hsm_command(self, vendor: str, command: str):
        """Get HSM command by vendor and command"""
        return get_hsm_command(vendor, command)
    
    def parse_apdu_response(self, response_code: str) -> Dict[str, Any]:
        """Parse APDU response code"""
        resp = get_apdu_response(response_code)
        if not resp:
            return {"error": f"Unknown response code: {response_code}"}

        return {
            "code": resp.code,
            "description": resp.description,
            "category": resp.category,
            "success": is_success(response_code)
        }
    
    def get_emv_tag_info(self, tag: str) -> Dict[str, Any]:
        """Get EMV tag information"""
        for tag_info in self.reference_data.get("emv_tags", []):
            if tag_info.get("tag") == tag.upper():
                return tag_info
        return {"error": f"Tag {tag} not found"}
    
    def get_aid_info(self, aid: str) -> Dict[str, Any]:
        """Get Application Identifier information"""
        for aid_info in self.reference_data.get("aids", []):
            if aid_info.get("aid") == aid.upper():
                return aid_info
        return {"error": f"AID {aid} not found"}
    
    def list_available_commands(self) -> List[str]:
        """List all available EMV commands"""
        return list_emv_commands()
    
    def get_statistics(self) -> Dict[str, int]:
        """Get EMV data statistics"""
        return {
            "emv_commands": len(EMV_COMMANDS),
            "apdu_responses": len(APDU_RESPONSES),
            "hsm_commands": len(HSM_COMMANDS),
            "emv_tags": len(self.reference_data.get("emv_tags", [])),
            "aids": len(self.reference_data.get("aids", [])),
            "pin_blocks": len(self.reference_data.get("pin_blocks", []))
        }

# Global EMV interface instance
emv_interface = GREENWIREEMVInterface()

# Convenience functions
def execute_emv_command(command: str, **kwargs):
    """Execute EMV command - convenience function"""
    return emv_interface.execute_emv_command(command, **kwargs)

def parse_response(code: str):
    """Parse APDU response - convenience function"""  
    return emv_interface.parse_apdu_response(code)

def get_tag_info(tag: str):
    """Get EMV tag info - convenience function"""
    return emv_interface.get_emv_tag_info(tag)

if __name__ == "__main__":
    # Demo functionality
    print("GREENWIRE EMV Integration Module")
    print("=" * 40)
    
    stats = emv_interface.get_statistics()
    print("📊 Data Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n🔧 Available Commands:")
    for cmd in emv_interface.list_available_commands()[:5]:
        print(f"  - {cmd}")
    
    print("\n✅ EMV integration ready for GREENWIRE!")
