#!/usr/bin/env python3
"""
HSM Commands Module - GREENWIRE Integration
==========================================
Hardware Security Module commands from production data
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class HSMCommand:
    """HSM Command structure"""
    vendor: str
    command: str
    description: str
    parameters: Dict[str, Any]

# Hardcoded HSM commands from production data
HSM_COMMANDS = {
    "THALES_A0": HSMCommand(vendor="Thales", command="A0", description="Generate Key", parameters={"key_type": "str"}),
    "THALES_A2": HSMCommand(vendor="Thales", command="A2", description="Generate Key Component", parameters={"component": "str"}),
    "THALES_B0": HSMCommand(vendor="Thales", command="B0", description="Import Key", parameters={"key_data": "str"}),
    "THALES_B2": HSMCommand(vendor="Thales", command="B2", description="Export Key", parameters={"key_name": "str"}),
    "SAFENET_GK": HSMCommand(vendor="SafeNet", command="GK", description="Generate Key", parameters={"algorithm": "str"}),
    "SAFENET_EK": HSMCommand(vendor="SafeNet", command="EK", description="Encrypt Key", parameters={"key_data": "str"}),
    "SAFENET_DK": HSMCommand(vendor="SafeNet", command="DK", description="Decrypt Key", parameters={"encrypted_key": "str"}),
    "ATALLA_CMD01": HSMCommand(vendor="Atalla", command="CMD01", description="Key Generation", parameters={"key_type": "str"}),
    "ATALLA_CMD02": HSMCommand(vendor="Atalla", command="CMD02", description="PIN Verification", parameters={"pin_block": "str"}),
    "ATALLA_CMD03": HSMCommand(vendor="Atalla", command="CMD03", description="MAC Generation", parameters={"data": "str"}),
}

def get_hsm_command(vendor: str, command: str) -> Optional[HSMCommand]:
    """Get HSM command by vendor and command"""
    key = f"{vendor}_{command}".replace(" ", "_").upper()
    return HSM_COMMANDS.get(key)

def get_vendor_commands(vendor: str) -> List[HSMCommand]:
    """Get all commands for a specific vendor"""
    return [cmd for cmd in HSM_COMMANDS.values() if cmd.vendor.upper() == vendor.upper()]

def list_vendors() -> List[str]:
    """List all HSM vendors"""
    return list(set(cmd.vendor for cmd in HSM_COMMANDS.values()))

def list_hsm_commands() -> List[str]:
    """List all HSM command keys"""
    return list(HSM_COMMANDS.keys())