#!/usr/bin/env python3
"""
EMV Commands Module - GREENWIRE Integration
==========================================
Hardcoded EMV command definitions extracted from production data
"""

from dataclasses import dataclass
from typing import Any, Dict, List

@dataclass
class EMVCommand:
    """EMV Command structure"""
    name: str
    apdu: str
    description: str
    category: str
    parameters: Dict[str, Any]
    response_codes: List[str]

# Hardcoded EMV commands from production data
EMV_COMMANDS = {
    "SELECT": EMVCommand(
        name="SELECT",
        apdu="00A40400",
        description="Select EMV application by AID",
        category="Application Selection",
        parameters={"aid": "str", "length": "int"},
        response_codes=["9000", "6A82", "6A81"]
    ),
    "GET_PROCESSING_OPTIONS": EMVCommand(
        name="GET_PROCESSING_OPTIONS",
        apdu="80A80000",
        description="Initiate application processing",
        category="Transaction Processing",
        parameters={"pdol": "str"},
        response_codes=["9000", "6985", "6A81"]
    ),
    "READ_RECORD": EMVCommand(
        name="READ_RECORD",
        apdu="00B2",
        description="Read application data record",
        category="Data Retrieval",
        parameters={"record": "int", "sfi": "int"},
        response_codes=["9000", "6A83", "6982"]
    ),
    "VERIFY": EMVCommand(
        name="VERIFY",
        apdu="0020",
        description="PIN verification",
        category="Authentication",
        parameters={"pin": "str", "format": "str"},
        response_codes=["9000", "63C0", "6983"]
    ),
    "GENERATE_AC": EMVCommand(
        name="GENERATE_AC",
        apdu="80AE",
        description="Generate Application Cryptogram",
        category="Cryptographic",
        parameters={"type": "str", "cdol": "str"},
        response_codes=["9000", "6985", "6A81"]
    ),
}

def get_emv_command(name: str) -> EMVCommand:
    """Get EMV command by name"""
    return EMV_COMMANDS.get(name.upper())

def list_emv_commands() -> List[str]:
    """List all available EMV commands"""
    return list(EMV_COMMANDS.keys())

def get_commands_by_category(category: str) -> List[EMVCommand]:
    """Get commands by category"""
    return [cmd for cmd in EMV_COMMANDS.values() if cmd.category == category]