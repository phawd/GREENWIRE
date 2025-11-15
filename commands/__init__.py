"""
GREENWIRE Modern CLI - Commands Package

This package contains the command modules that bridge the modern CLI
with the core logic of the GREENWIRE framework.
"""

from .cap_management import get_command as get_cap_command
from .issuer_pipeline import get_command as get_pipeline_command
from .rfid_testing import get_command as get_rfid_command

__all__ = [
    'get_cap_command', 'get_pipeline_command', 'get_rfid_command'
]