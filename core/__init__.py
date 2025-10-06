"""
GREENWIRE Core Package

Core system functionality for GREENWIRE security testing framework.
This package contains fundamental system components that other modules depend on.

Structure:
    config.py           - System configuration management
    imports.py          - Dynamic module import system
    logging_system.py   - Centralized logging infrastructure
    menu_system.py      - Interactive menu system
    nfc_manager.py      - NFC device management
    utils/              - Core utility functions
    global_defaults.py  - System-wide default values
    advanced_fuzzing.py - Advanced fuzzing engine
    apdu_fuzzer.py      - APDU protocol fuzzing
    ai_vuln_testing.py  - AI-powered vulnerability testing
    card_standards.py   - Card standard implementations
"""

__version__ = "2.0.0"
__author__ = "GREENWIRE Security Research"

# Import core modules for easy access while keeping menu dependencies optional
from .config import GreenwireConfig as Config, get_config
from .logging_system import GreenwireLogger as LoggingSystem, get_logger
from .nfc_manager import UnifiedNFCManager as NFCManager
from .imports import ModuleManager

__all__ = [
    'Config',
    'LoggingSystem',
    'NFCManager',
    'ModuleManager',
]

try:
    from .menu_system import MenuSystem
except Exception as exc:  # pragma: no cover - optional UI dependency
    import logging

    MenuSystem = None  # type: ignore[assignment]
    logging.getLogger(__name__).warning(
        "Menu system unavailable during import: %s", exc
    )
else:
    __all__.append('MenuSystem')

# Import utility modules
try:
    from . import utils
    __all__.append('utils')
except ImportError:
    pass

# Import advanced functionality
try:
    from . import advanced_fuzzing
    from . import apdu_fuzzer
    from . import ai_vuln_testing
    from . import card_standards
    __all__.extend(['advanced_fuzzing', 'apdu_fuzzer', 'ai_vuln_testing', 'card_standards'])
except Exception:  # pragma: no cover - these modules are optional during unit tests
    pass