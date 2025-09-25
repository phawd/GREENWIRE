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

# Import core modules for easy access
try:
    from .config import GreenwireConfig as Config, get_config
    from .logging_system import GreenwireLogger as LoggingSystem, get_logger
    from .menu_system import MenuSystem
    from .nfc_manager import UnifiedNFCManager as NFCManager
    from .imports import ModuleManager
    __all__ = [
        'Config',
        'LoggingSystem', 
        'MenuSystem',
        'NFCManager',
        'ModuleManager'
    ]
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"Failed to import core modules: {e}")
    __all__ = []

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
except ImportError:
    pass