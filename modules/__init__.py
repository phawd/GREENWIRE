"""
GREENWIRE Modules Package

Consolidated modules for GREENWIRE security testing framework.
This package contains all specialized functionality organized by domain.

Structure:
    emulation.py         - Advanced card/terminal/NFC emulation
    crypto/             - Cryptographic functions and analysis  
    nfc/                - NFC protocol implementations
    ui/                 - User interface components
    android_nfc.py      - Android NFC integration
    greenwire_key_manager.py      - Key management utilities
    greenwire_protocol_logger.py  - Protocol logging and analysis
    greenwire_emv_compliance.py   - EMV compliance testing
    greenwire_log_viewer.py       - Log viewing utilities
    greenwire_crypto_fuzzer.py    - Cryptographic fuzzing tools
    greenwire_pyapdu_fuzzer.py    - APDU fuzzing implementation
"""

__version__ = "2.0.0"
__author__ = "GREENWIRE Security Research"

# Import key modules for easy access
try:
    from .emulation import (
        EmulationBase,
        CardEmulator, 
        TerminalEmulator,
        NFCDeviceEmulator,
        EmulationManager
    )
    __all__ = [
        'EmulationBase',
        'CardEmulator',
        'TerminalEmulator', 
        'NFCDeviceEmulator',
        'EmulationManager'
    ]
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"Failed to import emulation modules: {e}")
    __all__ = []

# Import crypto modules
try:
    from . import crypto
    __all__.append('crypto')
except ImportError:
    pass

# Import NFC modules
try:
    from . import nfc
    __all__.append('nfc')
except ImportError:
    pass

# Import UI modules
try:
    from . import ui
    __all__.append('ui')
except ImportError:
    pass

# Import specialized modules
try:
    from . import greenwire_key_manager
    from . import greenwire_protocol_logger
    from . import android_nfc
    from . import greenwire_emv_compliance
    from . import greenwire_crypto_fuzzer
    from . import greenwire_pyapdu_fuzzer
    __all__.extend([
        'greenwire_key_manager', 'greenwire_protocol_logger', 'android_nfc',
        'greenwire_emv_compliance', 'greenwire_crypto_fuzzer', 'greenwire_pyapdu_fuzzer'
    ])
except ImportError:
    pass