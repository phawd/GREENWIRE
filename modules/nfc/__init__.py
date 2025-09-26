"""
GREENWIRE NFC Library
=====================
A self-contained NFC library for GREENWIRE static distribution.
Provides NFC communication, card emulation, and protocol handling.
"""

__version__ = "1.0.0-greenwire"
__author__ = "GREENWIRE Project"

from .core import *  # noqa: F401
from .emulation import *  # noqa: F401
from .protocols import *  # noqa: F401

__all__ = [
    'NFCDevice',
    'NFCTarget',
    'EMVEmulator',
    'ISO14443A',
    'APDU',
    'GreenwireNFCError',
]