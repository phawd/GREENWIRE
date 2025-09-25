"""
GREENWIRE Static Library Package

This package contains advanced modules for GREENWIRE security testing framework.
"""

__version__ = "1.0.0"
__author__ = "GREENWIRE Security Research"

# Make key modules available at package level
try:
    from . import lib
except ImportError:
    # Graceful fallback if lib package not available
    pass