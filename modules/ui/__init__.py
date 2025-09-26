"""
GREENWIRE UI Library
====================
User interface components for GREENWIRE static distribution.
"""

__version__ = "1.0.0-greenwire"
__author__ = "GREENWIRE Project"

from .menu import *  # noqa: F401
from .colors import *  # noqa: F401

__all__ = [
    'GreenwireMenu',
    'MenuItem',
    'MenuAction',
    'print_colored',
    'print_banner',
    'Colors',
]