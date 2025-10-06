"""Compatibility shim for legacy imports.

Historically modules imported configuration logic via:
    from core.configuration_manager import get_configuration_manager

During the package namespacing refactor the implementation moved to:
    greenwire/core/configuration_manager.py

To avoid touching dozens of existing modules we provide this thin re-export
module so both import styles continue to function.
"""
from greenwire.core.configuration_manager import *  # type: ignore F401,F403
