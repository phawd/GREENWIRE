"""Operator mode wrapper for backwards compatibility.

Some modules import `greenwire.core.operator_mode` while others import `core.operator_mode`.
This small wrapper re-exports the implementation from `core.operator_mode` so both
import styles work during the transition.
"""
from core.operator_mode import ask_operator_mode  # noqa: F401
__all__ = ['ask_operator_mode']
