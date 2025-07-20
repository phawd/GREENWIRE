from __future__ import annotations

"""JCOP applet feature configuration.

This module defines :class:`JCOPAppletConfig`, a simple container for
toggling features on a hypothetical JCOP/GlobalPlatform applet. The
current set of features does not correspond to any particular real
product but demonstrates how a large number of capabilities could be
controlled programmatically.
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class JCOPAppletConfig:
    """Manage applet feature toggles.

    All feature flags default to ``False``. Use :meth:`toggle` to enable
    or disable individual features by name.
    """

    # Define 39 boolean feature flags.
    feature_01: bool = False
    feature_02: bool = False
    feature_03: bool = False
    feature_04: bool = False
    feature_05: bool = False
    feature_06: bool = False
    feature_07: bool = False
    feature_08: bool = False
    feature_09: bool = False
    feature_10: bool = False
    feature_11: bool = False
    feature_12: bool = False
    feature_13: bool = False
    feature_14: bool = False
    feature_15: bool = False
    feature_16: bool = False
    feature_17: bool = False
    feature_18: bool = False
    feature_19: bool = False
    feature_20: bool = False
    feature_21: bool = False
    feature_22: bool = False
    feature_23: bool = False
    feature_24: bool = False
    feature_25: bool = False
    feature_26: bool = False
    feature_27: bool = False
    feature_28: bool = False
    feature_29: bool = False
    feature_30: bool = False
    feature_31: bool = False
    feature_32: bool = False
    feature_33: bool = False
    feature_34: bool = False
    feature_35: bool = False
    feature_36: bool = False
    feature_37: bool = False
    feature_38: bool = False
    feature_39: bool = False

    _features: Dict[str, bool] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Cache feature names for quick lookup
        self._features = {
            f"feature_{i:02d}": getattr(self, f"feature_{i:02d}")
            for i in range(1, 40)
        }

    def toggle(self, name: str, enabled: bool) -> None:
        """Enable or disable ``name`` if it exists."""
        if name not in self._features:
            raise KeyError(f"unknown feature: {name}")
        setattr(self, name, enabled)
        self._features[name] = enabled

    def is_enabled(self, name: str) -> bool:
        """Return ``True`` if ``name`` is enabled."""
        if name not in self._features:
            raise KeyError(f"unknown feature: {name}")
        return self._features[name]
