"""Test configuration for GREENWIRE project.

This file ensures the project root is available on sys.path so that tests can
import modules using the canonical package names (e.g. ``GREENWIRE.core``).
"""
from __future__ import annotations  # noqa: F401

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
