#!/usr/bin/env python3
"""Global defaults configuration for GREENWIRE.
Centralizes cross-feature runtime defaults accessible by menu and CLI.
"""
from __future__ import annotations  # noqa: F401
import json, os, threading  # noqa: F401
from pathlib import Path

_DEFAULTS = {
    "verbose_default": True,
    "max_payload_default": 220,
    "stateful_default": False,
    "artifact_dir_default": ".",
}

_LOCK = threading.Lock()
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "global_defaults.json"


def _ensure_file():
    if not _CONFIG_PATH.exists():
        save_defaults(_DEFAULTS)


def load_defaults() -> dict:
    _ensure_file()
    try:
        with _LOCK, open(_CONFIG_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Merge with defaults to fill missing keys
        merged = {**_DEFAULTS, **data}
        return merged
    except Exception:
        return dict(_DEFAULTS)


def save_defaults(new_values: dict):
    merged = {**_DEFAULTS, **new_values}
    with _LOCK:
        with open(_CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(merged, f, indent=2)
    return merged


def update_defaults(**kwargs):
    current = load_defaults()
    current.update({k: v for k,v in kwargs.items() if k in _DEFAULTS})
    return save_defaults(current)

__all__ = ["load_defaults", "save_defaults", "update_defaults"]
