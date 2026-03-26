"""Persistent PAN registry to prevent duplicate auto-generated PANs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional


_REGISTRY_PATH = Path("data") / "generated_pans.json"


def _normalize_pan(pan: str) -> str:
    return "".join(ch for ch in str(pan or "") if ch.isdigit())


def _load_registry(path: Optional[Path] = None) -> Dict[str, Dict[str, str]]:
    registry_path = path or _REGISTRY_PATH
    if not registry_path.exists():
        return {}
    try:
        return json.loads(registry_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_registry(registry: Dict[str, Dict[str, str]], path: Optional[Path] = None) -> None:
    registry_path = path or _REGISTRY_PATH
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")


def is_registered(pan: str, *, path: Optional[Path] = None) -> bool:
    normalized = _normalize_pan(pan)
    if not normalized:
        return False
    registry = _load_registry(path)
    return normalized in registry


def register_pan(
    pan: str,
    *,
    source: str,
    allow_existing: bool = False,
    path: Optional[Path] = None,
) -> bool:
    normalized = _normalize_pan(pan)
    if not normalized:
        return False
    registry = _load_registry(path)
    if normalized in registry and not allow_existing:
        return False
    registry[normalized] = {
        "registered_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "source": source,
    }
    _save_registry(registry, path)
    return True


def acquire_unique_pan(
    generator: Callable[[], str],
    *,
    source: str,
    reserve: bool = True,
    max_attempts: int = 1000,
    path: Optional[Path] = None,
) -> str:
    for _ in range(max_attempts):
        candidate = _normalize_pan(generator())
        if not candidate:
            continue
        if is_registered(candidate, path=path):
            continue
        if reserve:
            if register_pan(candidate, source=source, allow_existing=False, path=path):
                return candidate
            continue
        return candidate
    raise RuntimeError("Unable to generate a unique PAN after maximum attempts")


__all__ = [
    "acquire_unique_pan",
    "is_registered",
    "register_pan",
]
