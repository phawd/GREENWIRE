"""Windows-focused runtime helpers."""

from __future__ import annotations

import locale
import os
import shutil
import sys
from typing import Dict


def configure_windows_console() -> Dict[str, object]:
    info: Dict[str, object] = {
        "platform": sys.platform,
        "configured": False,
        "encoding": getattr(sys.stdout, "encoding", None),
        "java": shutil.which("java"),
        "adb": shutil.which("adb"),
    }
    if os.name != "nt":
        return info

    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None) if stream is not None else None
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    info["configured"] = True
    info["encoding"] = getattr(sys.stdout, "encoding", None) or locale.getpreferredencoding(False)
    return info


__all__ = ["configure_windows_console"]
