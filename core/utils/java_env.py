"""Static JDK environment helper.

Detects a bundled JDK under static/java/jdk and adjusts process environment
variables (JAVA_HOME and PATH) to prefer it. This keeps GREENWIRE portable
and avoids depending on a system-wide JDK.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def _find_static_jdk_bin() -> Optional[Path]:
    here = Path(__file__).resolve()
    # core/utils/java_env.py -> core/utils -> core -> repo root (parents[2])
    root = here.parents[2]
    jdk_root = root / 'static' / 'java' / 'jdk'
    if not jdk_root.exists():
        return None
    # Prefer the longest folder name (e.g., jdk8u462-b08 over generic)
    candidates = list(jdk_root.glob('jdk*/bin'))
    if candidates:
        return max(candidates, key=lambda p: len(str(p)))
    # Fallback to static/java/jdk/bin
    fallback = jdk_root / 'bin'
    return fallback if fallback.exists() else None


def prefer_static_jdk() -> Optional[Path]:
    """If a static JDK is bundled, set JAVA_HOME and prepend its bin to PATH.

    Returns the Path to the bin directory used, or None if not configured.
    """
    bin_path = _find_static_jdk_bin()
    if not bin_path:
        return None

    jdk_home = bin_path.parent
    # Set JAVA_HOME for child processes
    os.environ['JAVA_HOME'] = str(jdk_home)

    # Prepend bin to PATH once per process
    path_sep = ';' if os.name == 'nt' else ':'
    current_path = os.environ.get('PATH', '')
    bin_str = str(bin_path)
    if not current_path.lower().startswith(bin_str.lower()):
        os.environ['PATH'] = bin_str + path_sep + current_path

    return bin_path
