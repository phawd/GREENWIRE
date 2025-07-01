"""Utility helpers for GREENWIRE tests.

This module provides small helper functions used by the test suite
and standalone scripts. The functionality is intentionally minimal
so it can be reused in lightweight test scenarios.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Iterable, Tuple

logger = logging.getLogger(__name__)


def run_command(cmd: Iterable[str], timeout: int = 30) -> Tuple[str, str, int]:
    """Run *cmd* as a subprocess.

    Parameters
    ----------
    cmd : Iterable[str]
        Command and arguments to execute.
    timeout : int
        Maximum time in seconds before the process is terminated.

    Returns
    -------
    tuple
        Standard output, standard error, and return code.
    """
    logger.debug("Running command: %s", " ".join(cmd))
    result = subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout, result.stderr, result.returncode


def ensure_file(path: str | Path) -> Path:
    """Return *path* if it exists, otherwise raise FileNotFoundError."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{p} does not exist")
    return p
