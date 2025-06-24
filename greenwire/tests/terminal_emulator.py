"""Lightweight terminal wrapper used for unit tests."""

import sys
import os
import pathlib
import pexpect
from typing import Optional


class TerminalEmulator:
    """Simple utility to run commands inside a pseudo-terminal.

    This class relies on :mod:`pexpect` to spawn a child process and interact
    with it as if a real terminal were attached.  It is primarily used by the
    unit tests to exercise the CLI in an isolated environment.
    """

    def __init__(self, env: Optional[dict] = None, issuer: str | None = None):
        self.env = env or os.environ.copy()
        self.issuer = issuer or "TEST_ISSUER"

    def run(self, command, timeout: int = 5) -> str:
        """Execute ``command`` inside a pseudo-terminal and capture the output.

        The returned string contains everything printed by the child process.
        """

        env = self.env.copy()
        env["TERMINAL_ISSUER"] = self.issuer

        # ``pexpect.spawn`` launches the child process and gives us control
        # over its stdin/stdout streams for deterministic testing.
        child = pexpect.spawn(
            command[0],
            command[1:],
            env=env,
            encoding="utf-8",
        )
        child.expect(pexpect.EOF, timeout=timeout)
        return child.before


def _script_path() -> pathlib.Path:
    """Return the absolute path to ``greenwire-brute.py`` used in tests."""
    return pathlib.Path(__file__).resolve().parents[2] / "greenwire-brute.py"


def run_cli(args, timeout: int = 5, issuer: str | None = None) -> str:
    """Run the CLI script inside a pseudo-terminal and return its output.

    The environment's ``PYTHONPATH`` is extended so that the test mocks take
    precedence over any system-wide installations.  This ensures consistent
    behaviour regardless of the surrounding environment.
    """
    mocks = pathlib.Path(__file__).parent
    env = os.environ.copy()
    env["PYTHONPATH"] = (
        f"{str(mocks)}:{env.get('PYTHONPATH', '')}"
    )
    emulator = TerminalEmulator(env=env, issuer=issuer)
    return emulator.run(
        [sys.executable, str(_script_path()), *args],
        timeout=timeout,
    )
