"""Lightweight terminal wrapper used for unit tests."""

import sys
import os
import pathlib
import pexpect
from typing import Optional


class TerminalEmulator:
    """Simple utility to run commands inside a pseudo-terminal."""

    def __init__(self, env: Optional[dict] = None, issuer: str | None = None):
        self.env = env or os.environ.copy()
        self.issuer = issuer or "TEST_ISSUER"

    def run(self, command, timeout: int = 5) -> str:
        env = self.env.copy()
        env["TERMINAL_ISSUER"] = self.issuer
        child = pexpect.spawn(command[0], command[1:], env=env, encoding="utf-8")
        child.expect(pexpect.EOF, timeout=timeout)
        return child.before


def _script_path() -> pathlib.Path:
    """Return the absolute path to greenwire-brute.py."""
    return pathlib.Path(__file__).resolve().parents[2] / "greenwire-brute.py"


def run_cli(args, timeout: int = 5, issuer: str | None = None) -> str:
    """Run the CLI script inside a pseudo-terminal and return its output."""
    mocks = pathlib.Path(__file__).parent
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{str(mocks)}:{env.get('PYTHONPATH', '')}"
    emulator = TerminalEmulator(env=env, issuer=issuer)
    return emulator.run([sys.executable, str(_script_path()), *args], timeout=timeout)
