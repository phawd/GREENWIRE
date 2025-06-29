import pathlib
import py_compile
import sys
from pathlib import Path
import pytest

pytest.importorskip("smartcard", reason="pyscard not installed")

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "greenwire-brute.py"

def test_terminal_emulation_cli():
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--emulate", "terminal", "--emv-transaction"],
        capture_output=True,
        text=True,
=======

import importlib.util

_terminal_path = pathlib.Path(__file__).with_name("terminal_emulator.py")
spec = importlib.util.spec_from_file_location(
    "terminal_emulator",
    _terminal_path,
)
terminal_emulator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(terminal_emulator)
run_cli = terminal_emulator.run_cli
TerminalEmulator = terminal_emulator.TerminalEmulator


def _script_path() -> pathlib.Path:
    """Return the absolute path to greenwire-brute-improved.py."""
    return (
        pathlib.Path(__file__).resolve().parents[2]
        / "greenwire-brute-improved.py"
    )


def test_cli_script_compiles():
    (
        "greenwire-brute.py should be syntactically valid and contain "
        "EMULATION section."
 main
    )
    script = _script_path()
    py_compile.compile(str(script), doraise=True)
    content = script.read_text()
    assert "[EMULATION]" in content
    assert "--dda" in content
    assert "--wireless" in content


def test_terminal_emulator_runs_basic_command():
    emulator = TerminalEmulator()
    out = emulator.run(
        [sys.executable, "-c", "print('hello')"]
    )
    assert "hello" in out


def test_card_emulation_cli():
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--emulate", "card"],
        capture_output=True,
        text=True,
=======
def test_terminal_emulator_sets_issuer_env():
    emulator = TerminalEmulator(issuer="BankX")
    out = emulator.run(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ['TERMINAL_ISSUER'])",
        ]
 main
    )
    assert "BankX" in out
