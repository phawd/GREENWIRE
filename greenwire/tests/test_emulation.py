import subprocess
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
    )
    assert "EMULATION" in result.stdout or "EMULATION" in result.stderr

def test_card_emulation_cli():
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--emulate", "card"],
        capture_output=True,
        text=True,
    )
    assert "EMULATION" in result.stdout or "EMULATION" in result.stderr
