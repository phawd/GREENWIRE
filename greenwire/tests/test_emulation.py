import subprocess
import sys
import pytest

def test_terminal_emulation_cli():
    result = subprocess.run([
        sys.executable, "../../greenwire-brute.py", "--emulate", "terminal", "--emv-transaction"],
        capture_output=True, text=True
    )
    assert "EMULATION" in result.stdout or "EMULATION" in result.stderr

def test_card_emulation_cli():
    result = subprocess.run([
        sys.executable, "../../greenwire-brute.py", "--emulate", "card"],
        capture_output=True, text=True
    )
    assert "EMULATION" in result.stdout or "EMULATION" in result.stderr
