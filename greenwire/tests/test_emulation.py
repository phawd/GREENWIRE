import subprocess
import sys
import os
import pytest

SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "greenwire-brute.py"))
STUB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "tests", "stubs"))

def run_script(args):
    env = os.environ.copy()
    env["PYTHONPATH"] = STUB_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(args, capture_output=True, text=True, env=env)

@pytest.mark.xfail(reason="Emulation requires external dependencies")
def test_terminal_emulation_cli():
    result = run_script([
        sys.executable,
        SCRIPT,
        "--mode",
        "standard",
        "--emulate",
        "terminal",
        "--emv-transaction",
    ])
    assert "EMULATION" in result.stdout or "EMULATION" in result.stderr

@pytest.mark.xfail(reason="Emulation requires external dependencies")
def test_card_emulation_cli():
    result = run_script([
        sys.executable,
        SCRIPT,
        "--mode",
        "standard",
        "--emulate",
        "card",
    ])
    assert "EMULATION" in result.stdout or "EMULATION" in result.stderr
