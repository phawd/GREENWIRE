import importlib.util
from pathlib import Path
import sys

_fuzzer_path = Path(__file__).resolve().parents[1] / "core" / "fuzzer.py"
sys.path.insert(0, str(_fuzzer_path.parents[2]))
spec = importlib.util.spec_from_file_location("fuzzer", _fuzzer_path)
fuzzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fuzzer)


class DummyEmulator:
    def __init__(self):
        self.commands = []

    def send_apdu(self, cla, ins, p1, p2, data=b""):
        self.commands.append((cla, ins, p1, p2, data))
        return b"\x90\x00"


def test_fuzz_applet_emulation(monkeypatch):
    emulator = DummyEmulator()
    sf = fuzzer.SmartcardFuzzer({"dry_run": True})
    res = sf.fuzz_applet_emulation(emulator, "A0000000031010", iterations=2)
    assert len(res) == 2
    assert emulator.commands[0][1] == 0xA4
