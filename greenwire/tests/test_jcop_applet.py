import importlib.util
from pathlib import Path

_applet_path = Path(__file__).resolve().parents[1] / "core" / "greenprobe_applet.py"
spec = importlib.util.spec_from_file_location("greenprobe_applet", _applet_path)
greenprobe_applet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(greenprobe_applet)


def test_probe_terminal_log(monkeypatch):
    class DummyReader:
        def __init__(self):
            self.connected = False

        def connect(self):
            self.connected = True
            return True

        def transceive(self, data: bytes):
            return b"9000"

        def disconnect(self):
            self.connected = False
    applet = greenprobe_applet.GreenProbeApplet()
    dummy = DummyReader()
    applet.probe_terminal(dummy, terminal_name="TEST")
    log = applet.get_transaction_log()
    assert log and log[0]["terminal"] == "TEST"


def test_fuzz_after_identification(monkeypatch):
    class DummyReader:
        def connect(self):
            return True

        def transceive(self, data: bytes):
            return b"9000"

        def disconnect(self):
            pass

    applet = greenprobe_applet.GreenProbeApplet()
    dummy = DummyReader()
    applet.fuzz_after_identification("ATM", dummy)
    log = applet.get_transaction_log()
    assert any(entry.get("fuzzed") == "ATM" for entry in log)
