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


def test_attack_terminal_atm():
    class DummyReader:
        def __init__(self):
            self.cmds = []

        def connect(self):
            return True

        def transceive(self, data: bytes):
            self.cmds.append(data)
            return b"9000"

        def disconnect(self):
            pass

    applet = greenprobe_applet.GreenProbeApplet()
    dummy = DummyReader()
    applet.attack_terminal("ATM", dummy)
    log = applet.get_transaction_log()
    assert any(entry.get("attack") == "ATM" for entry in log)
    assert dummy.cmds


def test_attack_terminal_generic():
    class DummyReader:
        def __init__(self):
            self.cmds = []

        def connect(self):
            return True

        def transceive(self, data: bytes):
            self.cmds.append(data)
            return b"9000"

        def disconnect(self):
            pass

    applet = greenprobe_applet.GreenProbeApplet()
    dummy = DummyReader()
    applet.attack_terminal("POS", dummy)
    log = applet.get_transaction_log()
    assert any(entry.get("attack") == "POS" for entry in log)
    # Expect at least 100 APDUs (50 loops of 2 commands + 50 GENERATE_AC)
    assert len(dummy.cmds) >= 100
