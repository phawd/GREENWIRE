import importlib.util
from pathlib import Path

_applet_path = Path(__file__).resolve().parents[1] / "core" / "jcop_applet.py"
spec = importlib.util.spec_from_file_location("jcop_applet", _applet_path)
jcop_applet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jcop_applet)


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
    applet = jcop_applet.JCOPProbeApplet()
    dummy = DummyReader()
    applet.probe_terminal(dummy, terminal_name="TEST")
    log = applet.get_transaction_log()
    assert log and log[0]["terminal"] == "TEST"
