import importlib.util
from pathlib import Path

_applet_path = Path(__file__).resolve().parents[1] / "core" / "applet_generator.py"
spec = importlib.util.spec_from_file_location("applet_generator", _applet_path)
applet_generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(applet_generator)


def test_generate_applet_bytes(tmp_path):
    data = applet_generator.generate_applet()
    assert isinstance(data, bytes)
    assert len(data) > 32
    out = tmp_path / "sample.cap"
    applet_generator.save_applet(data, out)
    assert out.exists()
    assert out.read_bytes() == data
