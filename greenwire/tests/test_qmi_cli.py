import importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest

# dynamic import like other tests
_qmi_path = Path(__file__).resolve().parents[1] / "qmi_cli.py"
spec = importlib.util.spec_from_file_location("qmi_cli", _qmi_path)
qmi_cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qmi_cli)


def test_get_device_ids_invokes_qmicli(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output=True, text=True, check=False):
        captured["cmd"] = cmd
        return SimpleNamespace(stdout="OK")

    monkeypatch.setattr(qmi_cli.shutil, "which", lambda name: "/usr/bin/qmicli")
    monkeypatch.setattr(qmi_cli.subprocess, "run", fake_run)
    out = qmi_cli.get_device_ids("/dev/test")
    assert out == "OK"
    assert captured["cmd"] == ["/usr/bin/qmicli", "-d", "/dev/test", "--dms-get-ids"]


def test_send_raw_message_requires_hex(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output=True, text=True, check=False):
        captured["cmd"] = cmd
        return SimpleNamespace(stdout="RAW")

    monkeypatch.setattr(qmi_cli.shutil, "which", lambda name: "/usr/bin/qmicli")
    monkeypatch.setattr(qmi_cli.subprocess, "run", fake_run)
    out = qmi_cli.send_raw_message("00ff", "/dev/test")
    assert out == "RAW"
    assert "--qmi-proxy=00ff" in captured["cmd"][-1]


def test_run_qmicli_raises_without_binary(monkeypatch):
    monkeypatch.setattr(qmi_cli.shutil, "which", lambda name: None)
    with pytest.raises(FileNotFoundError):
        qmi_cli.get_device_ids()


def test_main_falls_back_to_serial(monkeypatch, capsys):
    monkeypatch.setattr(qmi_cli.shutil, "which", lambda name: None)
    monkeypatch.setattr(qmi_cli.glob, "glob", lambda pat: ["/dev/ttyUSB0"])
    qmi_cli.main(["ids"])
    out = capsys.readouterr().out
    assert "serial port" in out
