import importlib.util
from pathlib import Path
import pytest

_iso_path = Path(__file__).resolve().parents[1] / "core" / "nfc_iso.py"
spec = importlib.util.spec_from_file_location("nfc_iso", _iso_path)
nfc_iso = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nfc_iso)


def _run_rw_test(cls):
    handler = cls()
    handler.write_block(1, b"test")
    assert handler.read_block(1) == b"test"
    assert handler.read_block(2) == b""


def test_iso14443_rw():
    _run_rw_test(nfc_iso.ISO14443ReaderWriter)


def test_iso15693_rw():
    _run_rw_test(nfc_iso.ISO15693ReaderWriter)


def test_iso18092_rw():
    _run_rw_test(nfc_iso.ISO18092ReaderWriter)


def test_transceive_requires_connection():
    handler = nfc_iso.ISO14443ReaderWriter()
    with pytest.raises(RuntimeError):
        handler.transceive(b"\x00")
