import importlib.util
from pathlib import Path
import sys

# load modules directly
_iso_path = Path(__file__).resolve().parents[1] / "core" / "nfc_iso.py"
spec = importlib.util.spec_from_file_location("nfc_iso", _iso_path)
nfc_iso = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nfc_iso)

_vuln_path = Path(__file__).resolve().parents[1] / "nfc_vuln.py"
spec2 = importlib.util.spec_from_file_location("nfc_vuln", _vuln_path)
nfc_vuln = importlib.util.module_from_spec(spec2)
sys.path.insert(0, str(_vuln_path.parents[1]))
spec2.loader.exec_module(nfc_vuln)


class DummyRW(nfc_iso.ISO14443ReaderWriter):
    def authenticate(self, block: int, key: bytes) -> bool:
        return key == b"\xff" * 6


class BackdoorRW(DummyRW):
    def transceive(self, data: bytes) -> bytes:
        if data == b"\x40\x43":
            return b"\x0a"
        raise RuntimeError("No tag")


def test_scan_vulnerabilities_detects_default_key():
    reader = DummyRW()
    vulns = nfc_vuln.scan_nfc_vulnerabilities(reader)
    assert any(v["type"] == "DEFAULT_KEY" for v in vulns)


def test_scan_vulnerabilities_unprotected_block():
    reader = DummyRW()
    reader.write_block(4, b"data")
    vulns = nfc_vuln.scan_nfc_vulnerabilities(reader)
    assert {"type": "UNPROTECTED_BLOCK", "block": 4} in vulns


def test_detect_backdoor_cloning():
    reader = BackdoorRW()
    assert nfc_vuln.detect_backdoor_cloning(reader) is True
