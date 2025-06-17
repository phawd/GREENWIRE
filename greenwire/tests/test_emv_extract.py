import importlib.util
from pathlib import Path
import sys

_emv_path = Path(__file__).resolve().parents[1] / "core" / "nfc_emv.py"
spec = importlib.util.spec_from_file_location("nfc_emv", _emv_path)
nfc_emv = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(_emv_path.parents[1]))
sys.modules[spec.name] = nfc_emv
spec.loader.exec_module(nfc_emv)


class DummyTag:
    def __init__(self):
        self.log_reads = []

    def send_apdu(self, cla, ins, p1, p2, data=b""):
        if ins == 0xA4:
            return b"\x90\x00"
        if ins == 0xA8:
            return b"\x80\x0A\x94\x04\x18\x01\x01\x00\x00\x00\x00\x00"
        if ins == 0xB2 and p1 == 1:
            # record with Log Entry SFI=2, records=3 and log format tag
            return b"\x70\x0A\x9F\x4D\x02\x02\x03\x9F\x4F\x01\xAA"
        if ins == 0xB2 and p1 in {1, 2, 3} and (p2 >> 3) == 2:
            self.log_reads.append(p1)
            return b"\x70\x02\x9F\x11\x02"
        return b"\x90\x00"


class DummyCLF:
    def connect(self, rdwr):
        return DummyTag()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        pass


def test_extract_emv_data_collects_logs():
    proc = nfc_emv.NFCEMVProcessor()
    proc._connect = lambda: DummyCLF()
    data = proc.extract_emv_data()
    assert len(data["records"]) == 1
    assert len(data["transactions"]) == 3
