import os
import sys

# Add stubs to path
stub_dir = os.path.join(os.path.dirname(__file__), 'stubs')
if stub_dir not in sys.path:
    sys.path.insert(0, stub_dir)

import greenwire.core.hardware as hw


def test_list_pcsc_readers_empty():
    assert hw.list_pcsc_readers() == []


def test_send_apdu_monkeypatch(monkeypatch):
    class DummyConn:
        def transmit(self, apdu):
            return [0x01], 0x90, 0x00

    monkeypatch.setattr(hw, 'connect_pcsc', lambda idx=0: DummyConn())
    data, sw1, sw2 = hw.send_apdu(b"\x00\x84\x00\x00")
    assert data == b"\x01"
    assert sw1 == 0x90 and sw2 == 0x00

