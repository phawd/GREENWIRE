import importlib
import sys
import types
import os

import pytest

@pytest.fixture(scope="module")
def tlv_parser():
    # Stub smartcard modules to satisfy imports in greenwire.core.fuzzer
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if root_dir not in sys.path:
        sys.path.insert(0, root_dir)
    smartcard = types.ModuleType("smartcard")
    system_mod = types.ModuleType("smartcard.System")
    system_mod.readers = lambda: []
    util_mod = types.ModuleType("smartcard.util")
    util_mod.toHexString = lambda data: ' '.join(f'{b:02X}' for b in data)
    util_mod.toBytes = lambda s: bytes.fromhex(s.replace(' ', ''))

    sys.modules.setdefault("smartcard", smartcard)
    sys.modules.setdefault("smartcard.System", system_mod)
    sys.modules.setdefault("smartcard.util", util_mod)
    # Link submodules to the parent package
    smartcard.System = system_mod
    smartcard.util = util_mod

    module = importlib.import_module("greenwire.core.fuzzer")
    return module.TLVParser

def test_parse_and_find_simple(tlv_parser):
    hex_data = "5A0847617390010100105F3401029F1A020840"
    data = bytes.fromhex(hex_data)
    objects = tlv_parser.parse(data)
    assert len(objects) == 3
    assert [obj.tag for obj in objects] == [bytes.fromhex("5A"), bytes.fromhex("5F34"), bytes.fromhex("9F1A")]
    assert objects[0].value == bytes.fromhex("4761739001010010")
    assert tlv_parser.find_tag(data, "5F34") == bytes.fromhex("02")
    assert tlv_parser.find_tag(data, bytes.fromhex("9F1A")) == bytes.fromhex("0840")


def test_parse_multibyte_length(tlv_parser):
    hex_data = "9F468120" + "AA"*32 + "5F2A020840"
    data = bytes.fromhex(hex_data)
    objects = tlv_parser.parse(data)
    assert len(objects) == 2
    assert objects[0].tag == bytes.fromhex("9F46")
    assert objects[0].length == 32
    assert objects[0].value == bytes.fromhex("AA"*32)
    assert tlv_parser.find_tag(data, "9F46") == bytes.fromhex("AA"*32)
    assert tlv_parser.find_tag(data, "FFFF") is None
