import importlib.util
from pathlib import Path

_fuzzer_path = Path(__file__).resolve().parents[1] / "core" / "fuzzer.py"
spec = importlib.util.spec_from_file_location("fuzzer", _fuzzer_path)
fuzzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fuzzer)


def test_parse_and_find_tag():
    data = bytes.fromhex("9F02060000000100009F110101")
    objs = fuzzer.TLVParser.parse(data)
    assert len(objs) == 2
    assert objs[0].tag == bytes.fromhex("9F02")
    assert objs[0].length == 6
    assert objs[0].value == bytes.fromhex("000000010000")
    assert objs[1].tag == bytes.fromhex("9F11")
    assert objs[1].value == bytes.fromhex("01")

    val = fuzzer.TLVParser.find_tag(data, "9F02")
    assert val == bytes.fromhex("000000010000")
