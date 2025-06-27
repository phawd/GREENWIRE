import importlib.util
from pathlib import Path
from PIL import Image

_fuzzer_path = Path(__file__).resolve().parents[1] / "core" / "file_fuzzer.py"
spec = importlib.util.spec_from_file_location("file_fuzzer", _fuzzer_path)
file_fuzzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(file_fuzzer)


def test_fuzz_image_file(tmp_path):
    img = Image.new("RGB", (1, 1))
    img_path = tmp_path / "img.png"
    img.save(img_path)
    res = file_fuzzer.fuzz_image_file(img_path, iterations=2)
    assert len(res) == 2


def test_fuzz_binary_file(tmp_path):
    bin_path = tmp_path / "bin.dat"
    bin_path.write_bytes(b"\x00\x01\x02")
    res = file_fuzzer.fuzz_binary_file(bin_path, iterations=2)
    assert len(res) == 2


def test_fuzz_unusual_input():
    res = file_fuzzer.fuzz_unusual_input(lambda s: len(s), "abc", iterations=2)
    assert len(res) == 2
