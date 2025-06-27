import importlib.util
from pathlib import Path

_symm_path = Path(__file__).resolve().parents[1] / "core" / "symm_analysis.py"
spec = importlib.util.spec_from_file_location("symm_analysis", _symm_path)
symm_analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(symm_analysis)


def test_entropy_low_detected():
    info = symm_analysis.analyze_symmetric_key(b"\x00" * 16, "AES")
    assert any("Low entropy" in w for w in info["potential_weaknesses"])


def test_valid_key_length():
    info = symm_analysis.analyze_symmetric_key(bytes(range(16)), "AES")
    assert info["key_length"] == 128
