import importlib.util
from pathlib import Path
import sys

_fuzzer_path = Path(__file__).resolve().parents[1] / "core" / "fuzzer.py"
sys.path.insert(0, str(_fuzzer_path.parents[2]))
spec = importlib.util.spec_from_file_location("fuzzer", _fuzzer_path)
fuzzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fuzzer)


class DummyTerminal:
    def __init__(self, aids, ca_keys):
        self.aids = aids

    def run(self):
        return [
            {
                "aid": aid,
                "select": b"\x90\x00",
                "gpo": b"\x90\x00",
            }
            for aid in self.aids
        ]


def test_fuzz_contactless_runs(monkeypatch):
    monkeypatch.setattr(fuzzer, "ContactlessEMVTerminal", DummyTerminal)
    sf = fuzzer.SmartcardFuzzer({"dry_run": True})
    res = sf.fuzz_contactless(["A0000000031010"], iterations=2)
    assert len(res) == 2
    assert res[0]["aid"] == "A0000000031010"
