import importlib.util
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# load modules directly
_menu_path = Path(__file__).resolve().parents[1] / "menu_cli.py"
spec = importlib.util.spec_from_file_location("menu_cli", _menu_path)
menu_cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menu_cli)

_backend_path = Path(__file__).resolve().parents[1] / "core" / "backend.py"
spec2 = importlib.util.spec_from_file_location("greenwire.core.backend", _backend_path)
backend = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(backend)


def test_menu_functions(monkeypatch, tmp_path, capsys):
    conn = backend.init_backend(tmp_path / "db.sqlite")

    class DummyTerminal:
        def __init__(self, aids):
            pass
        def run(self):
            return [{"aid": "A"}]
    monkeypatch.setattr(menu_cli, "ContactlessEMVTerminal", DummyTerminal)

    class DummyReader(menu_cli.ISO14443ReaderWriter):
        def __init__(self):
            super().__init__()
            self.tag = type("Tag", (), {"ats": b"\x3B\x00"})()
        def connect(self, device: str = "usb") -> bool:
            return True
    monkeypatch.setattr(menu_cli, "ISO14443ReaderWriter", DummyReader)

    monkeypatch.setattr(menu_cli, "scan_nfc_vulnerabilities", lambda r: [])
    monkeypatch.setattr(menu_cli.SmartcardFuzzer, "fuzz_contactless", lambda self, aids, iterations=1: [{"fuzz": True}])
    monkeypatch.setattr(menu_cli.SmartcardFuzzer, "fuzz_pcsc_random", lambda self: [{"pcsc": True}])
    monkeypatch.setattr(menu_cli, "fuzz_image_file", lambda p: ["img"])
    monkeypatch.setattr(menu_cli, "fuzz_binary_file", lambda p: ["bin"])
    monkeypatch.setattr(menu_cli, "fuzz_unusual_input", lambda f, b: ["unusual"])

    inputs = iter([
        "0",        # read_nfc_block
        "0", "00",  # write_nfc_block
        str(tmp_path / "seed.txt"), "unusual",  # fuzz_file_menu
    ])
    import builtins
    monkeypatch.setattr(builtins, "input", lambda _: next(inputs))
    monkeypatch.setattr(menu_cli.NFCEMVProcessor, "read_uid", lambda self: "UID")

    (tmp_path / "seed.txt").write_text("seed")

    # call each helper
    menu_cli.issue_new_card(conn)
    menu_cli.show_card_count(conn)
    menu_cli.list_cards(conn)
    menu_cli.run_contactless_txn()
    menu_cli.scan_vulnerabilities()
    menu_cli.read_nfc_block()
    menu_cli.write_nfc_block()
    menu_cli.show_uid(menu_cli.NFCEMVProcessor())
    menu_cli.dump_atr()
    menu_cli.dump_memory(1)
    menu_cli.brute_force_pin()
    menu_cli.fuzz_apdu()
    menu_cli.fuzz_transaction()
    menu_cli.scan_for_cards()
    menu_cli.dump_filesystem()
    menu_cli.export_data(conn)
    menu_cli.import_data()
    menu_cli.reset_card()
    menu_cli.detect_card_os()
    menu_cli.fuzz_file_menu()
    menu_cli.fuzz_pcsc()

    captured = capsys.readouterr()
    assert "Issued card" in captured.out
