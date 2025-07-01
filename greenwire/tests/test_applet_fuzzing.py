from greenwire.core.fuzzer import SmartcardFuzzer


class DummyEmulator:
    def __init__(self):
        self.commands = []

    def send_apdu(self, cla, ins, p1, p2, data=b""):
        self.commands.append((cla, ins, p1, p2, data))
        return b"\x90\x00"


def test_fuzz_applet_emulation(monkeypatch):
    emulator = DummyEmulator()
    sf = SmartcardFuzzer({"dry_run": True})
    res = sf.fuzz_applet_emulation(emulator, "A0000000031010", iterations=2)
    assert len(res) == 2
    assert emulator.commands[0][1] == 0xA4
    assert emulator.commands[1][1] == 0xB0
