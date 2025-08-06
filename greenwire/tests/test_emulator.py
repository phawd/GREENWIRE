
import unittest
import sys
from pathlib import Path

# Ensure the greenwire package is on sys.path for absolute imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from greenwire.emulator import UnifiedEmulator


class TestUnifiedEmulator(unittest.TestCase):
    """Unit tests for the UnifiedEmulator class covering NFC, smartcard, and hardware reset."""

    def setUp(self):
        self.emulator = UnifiedEmulator()

    def test_simulate_terminal_nfc(self):
        """Test NFC terminal simulation returns expected response."""
        response = self.emulator.simulate_terminal("nfc", "00A40400")
        self.assertEqual(response, '9000', "NFC terminal simulation failed.")

    def test_simulate_terminal_smartcard(self):
        """Test smartcard terminal simulation returns expected response."""
        response = self.emulator.simulate_terminal("smartcard", "00B00000")
        self.assertEqual(response, '9000', "Smartcard terminal simulation failed.")

    def test_emulate_nfc_operations(self):
        """Test NFC emulation operations run without exception."""
        try:
            self.emulator.emulate_nfc_operations(duration=5)
        except Exception as e:
            self.fail(f"NFC emulation raised an exception: {e}")

    def test_emulate_smartcard_operations(self):
        """Test smartcard emulation operations run without exception."""
        try:
            self.emulator.emulate_smartcard_operations(duration=5)
        except Exception as e:
            self.fail(f"Smartcard emulation raised an exception: {e}")

    def test_reset_hardware(self):
        """Test hardware reset runs without exception."""
        try:
            self.emulator.reset_hardware()
        except Exception as e:
            self.fail(f"Hardware reset raised an exception: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
