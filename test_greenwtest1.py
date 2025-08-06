import unittest
from unittest.mock import MagicMock, patch
from greenwtest1 import TLVParser, VulnerabilityDetector, init_database, run_standard, run_fuzz

class TestTLVParser(unittest.TestCase):
    def test_parse_valid_tlv(self):
        data = bytes.fromhex("6F108407A0000000031010A5049F3704")
        result = TLVParser.parse(data)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0].tag.hex().upper(), "6F")
        self.assertEqual(result[1].tag.hex().upper(), "84")
        self.assertEqual(result[2].tag.hex().upper(), "A5")

    def test_parse_invalid_tlv(self):
        data = bytes.fromhex("6F108407A0000000031010A5049F37")
        result = TLVParser.parse(data)
        self.assertEqual(len(result), 2)  # Should stop parsing at incomplete TLV

class TestVulnerabilityDetector(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.detector = VulnerabilityDetector(self.mock_db)

    def test_analyze_command_timing_anomaly(self):
        for _ in range(10):
            self.detector.analyze_command("SELECT", b"", b"", 0x90, 0x00, 0.5)
        findings = self.detector.analyze_command("SELECT", b"", b"", 0x90, 0x00, 2.0)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'TIMING_ANOMALY')

    def test_analyze_command_suspicious_status(self):
        findings = self.detector.analyze_command("SELECT", b"", b"", 0x62, 0x83, 0.5)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'SUSPICIOUS_STATUS')

class TestRunFunctions(unittest.TestCase):
    @patch("greenwtest1.readers", return_value=["MockReader"])
    @patch("greenwtest1.CardConnection")
    def test_run_standard(self, mock_card_connection, mock_readers):
        mock_conn = MagicMock()
        mock_fuzzer = MagicMock()
        mock_detector = MagicMock()
        mock_card = mock_card_connection.return_value
        mock_card.transmit.return_value = ([], 0x90, 0x00)

        run_standard(mock_conn, MagicMock(), mock_fuzzer, mock_detector)
        mock_card.transmit.assert_called()
        mock_detector.analyze_command.assert_called()

    @patch("greenwtest1.SmartcardFuzzer")
    def test_run_fuzz(self, mock_fuzzer_class):
        mock_conn = MagicMock()
        mock_fuzzer = mock_fuzzer_class.return_value
        mock_detector = MagicMock()
        mock_fuzzer.simulate_attack_scenario.return_value = {"result": "success"}

        run_fuzz(mock_conn, MagicMock(), mock_fuzzer, mock_detector)
        # Assert that simulate_attack_scenario was called with the expected argument
        mock_fuzzer.simulate_attack_scenario.assert_called_with("SDA_DOWNGRADE")
        # Assert that analyze_command was called (for consistency with other tests)
        mock_detector.analyze_command.assert_called()



if __name__ == "__main__":
    unittest.main()
