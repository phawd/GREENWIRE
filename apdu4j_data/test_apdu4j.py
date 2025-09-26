#!/usr/bin/env python3
"""APDU4J integration test suite for GREENWIRE.

This module contains unit and integration tests for the APDU4J-related
components used by the GREENWIRE framework. It verifies APDU construction,
response parsing, GlobalPlatform command generation, and the APDU4J
interface adapter used to integrate APDU4J command templates into
GREENWIRE's testing and tooling.

Key contents and responsibilities:
- TestAPDU4JCommand: unit tests validating APDU4JCommand encoding and
  APDU case detection (Case 1, Case 2S, Case 4S) and helper command
  creators (SELECT AID, VERIFY PIN, GET DATA).
- TestAPDUResponseParsing: unit tests validating parse_apdu_response
  behaviour for success, error, and "more data" status words.
- TestGlobalPlatformCommands: tests for GlobalPlatform (GP) command
  generators (select card manager, get status, delete/install).
- TestAPDU4JInterface & TestGREENWIREIntegration: tests for the
  APDU4JInterface and GREENWIREAPDU4JInterface adapters that wrap a
  communicator and expose high-level execution methods (send_command,
  select_application, execute_command, send_raw_apdu).
- TestCommandTemplates: sanity checks for APDU_COMMANDS, PCSC_COMMANDS,
  and GP_COMMANDS dictionaries and their expected structure.

Utility functions:
- run_integration_tests(): lightweight runner that demonstrates and
  prints example commands and parsed responses; useful for manual
  integration checks.
- main(): entrypoint for running the unit test suite and the integration
  demo when executed as a script.

Usage:
- Run the full unit test suite:
    python -m unittest d.repo.GREENWIRE.apdu4j_data.test_apdu4j
  or
    python d:\repo\GREENWIRE\apdu4j_data\test_apdu4j.py

Notes:
- The tests expect the APDU helper modules (apdu_commands, gp_commands,
  apdu4j_integration) to be importable from the parent directory.
- Tests use mocks for communicators to avoid hardware dependency; the
  integration demo prints sample outputs and does not require a real
  card/reader.

"""

import logging, os, sys, unittest
from unittest.mock import Mock, patch  # noqa: F401

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from apdu4j_data.apdu_commands import APDU4JCommand, APDU4JInterface, APDU_CASE_1, APDU_CASE_2S, APDU_CASE_4S, APDU_COMMANDS, PCSC_COMMANDS, SW_SUCCESS, create_get_data_command, create_pin_verify_command, create_select_aid_command, parse_apdu_response
from apdu4j_data.gp_commands import GPCommand, GPManager, GP_COMMANDS  # noqa: F401
from apdu4j_data.apdu4j_integration import GREENWIREAPDU4JInterface, create_apdu4j_interface  # noqa: F401

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestAPDU4JCommand(unittest.TestCase):
    """Test APDU4J command structure and encoding."""
    
    def test_case_1_apdu(self):
        """Test Case 1 APDU (no data, no response)."""
        cmd = APDU4JCommand(0x00, 0xA4, 0x00, 0x0C)
        
        self.assertEqual(cmd.case, APDU_CASE_1)
        self.assertEqual(cmd.to_hex(), "00A4000C")
        self.assertEqual(len(cmd.to_bytes()), 4)
        
    def test_case_2s_apdu(self):
        """Test Case 2S APDU (no data, short Le)."""
        cmd = APDU4JCommand(0x00, 0xCA, 0x00, 0x00, le=256)
        
        self.assertEqual(cmd.case, APDU_CASE_2S)
        self.assertEqual(cmd.to_hex(), "00CA000000")  # Le=256 encoded as 00
        self.assertEqual(len(cmd.to_bytes()), 5)
        
    def test_case_4s_apdu(self):
        """Test Case 4S APDU (short data, short Le)."""
        pin_data = b"1234"
        cmd = APDU4JCommand(0x00, 0x20, 0x00, 0x80, pin_data, le=256)
        
        self.assertEqual(cmd.case, APDU_CASE_4S)
        expected = "00200080043132333400"  # CLA INS P1 P2 Lc Data Le (Le=0 for 256)
        self.assertEqual(cmd.to_hex(), expected.upper())
        
    def test_select_aid_command(self):
        """Test SELECT AID command creation."""
        visa_aid = "A0000000031010"
        cmd = create_select_aid_command(visa_aid)
        
        self.assertEqual(cmd.cla, 0x00)
        self.assertEqual(cmd.ins, 0xA4)
        self.assertEqual(cmd.p1, 0x04)
        self.assertEqual(cmd.p2, 0x00)
        self.assertEqual(cmd.data, bytes.fromhex(visa_aid))
        self.assertEqual(cmd.le, 256)
        
    def test_pin_verify_command(self):
        """Test PIN verification command creation."""
        pin = "1234"
        cmd = create_pin_verify_command(pin)
        
        self.assertEqual(cmd.cla, 0x00)
        self.assertEqual(cmd.ins, 0x20)
        self.assertEqual(cmd.p1, 0x00)
        self.assertEqual(cmd.p2, 0x80)
        self.assertEqual(cmd.data, b"1234")
        
    def test_get_data_command(self):
        """Test GET DATA command creation."""
        tag = 0x006E  # Application info tag
        cmd = create_get_data_command(tag)
        
        self.assertEqual(cmd.cla, 0x00)
        self.assertEqual(cmd.ins, 0xCA)
        self.assertEqual(cmd.p1, 0x00)
        self.assertEqual(cmd.p2, 0x6E)
        self.assertEqual(cmd.le, 256)

class TestAPDUResponseParsing(unittest.TestCase):
    """Test APDU response parsing functionality."""
    
    def test_success_response(self):
        """Test parsing successful response."""
        response = bytes.fromhex("6F1A840E315041592E5359532E44444630318701015F2D027A68") + bytes([0x90, 0x00])
        parsed = parse_apdu_response(response)
        
        self.assertTrue(parsed['success'])
        self.assertEqual(parsed['sw'], SW_SUCCESS)
        self.assertEqual(parsed['sw1'], 0x90)
        self.assertEqual(parsed['sw2'], 0x00)
        self.assertEqual(len(parsed['data']), len(response) - 2)
        
    def test_error_response(self):
        """Test parsing error response."""
        response = bytes([0x6A, 0x82])  # File not found
        parsed = parse_apdu_response(response)
        
        self.assertFalse(parsed['success'])
        self.assertEqual(parsed['sw'], 0x6A82)
        self.assertEqual(parsed['status'], 'File not found')
        self.assertEqual(len(parsed['data']), 0)
        
    def test_more_data_response(self):
        """Test parsing 61xx more data response."""
        response = bytes([0x61, 0x10])  # More data available (16 bytes)
        parsed = parse_apdu_response(response)
        
        self.assertFalse(parsed['success'])
        self.assertEqual(parsed['sw'], 0x6110)
        self.assertIn('More data available (16 bytes)', parsed['status'])

class TestGlobalPlatformCommands(unittest.TestCase):
    """Test GlobalPlatform command generation."""
    
    def test_select_card_manager(self):
        """Test Card Manager selection command."""
        cmd = GPCommand.select_card_manager()
        
        self.assertEqual(cmd.cla, 0x00)
        self.assertEqual(cmd.ins, 0xA4)
        self.assertEqual(cmd.p1, 0x04)
        self.assertEqual(cmd.p2, 0x00)
        self.assertEqual(cmd.data.hex().upper(), "A000000151000000")
        
    def test_get_status_command(self):
        """Test GET STATUS command."""
        cmd = GPCommand.get_status(0x40)  # Applications
        
        self.assertEqual(cmd.cla, 0x80)
        self.assertEqual(cmd.ins, 0xF2)
        self.assertEqual(cmd.p1, 0x40)
        self.assertEqual(cmd.p2, 0x00)
        self.assertEqual(cmd.le, 256)
        
    def test_delete_aid_command(self):
        """Test DELETE AID command."""
        test_aid = "A0000000031010"
        cmd = GPCommand.delete_aid(test_aid)
        
        self.assertEqual(cmd.cla, 0x80)
        self.assertEqual(cmd.ins, 0xE4)
        expected_data = b'\x4F\x07' + bytes.fromhex(test_aid)  # Tag 4F + length + AID
        self.assertEqual(cmd.data, expected_data)
        
    def test_install_for_load_command(self):
        """Test Install for Load command."""
        package_aid = "A000000003000000"
        cmd = GPCommand.install_for_load(package_aid)
        
        self.assertEqual(cmd.cla, 0x80)
        self.assertEqual(cmd.ins, 0xE6)
        self.assertEqual(cmd.p1, 0x02)  # Install for Load
        
        # Check data format: AID length + AID + SD length (0) + Hash length (0) + Params length (0)
        expected_data = bytes([8]) + bytes.fromhex(package_aid) + b'\x00\x00\x00'
        self.assertEqual(cmd.data, expected_data)

class TestAPDU4JInterface(unittest.TestCase):
    """Test APDU4J interface functionality."""
    
    def setUp(self):
        """Set up mock communicator."""
        self.mock_communicator = Mock()
        self.interface = APDU4JInterface(self.mock_communicator)
        
    def test_send_command_success(self):
        """Test successful command sending."""
        # Mock successful response
        self.mock_communicator.send_apdu.return_value = ("6F1A840E315041592E5359532E44444630318701015F2D027A68", "9000")
        
        cmd = create_select_aid_command("A0000000031010")
        result = self.interface.send_command(cmd)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['sw'], 0x9000)
        self.mock_communicator.send_apdu.assert_called_once()
        
    def test_send_command_failure(self):
        """Test failed command sending."""
        self.mock_communicator.send_apdu.return_value = (None, None)
        
        cmd = create_select_aid_command("A0000000031010")
        result = self.interface.send_command(cmd)
        
        self.assertIn('error', result)
        self.assertEqual(result['error'], 'Communication failed')
        
    def test_select_application(self):
        """Test application selection."""
        self.mock_communicator.send_apdu.return_value = ("6F1A840E315041592E5359532E44444630318701015F2D027A68", "9000")
        
        result = self.interface.select_application("A0000000031010")
        
        self.assertTrue(result['success'])
        args, kwargs = self.mock_communicator.send_apdu.call_args
        sent_command = args[0]
        self.assertIn("A0000000031010", sent_command)

class TestGREENWIREIntegration(unittest.TestCase):
    """Test GREENWIRE APDU4J integration."""
    
    def setUp(self):
        """Set up integration interface."""
        self.mock_communicator = Mock()
        self.integration = GREENWIREAPDU4JInterface(self.mock_communicator)
        
    def test_available_commands(self):
        """Test available command listing."""
        commands = self.integration.get_available_commands()
        
        self.assertIsInstance(commands, list)
        self.assertIn('SELECT_ADF', commands)
        self.assertIn('VERIFY_PIN', commands)
        self.assertIn('GP_GET_STATUS', commands)
        self.assertGreater(len(commands), 20)  # Should have plenty of commands
        
    def test_command_info(self):
        """Test command information retrieval."""
        info = self.integration.get_command_info('SELECT_ADF')
        
        self.assertIsNotNone(info)
        self.assertEqual(info['name'], 'SELECT_ADF')
        self.assertEqual(info['cla'], '0x00')
        self.assertEqual(info['ins'], '0xA4')
        self.assertIn('description', info)
        
    def test_execute_select_command(self):
        """Test executing SELECT command with parameters."""
        self.mock_communicator.send_apdu.return_value = ("6F1A", "9000")
        
        result = self.integration.execute_command('SELECT_ADF', aid="A0000000031010")
        
        self.assertTrue(result['success'])
        self.mock_communicator.send_apdu.assert_called_once()
        
    def test_execute_pin_command(self):
        """Test executing PIN verification command."""
        self.mock_communicator.send_apdu.return_value = ("", "9000")
        
        result = self.integration.execute_command('VERIFY_PIN', pin="1234")
        
        self.assertTrue(result['success'])
        args, kwargs = self.mock_communicator.send_apdu.call_args
        sent_command = args[0]
        # Should contain PIN data
        self.assertIn("31323334", sent_command)  # "1234" in hex
        
    def test_send_raw_apdu(self):
        """Test sending raw APDU."""
        self.mock_communicator.send_apdu.return_value = ("", "9000")
        
        result = self.integration.send_raw_apdu(0x00, 0xA4, 0x00, 0x0C)
        
        self.assertTrue(result['success'])
        args, kwargs = self.mock_communicator.send_apdu.call_args
        sent_command = args[0]
        self.assertEqual(sent_command, "00A4000C")

class TestCommandTemplates(unittest.TestCase):
    """Test hardcoded command templates."""
    
    def test_apdu_commands_structure(self):
        """Test APDU_COMMANDS dictionary structure."""
        self.assertIsInstance(APDU_COMMANDS, dict)
        self.assertIn('SELECT_MF', APDU_COMMANDS)
        self.assertIn('VERIFY_PIN', APDU_COMMANDS)
        self.assertIn('GET_DATA', APDU_COMMANDS)
        
        # Test command objects
        select_mf = APDU_COMMANDS['SELECT_MF']
        self.assertIsInstance(select_mf, APDU4JCommand)
        self.assertEqual(select_mf.cla, 0x00)
        self.assertEqual(select_mf.ins, 0xA4)
        
    def test_pcsc_commands_structure(self):
        """Test PC/SC commands structure."""
        self.assertIsInstance(PCSC_COMMANDS, dict)
        self.assertIn('PCSC_GET_UID', PCSC_COMMANDS)
        self.assertIn('PCSC_AUTH', PCSC_COMMANDS)
        
        # Test PC/SC command format
        get_uid = PCSC_COMMANDS['PCSC_GET_UID']
        self.assertEqual(get_uid.cla, 0xFF)  # PC/SC class
        
    def test_gp_commands_structure(self):
        """Test GlobalPlatform commands structure."""
        self.assertIsInstance(GP_COMMANDS, dict)
        self.assertIn('SELECT_CARD_MANAGER', GP_COMMANDS)
        self.assertIn('GET_STATUS_APPS', GP_COMMANDS)
        
        # Test GP command format
        select_cm = GP_COMMANDS['SELECT_CARD_MANAGER']
        self.assertEqual(select_cm.ins, 0xA4)  # SELECT instruction

def run_integration_tests():
    """Run comprehensive integration tests."""
    print("🧪 APDU4J Integration Test Suite")
    print("=" * 50)
    
    # Test 1: Command Structure
    print("\n📋 Test 1: Command Structure")
    cmd = APDU4JCommand(0x00, 0xA4, 0x04, 0x00, bytes.fromhex("A0000000031010"), 256)
    print(f"   Command: {cmd}")
    print(f"   Hex: {cmd.to_hex()}")
    print(f"   Case: {cmd.case}")
    
    # Test 2: Command Templates
    print("\n📋 Test 2: Available Commands")
    integration = GREENWIREAPDU4JInterface()
    commands = integration.get_available_commands()
    print(f"   Total commands: {len(commands)}")
    print(f"   Sample commands: {commands[:5]}")
    
    # Test 3: Command Information
    print("\n📋 Test 3: Command Information")
    for cmd_name in ['SELECT_ADF', 'VERIFY_PIN', 'GP_GET_STATUS']:
        info = integration.get_command_info(cmd_name)
        if info:
            print(f"   {cmd_name}: {info['hex']} - {info['description']}")
    
    # Test 4: Response Parsing
    print("\n📋 Test 4: Response Parsing")
    test_responses = [
        ("9000", "Success"),
        ("6A82", "File not found"), 
        ("6110", "More data available")
    ]
    
    for response_hex, expected in test_responses:
        response = bytes.fromhex(response_hex)
        parsed = parse_apdu_response(response)
        print(f"   {response_hex}: {parsed['status']} ({'✅' if expected.lower() in parsed['status'].lower() else '❌'})")
    
    # Test 5: GlobalPlatform Commands
    print("\n📋 Test 5: GlobalPlatform Commands")
    gp_commands = ['SELECT_CARD_MANAGER', 'GET_STATUS_APPS', 'GET_CARD_DATA']
    for cmd_name in gp_commands:
        cmd = GP_COMMANDS.get(cmd_name)
        if cmd:
            print(f"   {cmd_name}: {cmd.to_hex()}")
    
    print("\n✅ Integration tests completed!")
    
def main():
    """Main test runner."""
    print("🚀 APDU4J Integration Testing")
    print("=" * 40)
    
    # Run unit tests
    print("\n🔬 Running Unit Tests...")
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run integration tests
    print("\n🔧 Running Integration Tests...")
    run_integration_tests()

if __name__ == "__main__":
    main()