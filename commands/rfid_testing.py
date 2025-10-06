"""
GREENWIRE Modern CLI - RFID Testing Command
"""
import argparse
from modules.rfid_vulnerability_tester import RFIDVulnerabilityTester

class RFIDTestCommand:
    """Executes RFID vulnerability tests."""

    def get_name(self) -> str:
        return "rfid-test"

    def get_description(self) -> str:
        return "Execute RFID vulnerability testing (relay, timing, eavesdropping, collision)"

    def execute(self, args: list) -> dict:
        """Execute the RFID test command."""
        parser = argparse.ArgumentParser(
            prog='greenwire rfid-test',
            description=self.get_description()
        )
        parser.add_argument('test_type', choices=['all'], help="Type of RFID test to run.")

        try:
            parsed_args = parser.parse_args(args)
            tester = RFIDVulnerabilityTester()

            if parsed_args.test_type == 'all':
                results = tester.run_all_vulnerability_tests()
                return {
                    'success': all(t.get('status') == 'completed' for t in results.get('tests', {}).values()),
                    'message': 'RFID vulnerability test session finished.',
                    'data': results
                }
        except Exception as e:
            return {'success': False, 'message': str(e)}

def get_command():
    """Returns an instance of the command."""
    return RFIDTestCommand()