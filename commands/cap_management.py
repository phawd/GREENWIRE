"""
GREENWIRE Modern CLI - CAP Management Command
"""
import argparse
from modules.caplet_production_system import CapletProductionSystem

class CAPManagementCommand:
    """Handles JavaCard CAP file operations."""

    def get_name(self) -> str:
        return "cap"

    def get_description(self) -> str:
        return "JavaCard CAP file operations (produce, deploy, list)"

    def execute(self, args: list) -> dict:
        """Execute the CAP management command."""
        parser = argparse.ArgumentParser(
            prog='greenwire cap',
            description=self.get_description()
        )
        subparsers = parser.add_subparsers(dest='action', required=True)

        # produce-all subcommand
        produce_parser = subparsers.add_parser('produce-all', help='Produce all caplet variants.')

        # deploy subcommand
        deploy_parser = subparsers.add_parser('deploy', help='Deploy a caplet to a smartcard.')
        deploy_parser.add_argument('--cap-file', required=True, help='Path to the .cap file to deploy.')
        deploy_parser.add_argument('--reader-index', type=int, default=0, help='Index of the card reader to use.')

        try:
            parsed_args = parser.parse_args(args)
            producer = CapletProductionSystem()

            if parsed_args.action == 'produce-all':
                results = producer.produce_all_caplets()
                return {
                    'success': results.get('failed_builds', 1) == 0,
                    'message': 'Caplet production run finished.',
                    'data': results
                }
            elif parsed_args.action == 'deploy':
                results = producer.deploy_caplet_to_card(parsed_args.cap_file, parsed_args.reader_index)
                return {
                    'success': results.get('success', False),
                    'message': 'Caplet deployment finished.',
                    'data': results
                }

        except SystemExit:
            # argparse throws SystemExit on --help or error, which is fine.
            return {'success': True, 'message': 'Displayed help for cap command.'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

def get_command():
    """Returns an instance of the command."""
    return CAPManagementCommand()