#!/usr/bin/env python3
"""APDU4J CLI Integration for GREENWIRE.

Extends GREENWIRE's command-line interface with APDU4J functionality,
providing access to hardcoded APDU command libraries and GlobalPlatform operations.
"""

import sys
import os
import argparse
import logging
from typing import Dict, List, Optional, Any

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from apdu4j_data.apdu4j_integration import GREENWIREAPDU4JInterface, create_apdu4j_interface
from apdu_communicator import APDUCommunicator

logger = logging.getLogger(__name__)

class APDU4JCLIHandler:
    """CLI handler for APDU4J operations in GREENWIRE."""
    
    def __init__(self):
        """Initialize CLI handler."""
        self.communicator = None
        self.apdu4j_interface = None
        
    def setup_connection(self, reader_name: str = None, verbose: bool = False) -> bool:
        """Setup APDU communication connection.
        
        Args:
            reader_name: Specific reader to use (optional)
            verbose: Enable verbose APDU logging
            
        Returns:
            True if connection successful
        """
        try:
            self.communicator = APDUCommunicator(verbose=verbose)
            
            if self.communicator.connect_reader(reader_name):
                self.apdu4j_interface = create_apdu4j_interface(self.communicator)
                if verbose:
                    print(f"✅ Connected to reader: {self.communicator.reader_name}")
                    atr = self.communicator.get_atr()
                    if atr:
                        print(f"📋 Card ATR: {atr}")
                return True
            else:
                print("❌ Failed to connect to card reader")
                return False
                
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False
            
    def list_readers(self) -> None:
        """List available card readers."""
        print("📖 Available Card Readers:")
        print("=" * 30)
        
        try:
            communicator = APDUCommunicator()
            readers = communicator.list_readers()
            
            if readers:
                for i, reader in enumerate(readers, 1):
                    print(f"  {i}. {reader}")
            else:
                print("  ❌ No card readers found")
                print("\n💡 Ensure:")
                print("  • PC/SC compatible reader is connected")
                print("  • Reader drivers are installed")
                print("  • pyscard is installed: pip install pyscard")
                
        except Exception as e:
            print(f"  ❌ Error listing readers: {e}")
            
    def list_commands(self) -> None:
        """List all available APDU4J commands."""
        print("📋 Available APDU4J Commands:")
        print("=" * 35)
        
        interface = GREENWIREAPDU4JInterface()
        commands = interface.get_available_commands()
        
        # Group commands by category
        iso_commands = [cmd for cmd in commands if not cmd.startswith(('PCSC_', 'GP_'))]
        pcsc_commands = [cmd for cmd in commands if cmd.startswith('PCSC_')]
        gp_commands = [cmd for cmd in commands if cmd.startswith('GP_')]
        
        print(f"\n🏛️  ISO 7816-4 Commands ({len(iso_commands)}):")
        for cmd in sorted(iso_commands):
            info = interface.get_command_info(cmd)
            if info:
                print(f"  {cmd:20} - {info['description']}")
                
        print(f"\n💳 PC/SC Commands ({len(pcsc_commands)}):")
        for cmd in sorted(pcsc_commands):
            info = interface.get_command_info(cmd)
            if info:
                print(f"  {cmd:20} - {info['description']}")
                
        print(f"\n🌐 GlobalPlatform Commands ({len(gp_commands)}):")
        for cmd in sorted(gp_commands):
            info = interface.get_command_info(cmd)
            if info:
                print(f"  {cmd:20} - {info['description']}")
                
        print(f"\n📊 Total Commands: {len(commands)}")
        
    def show_command_info(self, command_name: str) -> None:
        """Show detailed information about a command.
        
        Args:
            command_name: Name of command to inspect
        """
        interface = GREENWIREAPDU4JInterface()
        info = interface.get_command_info(command_name)
        
        if info:
            print(f"🔍 Command Information: {command_name}")
            print("=" * 40)
            print(f"  CLA (Class):       {info['cla']}")
            print(f"  INS (Instruction): {info['ins']}")
            print(f"  P1 (Parameter 1):  {info['p1']}")
            print(f"  P2 (Parameter 2):  {info['p2']}")
            print(f"  APDU Case:         {info['case']}")
            print(f"  Hex Encoding:      {info['hex']}")
            print(f"  Description:       {info['description']}")
        else:
            print(f"❌ Command not found: {command_name}")
            print("💡 Use --list-commands to see available commands")
            
    def execute_command(self, command_name: str, **kwargs) -> None:
        """Execute an APDU4J command.
        
        Args:
            command_name: Name of command to execute
            **kwargs: Command parameters
        """
        if not self.apdu4j_interface:
            print("❌ No connection established. Use setup first.")
            return
            
        print(f"🚀 Executing: {command_name}")
        
        # Show command info
        info = self.apdu4j_interface.get_command_info(command_name)
        if info:
            print(f"   APDU: {info['hex']}")
            
        # Execute command
        result = self.apdu4j_interface.execute_command(command_name, **kwargs)
        
        # Display results
        if result.get('success'):
            print("✅ Command successful")
            if result.get('data'):
                data_hex = result['data']
                if isinstance(data_hex, bytes):
                    data_hex = data_hex.hex()
                print(f"   Response Data: {data_hex}")
            print(f"   Status: {result.get('status', 'Unknown')}")
        else:
            print("❌ Command failed")
            if 'error' in result:
                print(f"   Error: {result['error']}")
            else:
                print(f"   Status: {result.get('status', 'Unknown')}")
                
    def send_raw_apdu(self, apdu_hex: str) -> None:
        """Send raw APDU command.
        
        Args:
            apdu_hex: APDU as hex string
        """
        if not self.apdu4j_interface:
            print("❌ No connection established. Use setup first.")
            return
            
        print(f"🚀 Sending Raw APDU: {apdu_hex}")
        
        result = self.apdu4j_interface.send_apdu_hex(apdu_hex)
        
        if result.get('success'):
            print("✅ APDU successful")
            if result.get('data'):
                data_hex = result['data']
                if isinstance(data_hex, bytes):
                    data_hex = data_hex.hex()
                print(f"   Response Data: {data_hex}")
            print(f"   Status Word: {result['sw1']:02X}{result['sw2']:02X}")
            print(f"   Status: {result.get('status')}")
        else:
            print("❌ APDU failed")
            print(f"   Error: {result.get('error', 'Unknown error')}")
            
    def gp_list_applications(self) -> None:
        """List GlobalPlatform applications."""
        if not self.apdu4j_interface:
            print("❌ No connection established. Use setup first.")
            return
            
        print("🌐 GlobalPlatform Applications:")
        print("=" * 35)
        
        result = self.apdu4j_interface.list_gp_applications()
        
        if result.get('success'):
            apps = result.get('applications', [])
            if apps:
                print(f"   Found {len(apps)} application(s):")
                for i, app in enumerate(apps, 1):
                    print(f"   {i}. AID: {app['aid']}")
                    print(f"      State: {app['state']} ({app['state_code']})")
            else:
                print("   No applications found")
        else:
            print(f"❌ Failed to list applications: {result.get('error')}")
            
    def gp_get_card_info(self) -> None:
        """Get GlobalPlatform card information."""
        if not self.apdu4j_interface:
            print("❌ No connection established. Use setup first.")
            return
            
        print("🌐 GlobalPlatform Card Information:")
        print("=" * 40)
        
        result = self.apdu4j_interface.get_card_info()
        
        if result.get('success'):
            print("✅ Card Manager accessible")
            if result.get('select_response'):
                print(f"   Selection Response: {result['select_response']}")
            if result.get('card_data'):
                print(f"   Card Data: {result['card_data']}")
        else:
            print(f"❌ Failed to get card info: {result.get('error')}")
            
    def disconnect(self) -> None:
        """Disconnect from card reader."""
        if self.communicator:
            self.communicator.disconnect()
            print("🔌 Disconnected from reader")
            
def create_cli_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser for APDU4J operations."""
    parser = argparse.ArgumentParser(
        description="APDU4J Integration for GREENWIRE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  List available readers:
    python apdu4j_cli.py --list-readers
    
  List all commands:
    python apdu4j_cli.py --list-commands
    
  Show command info:
    python apdu4j_cli.py --command-info SELECT_ADF
    
  Execute SELECT command:
    python apdu4j_cli.py --execute SELECT_ADF --aid A0000000031010 --verbose
    
  Send raw APDU:
    python apdu4j_cli.py --raw-apdu 00A404000A0000000031010000 --verbose
    
  GlobalPlatform operations:
    python apdu4j_cli.py --gp-list-apps --verbose
    python apdu4j_cli.py --gp-card-info --verbose
        """
    )
    
    # Connection options
    parser.add_argument('--reader', type=str, help='Specific card reader to use')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose APDU logging')
    
    # Information commands
    parser.add_argument('--list-readers', action='store_true', help='List available card readers')
    parser.add_argument('--list-commands', action='store_true', help='List all APDU4J commands')
    parser.add_argument('--command-info', type=str, metavar='COMMAND', help='Show command information')
    
    # APDU execution
    parser.add_argument('--execute', type=str, metavar='COMMAND', help='Execute APDU4J command')
    parser.add_argument('--aid', type=str, help='Application ID for SELECT commands')
    parser.add_argument('--pin', type=str, help='PIN for verification commands')
    parser.add_argument('--pin-id', type=int, default=0x80, help='PIN identifier (default: 0x80)')
    parser.add_argument('--tag', type=str, help='Data object tag for GET_DATA (hex)')
    parser.add_argument('--le', type=int, default=256, help='Expected response length (default: 256)')
    
    # Raw APDU
    parser.add_argument('--raw-apdu', type=str, metavar='HEX', help='Send raw APDU as hex string')
    
    # GlobalPlatform operations
    parser.add_argument('--gp-list-apps', action='store_true', help='List GlobalPlatform applications')
    parser.add_argument('--gp-card-info', action='store_true', help='Get GlobalPlatform card information')
    
    return parser

def main():
    """Main CLI entry point."""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)
    
    handler = APDU4JCLIHandler()
    
    try:
        # Information commands (no connection needed)
        if args.list_readers:
            handler.list_readers()
            return
            
        if args.list_commands:
            handler.list_commands()
            return
            
        if args.command_info:
            handler.show_command_info(args.command_info)
            return
        
        # Commands requiring connection
        needs_connection = any([
            args.execute,
            args.raw_apdu, 
            args.gp_list_apps,
            args.gp_card_info
        ])
        
        if needs_connection:
            if not handler.setup_connection(args.reader, args.verbose):
                return
                
        # Execute commands
        if args.execute:
            kwargs = {}
            if args.aid:
                kwargs['aid'] = args.aid
            if args.pin:
                kwargs['pin'] = args.pin
                kwargs['pin_id'] = args.pin_id
            if args.tag:
                kwargs['tag'] = int(args.tag, 16)  # Convert hex to int
                kwargs['le'] = args.le
                
            handler.execute_command(args.execute, **kwargs)
            
        elif args.raw_apdu:
            handler.send_raw_apdu(args.raw_apdu)
            
        elif args.gp_list_apps:
            handler.gp_list_applications()
            
        elif args.gp_card_info:
            handler.gp_get_card_info()
            
        else:
            # No command specified, show help
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        handler.disconnect()

if __name__ == "__main__":
    main()