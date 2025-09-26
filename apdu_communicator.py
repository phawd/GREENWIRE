#!/usr/bin/env python3
"""APDU Communication Module for GREENWIRE.

Provides PC/SC and NFC communication capabilities for APDU commands.
"""

import sys, time  # noqa: F401
from typing import Any, Dict, List, Optional, Tuple

try:
    import smartcard
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    from smartcard.CardConnection import CardConnection
    from smartcard.Exceptions import CardConnectionException, NoCardException
    HAS_PYSCARD = True
except ImportError:
    HAS_PYSCARD = False

try:
    import nfc
    HAS_NFC = True
except ImportError:
    HAS_NFC = False


class APDUCommunicator:
    """High-level APDU communication interface supporting PC/SC and NFC."""
    
    def __init__(self, verbose: bool = False):
        """Initialize APDU communicator.
        
        Args:
            verbose: Enable verbose logging of APDU exchanges
        """
        self.verbose = verbose
        self.connection = None
        self.reader_name = None
        
    def list_readers(self) -> List[str]:
        """List available PC/SC readers.
        
        Returns:
            List of reader names
        """
        if not HAS_PYSCARD:
            return []
            
        try:
            reader_list = readers()
            return [str(reader) for reader in reader_list]
        except Exception as e:
            if self.verbose:
                print(f"Error listing readers: {e}")
            return []
    
    def connect_reader(self, reader_name: Optional[str] = None) -> bool:
        """Connect to a PC/SC reader.
        
        Args:
            reader_name: Name of reader to connect to (first available if None)
            
        Returns:
            True if connection successful
        """
        if not HAS_PYSCARD:
            if self.verbose:
                print("PC/SC not available - pyscard not installed")
            return False
            
        try:
            reader_list = readers()
            if not reader_list:
                if self.verbose:
                    print("No PC/SC readers found")
                return False
                
            if reader_name is None:
                reader = reader_list[0]
                self.reader_name = str(reader)
            else:
                matching_readers = [r for r in reader_list if reader_name in str(r)]
                if not matching_readers:
                    if self.verbose:
                        print(f"Reader '{reader_name}' not found")
                    return False
                reader = matching_readers[0]
                self.reader_name = str(reader)
                
            self.connection = reader.createConnection()
            self.connection.connect()
            
            if self.verbose:
                print(f"Connected to reader: {self.reader_name}")
            return True
            
        except (CardConnectionException, NoCardException) as e:
            if self.verbose:
                print(f"Card connection error: {e}")
            return False
        except Exception as e:
            if self.verbose:
                print(f"Reader connection error: {e}")
            return False
    
    def send_apdu(self, apdu_hex: str) -> Tuple[Optional[str], Optional[str]]:
        """Send APDU command and receive response.
        
        Args:
            apdu_hex: APDU command as hex string
            
        Returns:
            Tuple of (response_data, status_word) or (None, None) on error
        """
        if not self.connection:
            if self.verbose:
                print("No active connection")
            return None, None
            
        try:
            # Convert hex string to bytes
            apdu_bytes = toBytes(apdu_hex.replace(" ", ""))
            
            if self.verbose:
                print(f">> {apdu_hex}")
                
            # Send APDU
            response, sw1, sw2 = self.connection.transmit(apdu_bytes)
            
            # Format response
            response_hex = toHexString(response) if response else ""
            sw_hex = f"{sw1:02X}{sw2:02X}"
            
            if self.verbose:
                print(f"<< {response_hex} {sw_hex}")
                
            return response_hex, sw_hex
            
        except Exception as e:
            if self.verbose:
                print(f"APDU transmission error: {e}")
            return None, None
    
    def send_apdu_script(self, script_path: str) -> List[Dict[str, Any]]:
        """Execute APDU script from file.
        
        Args:
            script_path: Path to APDU script file
            
        Returns:
            List of command results
        """
        results = []
        
        try:
            with open(script_path, 'r') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                if self.verbose:
                    print(f"Script line {line_num}: {line}")
                    
                response, sw = self.send_apdu(line)
                results.append({
                    'line': line_num,
                    'command': line,
                    'response': response,
                    'status': sw,
                    'success': sw == '9000' if sw else False
                })
                
        except FileNotFoundError:
            if self.verbose:
                print(f"Script file not found: {script_path}")
        except Exception as e:
            if self.verbose:
                print(f"Script execution error: {e}")
                
        return results
    
    def disconnect(self):
        """Disconnect from reader."""
        if self.connection:
            try:
                self.connection.disconnect()
                if self.verbose:
                    print(f"Disconnected from {self.reader_name}")
            except Exception as e:
                if self.verbose:
                    print(f"Disconnect error: {e}")
            finally:
                self.connection = None
                self.reader_name = None
    
    def get_atr(self) -> Optional[str]:
        """Get Answer to Reset (ATR) from connected card.
        
        Returns:
            ATR as hex string or None if not available
        """
        if not self.connection:
            return None
            
        try:
            atr = self.connection.getATR()
            return toHexString(atr)
        except Exception as e:
            if self.verbose:
                print(f"ATR error: {e}")
            return None
    
    def __enter__(self):
        """Context manager entry."""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure disconnection."""
        self.disconnect()

    def connect_to_card(self, reader_name: Optional[str] = None) -> bool:
        """Compatibility alias used by legacy callers.

        Previously some higher-level code called connect_to_card(); adapt
        that call to the current connect_reader implementation to maintain
        API compatibility.
        """
        return self.connect_reader(reader_name)


def main():
    """Command line interface for APDU communicator."""
    import argparse
    
    parser = argparse.ArgumentParser(description="APDU Communication Tool")
    parser.add_argument("--list-readers", action="store_true", help="List PC/SC readers")
    parser.add_argument("--reader", help="Reader to connect to")
    parser.add_argument("--command", help="APDU command in hex")
    parser.add_argument("--script", help="APDU script file")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    comm = APDUCommunicator(verbose=args.verbose)
    
    if args.list_readers:
        readers = comm.list_readers()
        if readers:
            print("Available PC/SC readers:")
            for i, reader in enumerate(readers, 1):
                print(f"  {i}. {reader}")
        else:
            print("No PC/SC readers found")
        return
    
    if args.command or args.script:
        if not comm.connect_reader(args.reader):
            print("Failed to connect to reader")
            return
            
        try:
            if args.command:
                response, sw = comm.send_apdu(args.command)
                if response is not None:
                    print(f"Response: {response}")
                    print(f"Status: {sw}")
                else:
                    print("Command failed")
                    
            if args.script:
                results = comm.send_apdu_script(args.script)
                print(f"Script executed {len(results)} commands")
                
        finally:
            comm.disconnect()


if __name__ == "__main__":
    main()