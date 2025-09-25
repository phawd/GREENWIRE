"""
GREENWIRE Menu System
=====================
Interactive menu system for GREENWIRE CLI.
"""

import sys
from typing import List, Callable, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum


class MenuAction(Enum):
    """Menu action types."""
    EXECUTE = "execute"
    SUBMENU = "submenu"
    EXIT = "exit"
    BACK = "back"


@dataclass
class MenuItem:
    """Represents a menu item."""
    key: str
    title: str
    description: str
    action: MenuAction
    handler: Optional[Callable] = None
    submenu: Optional['GreenwireMenu'] = None
    data: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Validate menu item after initialization."""
        if self.action == MenuAction.EXECUTE and self.handler is None:
            raise ValueError(f"Menu item '{self.key}' requires handler for EXECUTE action")
        if self.action == MenuAction.SUBMENU and self.submenu is None:
            raise ValueError(f"Menu item '{self.key}' requires submenu for SUBMENU action")


class GreenwireMenu:
    """GREENWIRE interactive menu system."""
    
    def __init__(self, title: str, description: str = ""):
        """Initialize menu."""
        self.title = title
        self.description = description
        self.items: List[MenuItem] = []
        self.parent: Optional['GreenwireMenu'] = None
        self._running = False
    
    def add_item(self, key: str, title: str, description: str, 
                 action: MenuAction, handler: Optional[Callable] = None,
                 submenu: Optional['GreenwireMenu'] = None,
                 data: Optional[Dict[str, Any]] = None) -> MenuItem:
        """Add menu item."""
        item = MenuItem(key, title, description, action, handler, submenu, data)
        if submenu:
            submenu.parent = self
        self.items.append(item)
        return item
    
    def add_separator(self, title: str = "-"):
        """Add visual separator."""
        self.items.append(MenuItem("", title, "", MenuAction.EXECUTE))
    
    def add_back_item(self, key: str = "b"):
        """Add back/exit item."""
        if self.parent:
            self.add_item(key, "← Back to Previous Menu", "Return to previous menu", MenuAction.BACK)
        else:
            self.add_item(key, "Exit", "Exit GREENWIRE", MenuAction.EXIT)
    
    def display(self):
        """Display the menu."""
        print("\n" + "="*60)
        print(f"GREENWIRE - {self.title}")
        print("="*60)
        
        if self.description:
            print(f"{self.description}\n")
        
        # Display menu items
        for item in self.items:
            if item.key == "":
                # Separator
                print(f"    {item.title}")
            else:
                print(f"  [{item.key}] {item.title}")
                if item.description:
                    print(f"      {item.description}")
        
        print("\n" + "-"*60)
    
    def run(self) -> bool:
        """
        Run the menu loop.
        
        Returns:
            True if should continue to parent menu, False to exit completely
        """
        self._running = True
        
        while self._running:
            try:
                self.display()
                choice = input("Select an option: ").strip().lower()
                
                if not choice:
                    continue
                
                # Find matching item
                item = None
                for menu_item in self.items:
                    if menu_item.key.lower() == choice:
                        item = menu_item
                        break
                
                if item is None:
                    print(f"\nInvalid choice: {choice}")
                    continue
                
                # Execute action
                if item.action == MenuAction.EXIT:
                    return False
                elif item.action == MenuAction.BACK:
                    return True
                elif item.action == MenuAction.EXECUTE:
                    if item.handler:
                        try:
                            result = item.handler(item.data or {})
                            if result is False:  # Handler requested exit
                                return False
                        except KeyboardInterrupt:
                            print("\n\nOperation cancelled.")
                        except Exception as e:
                            print(f"\nError executing {item.title}: {e}")
                elif item.action == MenuAction.SUBMENU:
                    if item.submenu:
                        should_continue = item.submenu.run()
                        if not should_continue:
                            return False
                
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                return False
            except EOFError:
                print("\n\nGoodbye!")
                return False
        
        return True
    
    def stop(self):
        """Stop the menu loop."""
        self._running = False


def create_main_menu() -> GreenwireMenu:
    """Create the main GREENWIRE menu."""
    menu = GreenwireMenu("Main Menu", "GREENWIRE Static Distribution")
    
    # Add main options
    menu.add_item("1", "NFC Operations", "NFC card interaction and emulation", MenuAction.SUBMENU,
                  submenu=create_nfc_menu())
    
    menu.add_item("2", "Cryptography Tools", "Encryption, signing, and key generation", MenuAction.SUBMENU,
                  submenu=create_crypto_menu())
    
    menu.add_item("3", "Card Analysis", "Analyze and inspect smart cards", MenuAction.SUBMENU,
                  submenu=create_analysis_menu())
    
    menu.add_separator()
    
    menu.add_item("q", "Exit", "Exit GREENWIRE", MenuAction.EXIT)
    
    return menu


def create_nfc_menu() -> GreenwireMenu:
    """Create NFC operations submenu."""
    menu = GreenwireMenu("NFC Operations", "Near Field Communication tools")
    
    def scan_for_cards(data):
        """Scan for NFC cards."""
        print("\nScanning for NFC cards...")
        # Import GREENWIRE NFC modules
        try:
            from greenwire_nfc import NFCDevice, NFCProtocol
            device = NFCDevice("greenwire:emulated")
            
            if device.open():
                targets = device.sense([NFCProtocol.ISO14443A])
                if targets:
                    print(f"Found {len(targets)} target(s):")
                    for i, target in enumerate(targets, 1):
                        print(f"  {i}. {target}")
                else:
                    print("No NFC targets found.")
                device.close()
            else:
                print("Failed to open NFC device.")
        except Exception as e:
            print(f"Error: {e}")
        
        input("\nPress Enter to continue...")
    
    def emulate_card(data):
        """Emulate an EMV card."""
        print("\nStarting EMV card emulation...")
        try:
            from greenwire_nfc.emulation import EMVEmulator
            emulator = EMVEmulator("visa")
            print(f"Emulating Visa card with UID: {emulator.get_uid().hex()}")
            print("Press Ctrl+C to stop emulation...")
            
            # Simulate emulation loop
            import time
            for i in range(10):
                time.sleep(1)
                print(".", end="", flush=True)
            print("\nEmulation complete.")
            
        except Exception as e:
            print(f"Error: {e}")
        
        input("\nPress Enter to continue...")
    
    menu.add_item("1", "Scan for Cards", "Detect NFC cards in field", MenuAction.EXECUTE, scan_for_cards)
    menu.add_item("2", "Emulate Card", "Emulate an EMV card", MenuAction.EXECUTE, emulate_card)
    menu.add_back_item()
    
    return menu


def create_crypto_menu() -> GreenwireMenu:
    """Create cryptography tools submenu."""
    menu = GreenwireMenu("Cryptography Tools", "Encryption and key management")
    
    def generate_keys(data):
        """Generate cryptographic keys."""
        print("\nGenerating RSA key pair...")
        try:
            from greenwire_crypto import generate_rsa_keypair
            key = generate_rsa_keypair(2048)
            print(f"Generated {key.key_size()}-bit RSA key pair")
            print(f"Public key modulus: {hex(key.n)[:50]}...")
            print("Key pair generated successfully!")
        except Exception as e:
            print(f"Error: {e}")
        
        input("\nPress Enter to continue...")
    
    def hash_data(data):
        """Hash data with various algorithms."""
        text = input("\nEnter text to hash: ")
        if text:
            try:
                from greenwire_crypto import hash_sha256, hash_sha1, hash_md5
                from greenwire_utils import hex_encode
                
                print(f"\nHash results for: '{text}'")
                print(f"MD5:    {hex_encode(hash_md5(text))}")
                print(f"SHA-1:  {hex_encode(hash_sha1(text))}")
                print(f"SHA-256: {hex_encode(hash_sha256(text))}")
            except Exception as e:
                print(f"Error: {e}")
        
        input("\nPress Enter to continue...")
    
    menu.add_item("1", "Generate Keys", "Generate RSA key pairs", MenuAction.EXECUTE, generate_keys)
    menu.add_item("2", "Hash Data", "Calculate hashes of data", MenuAction.EXECUTE, hash_data)
    menu.add_back_item()
    
    return menu


def create_analysis_menu() -> GreenwireMenu:
    """Create card analysis submenu."""
    menu = GreenwireMenu("Card Analysis", "Smart card inspection tools")
    
    def parse_tlv(data):
        """Parse TLV data."""
        hex_input = input("\nEnter TLV data (hex): ")
        if hex_input:
            try:
                from greenwire_utils import hex_decode, tlv_parse, hex_encode
                
                tlv_data = hex_decode(hex_input)
                tlv_list = tlv_parse(tlv_data)
                
                print(f"\nParsed {len(tlv_list)} TLV entries:")
                for tag, value in tlv_list:
                    print(f"  Tag {tag:04X} ({tag}): {hex_encode(value)}")
                    if len(value) <= 32:  # Show ASCII for short values
                        try:
                            ascii_val = value.decode('ascii')
                            if all(32 <= ord(c) < 127 for c in ascii_val):
                                print(f"    ASCII: '{ascii_val}'")
                        except:
                            pass
                
            except Exception as e:
                print(f"Error: {e}")
        
        input("\nPress Enter to continue...")
    
    def dump_hex(data):
        """Create hex dump of data."""
        hex_input = input("\nEnter data (hex): ")
        if hex_input:
            try:
                from greenwire_utils import hex_decode, print_hex_dump
                
                raw_data = hex_decode(hex_input)
                print(f"\nHex dump ({len(raw_data)} bytes):")
                print(print_hex_dump(raw_data))
                
            except Exception as e:
                print(f"Error: {e}")
        
        input("\nPress Enter to continue...")
    
    menu.add_item("1", "Parse TLV Data", "Parse Tag-Length-Value structures", MenuAction.EXECUTE, parse_tlv)
    menu.add_item("2", "Hex Dump", "Create hex dump of binary data", MenuAction.EXECUTE, dump_hex)
    menu.add_back_item()
    
    return menu