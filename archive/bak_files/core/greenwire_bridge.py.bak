"""
GREENWIRE Bridge Module
Connects modular architecture to original greenwire.py implementations.
"""

import sys
import os
from pathlib import Path
from typing import Any, Dict, Optional

# Add greenwire root to path for imports
greenwire_root = Path(__file__).parent.parent
sys.path.insert(0, str(greenwire_root))

from core.logging_system import get_logger, handle_errors

# Import original greenwire functions
try:
    # Import the original greenwire module
    import greenwire as original_greenwire
    
    # Import key functions from original implementation
    run_testing_original = getattr(original_greenwire, 'run_testing', None)
    run_easycard_original = getattr(original_greenwire, 'run_easycard', None)
    run_nfc_original = getattr(original_greenwire, 'run_nfc', None)
    run_emulation_original = getattr(original_greenwire, 'run_emulation', None)
    run_gp_original = getattr(original_greenwire, 'run_gp', None)
    run_probe_hardware_original = getattr(original_greenwire, 'run_probe_hardware', None)
    run_apdu_original = getattr(original_greenwire, 'run_apdu', None)
    run_fido_original = getattr(original_greenwire, 'run_fido', None)
    run_install_cap_original = getattr(original_greenwire, 'run_install_cap', None)
    run_crypto_original = getattr(original_greenwire, 'run_crypto', None)
    run_interactive_menu_original = getattr(original_greenwire, 'run_interactive_menu', None)
    
    # Import classes from original implementation
    NativeAPDUFuzzer = getattr(original_greenwire, 'NativeAPDUFuzzer', None)
    AndroidNFCVerifier = getattr(original_greenwire, 'AndroidNFCVerifier', None)
    CAPFileHandler = getattr(original_greenwire, 'CAPFileHandler', None)
    NFCDaemon = getattr(original_greenwire, 'NFCDaemon', None)
    
    BRIDGE_AVAILABLE = True
    
except ImportError as e:
    # If original greenwire can't be imported, provide stubs
    run_testing_original = None
    run_easycard_original = None
    run_nfc_original = None
    run_emulation_original = None
    run_gp_original = None
    run_probe_hardware_original = None
    run_apdu_original = None
    run_fido_original = None
    run_install_cap_original = None
    run_crypto_original = None
    run_interactive_menu_original = None
    
    NativeAPDUFuzzer = None
    AndroidNFCVerifier = None
    CAPFileHandler = None
    NFCDaemon = None
    
    BRIDGE_AVAILABLE = False

class GreenwireBridge:
    """Bridge class that provides access to original greenwire.py functionality."""
    
    def __init__(self):
        self.logger = get_logger()
        self.available = BRIDGE_AVAILABLE
        
        if not self.available:
            self.logger.warning("Original greenwire.py functions not available - using fallback implementations")
    
    @handle_errors("Testing command execution", return_on_error=False)
    def execute_testing_command(self, args: Any) -> bool:
        """Execute testing command using original implementation via subprocess."""
        try:
            import subprocess
            import sys
            
            # Build command line for original greenwire.py
            cmd = [sys.executable, "greenwire.py", "testing"]
            
            # Add specific testing subcommand
            if hasattr(args, 'testing_command'):
                cmd.append(args.testing_command)
            elif hasattr(args, 'command'):
                cmd.append(args.command)
            
            # Add common arguments
            if hasattr(args, 'hardware') and args.hardware:
                cmd.append('--hardware')
            if hasattr(args, 'verbose') and args.verbose:
                cmd.append('--verbose')
            if hasattr(args, 'iterations') and args.iterations:
                cmd.extend(['--iterations', str(args.iterations)])
                
            self.logger.info(f"Executing original command: {' '.join(cmd)}")
            
            # Execute the original greenwire.py
            result = subprocess.run(cmd, capture_output=False, text=True)
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Testing command failed: {e}")
            return False
    
    @handle_errors("EasyCard command execution", return_on_error=False)
    def execute_easycard_command(self, args: Any) -> bool:
        """Execute easycard command using original implementation."""
        if run_easycard_original:
            try:
                run_easycard_original(args)
                return True
            except Exception as e:
                self.logger.error(f"EasyCard command failed: {e}")
                return False
        else:
            self.logger.error("EasyCard command not available")
            return False
    
    @handle_errors("NFC command execution", return_on_error=False)
    def execute_nfc_command(self, args: Any) -> bool:
        """Execute NFC command using original implementation."""
        if run_nfc_original:
            try:
                run_nfc_original(args)
                return True
            except Exception as e:
                self.logger.error(f"NFC command failed: {e}")
                return False
        else:
            self.logger.error("NFC command not available")
            return False
    
    @handle_errors("Emulation command execution", return_on_error=False)
    def execute_emulation_command(self, args: Any) -> bool:
        """Execute emulation command using original implementation."""
        if run_emulation_original:
            try:
                run_emulation_original(args)
                return True
            except Exception as e:
                self.logger.error(f"Emulation command failed: {e}")
                return False
        else:
            self.logger.error("Emulation command not available")
            return False
    
    @handle_errors("GlobalPlatform command execution", return_on_error=False)
    def execute_gp_command(self, args: Any) -> bool:
        """Execute GlobalPlatform command using original implementation."""
        if run_gp_original:
            try:
                run_gp_original(args)
                return True
            except Exception as e:
                self.logger.error(f"GlobalPlatform command failed: {e}")
                return False
        else:
            self.logger.error("GlobalPlatform command not available")
            return False
    
    @handle_errors("Hardware probe execution", return_on_error=False)
    def execute_probe_hardware_command(self, args: Any) -> bool:
        """Execute hardware probing using original implementation via subprocess."""
        try:
            import subprocess
            import sys
            
            # Build command line for original greenwire.py
            cmd = [sys.executable, "greenwire.py", "probe-hardware"]
            
            # Add auto-init argument if requested
            if hasattr(args, 'auto_init') and args.auto_init:
                cmd.append('--auto-init')
            
            self.logger.info(f"Executing original command: {' '.join(cmd)}")
            
            # Execute the original greenwire.py
            result = subprocess.run(cmd, capture_output=False, text=True)
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Hardware probe failed: {e}")
            return False
    
    @handle_errors("APDU command execution", return_on_error=False)
    def execute_apdu_command(self, args: Any) -> bool:
        """Execute APDU command using original implementation."""
        if run_apdu_original:
            try:
                run_apdu_original(args)
                return True
            except Exception as e:
                self.logger.error(f"APDU command failed: {e}")
                return False
        else:
            self.logger.error("APDU command not available")
            return False
    
    @handle_errors("FIDO command execution", return_on_error=False)
    def execute_fido_command(self, args: Any) -> bool:
        """Execute FIDO command using original implementation."""
        if run_fido_original:
            try:
                run_fido_original(args)
                return True
            except Exception as e:
                self.logger.error(f"FIDO command failed: {e}")
                return False
        else:
            self.logger.error("FIDO command not available")
            return False
    
    @handle_errors("Install CAP command execution", return_on_error=False)
    def execute_install_cap_command(self, args: Any) -> bool:
        """Execute install CAP command using original implementation."""
        if run_install_cap_original:
            try:
                run_install_cap_original(args)
                return True
            except Exception as e:
                self.logger.error(f"Install CAP command failed: {e}")
                return False
        else:
            self.logger.error("Install CAP command not available")
            return False
    
    @handle_errors("Crypto command execution", return_on_error=False)
    def execute_crypto_command(self, args: Any) -> bool:  
        """Execute crypto command using original implementation."""
        if run_crypto_original:
            try:
                run_crypto_original(args)
                return True
            except Exception as e:
                self.logger.error(f"Crypto command failed: {e}")
                return False
        else:
            self.logger.error("Crypto command not available")
            return False
    
    @handle_errors("Interactive menu execution", return_on_error=False)
    def execute_interactive_menu(self) -> bool:
        """Execute interactive menu using original implementation."""
        if run_interactive_menu_original:
            try:
                run_interactive_menu_original()
                return True
            except Exception as e:
                self.logger.error(f"Interactive menu failed: {e}")
                return False
        else:
            self.logger.error("Interactive menu not available")
            return False
    
    def get_native_apdu_fuzzer(self, verbose: bool = True):
        """Get NativeAPDUFuzzer instance from original implementation."""
        if NativeAPDUFuzzer:
            return NativeAPDUFuzzer(verbose=verbose)
        else:
            self.logger.error("NativeAPDUFuzzer not available")
            return None
    
    def get_android_nfc_verifier(self):
        """Get AndroidNFCVerifier instance from original implementation."""
        if AndroidNFCVerifier:
            return AndroidNFCVerifier()
        else:
            self.logger.error("AndroidNFCVerifier not available")
            return None
    
    def get_cap_file_handler(self):
        """Get CAPFileHandler instance from original implementation."""
        if CAPFileHandler:
            return CAPFileHandler()
        else:
            self.logger.error("CAPFileHandler not available")
            return None
    
    def get_nfc_daemon(self):
        """Get NFCDaemon instance from original implementation."""
        if NFCDaemon:
            return NFCDaemon()
        else:
            self.logger.error("NFCDaemon not available")
            return None

# Global bridge instance
_bridge = None

def get_bridge() -> GreenwireBridge:
    """Get the global bridge instance."""
    global _bridge
    if _bridge is None:
        _bridge = GreenwireBridge()
    return _bridge