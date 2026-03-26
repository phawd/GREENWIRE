"""
GREENWIRE Command Router
Routes parsed CLI arguments to appropriate handlers.
"""

import sys
from typing import Any, Dict, Optional
from core.logging_system import get_logger, handle_errors
from core.config import get_config
from core.greenwire_bridge import get_bridge

class CommandRouter:
    """Routes CLI commands to appropriate handlers."""
    
    def __init__(self):
        self.logger = get_logger()
        self.config = get_config()
        self.bridge = get_bridge()
        self._handlers = {}
        
    def register_handler(self, command: str, handler_func):
        """Register a command handler function."""
        self._handlers[command] = handler_func
        self.logger.debug(f"Registered handler for command: {command}")
    
    @handle_errors("Command routing", return_on_error=False)
    def route_command(self, args: Any) -> bool:
        """
        Route parsed arguments to appropriate handler.
        
        Args:
            args: Parsed arguments from argparse
            
        Returns:
            True if command executed successfully
        """
        if not hasattr(args, 'command') or not args.command:
            self.logger.error("No command specified")
            return False
        
        command = args.command
        
        # Handle special cases first
        if args.menu:
            return self._handle_menu_mode(args)
        
        # Route to specific command handlers
        if command == "testing":
            return self._handle_testing_command(args)
        elif command == "easycard":
            return self._handle_easycard_command(args)
        elif command == "emulator":
            return self._handle_emulator_command(args)
        elif command == "nfc":
            return self._handle_nfc_command(args)
        elif command == "apdu":
            return self._handle_apdu_command(args)
        elif command == "fido":
            return self._handle_fido_command(args)
        elif command == "gp":
            return self._handle_gp_command(args)
        elif command == "install-cap":
            return self._handle_install_cap_command(args)
        elif command == "log-analysis":
            return self._handle_log_analysis_command(args)
        elif command == "crypto":
            return self._handle_crypto_command(args)
        elif command == "probe-hardware":
            return self._handle_probe_hardware_command(args)
        else:
            # Check for registered custom handlers
            if command in self._handlers:
                return self._handlers[command](args)
            else:
                self.logger.error(f"Unknown command: {command}")
                return False
    
    def _handle_menu_mode(self, args: Any) -> bool:
        """Handle interactive menu mode."""
        self.logger.info("Launching interactive menu interface")
        
        # Use bridge to access original menu implementation
        return self.bridge.execute_interactive_menu()
    
    def _handle_testing_command(self, args: Any) -> bool:
        """Handle testing subcommands."""
        self.logger.info("Executing testing command via bridge")
        return self.bridge.execute_testing_command(args)
    
    def _handle_fuzz_testing(self, args: Any) -> bool:
        """Handle APDU fuzzing operations."""
        self.logger.info(f"Starting APDU fuzzing - Target: {args.target}, Iterations: {args.iterations}")
        
        # Import and use APDU fuzzer from core
        try:
            from core.apdu_fuzzer import run_native_apdu_fuzz
            
            session, report = run_native_apdu_fuzz(
                target_card=args.target,
                iterations=args.iterations,
                mutation_level=args.mutation_level,
                hardware_mode=args.hardware,
                reader_name=args.reader,
                output_file=args.output,
                seed=args.seed
            )
            
            self.logger.info("APDU fuzzing completed successfully")
            return True
            
        except ImportError as e:
            self.logger.error(f"APDU fuzzer not available: {e}")
            return False
    
    def _handle_dump_testing(self, args: Any) -> bool:
        """Handle card data dumping."""
        self.logger.info(f"Starting card dump - Format: {args.format}")
        
        # This would integrate with card dumping functionality
        self.logger.warning("Card dumping functionality not yet implemented in modular structure")
        return False
    
    def _handle_attack_testing(self, args: Any) -> bool:
        """Handle specific attack execution."""
        self.logger.info(f"Executing attack: {args.attack_type}")
        
        # This would integrate with attack modules
        self.logger.warning("Attack testing functionality not yet implemented in modular structure")
        return False
    
    def _handle_auto_detect(self, args: Any) -> bool:
        """Handle auto-detection of card capabilities."""
        self.logger.info("Starting auto-detection")
        
        # This would integrate with detection functionality
        self.logger.warning("Auto-detection functionality not yet implemented in modular structure")
        return False
    
    def _handle_ai_vuln_testing(self, args: Any) -> bool:
        """Handle AI-powered vulnerability testing."""
        self.logger.info(f"Starting AI vulnerability testing - Model: {args.model}")
        
        # This would integrate with AI vulnerability modules
        self.logger.warning("AI vulnerability testing not yet implemented in modular structure")
        return False
    
    def _handle_easycard_command(self, args: Any) -> bool:
        """Handle easycard subcommands."""
        self.logger.info("Executing easycard command via bridge")
        return self.bridge.execute_easycard_command(args)
    
    def _handle_emulator_command(self, args: Any) -> bool:
        """Handle emulation commands."""
        self.logger.info("Executing emulation command via bridge")
        return self.bridge.execute_emulation_command(args)
    
    def _handle_nfc_command(self, args: Any) -> bool:
        """Handle NFC commands."""
        self.logger.info("Executing NFC command via bridge")
        return self.bridge.execute_nfc_command(args)
    
    def _handle_apdu_command(self, args: Any) -> bool:
        """Handle direct APDU commands."""
        self.logger.info("Executing APDU command via bridge")
        return self.bridge.execute_apdu_command(args)
    
    def _handle_fido_command(self, args: Any) -> bool:
        """Handle FIDO/WebAuthn commands."""
        self.logger.info("Executing FIDO command via bridge")
        return self.bridge.execute_fido_command(args)
    
    def _handle_gp_command(self, args: Any) -> bool:
        """Handle GlobalPlatform commands."""
        self.logger.info("Executing GlobalPlatform command via bridge")
        return self.bridge.execute_gp_command(args)
    
    def _handle_install_cap_command(self, args: Any) -> bool:
        """Handle CAP file installation."""
        self.logger.info("Executing install CAP command via bridge")
        return self.bridge.execute_install_cap_command(args)
    
    def _handle_log_analysis_command(self, args: Any) -> bool:
        """Handle log analysis commands."""
        self.logger.info(f"Log analysis operation: {args.operation}")
        
        if args.operation == "tlv" and args.file:
            try:
                from core.emv_processor import EMVProcessor
                emv_processor = EMVProcessor()
                
                tlv_entries = emv_processor.process_tlv_file(args.file)
                
                if args.format == "json":
                    import json
                    print(json.dumps(tlv_entries, indent=2, default=str))
                else:
                    for entry in tlv_entries:
                        print(f"Tag: {entry['tag']} | Length: {entry['length']} | {entry['description']}")
                        if entry['interpretation']:
                            print(f"  Meaning: {entry['interpretation']}")
                
                return True
                
            except ImportError:
                self.logger.error("EMV processor not available")
                return False
        else:
            self.logger.warning("Log analysis functionality not yet fully implemented")
            return False
    
    def _handle_crypto_command(self, args: Any) -> bool:
        """Handle cryptographic commands."""
        self.logger.info("Executing crypto command via bridge")
        return self.bridge.execute_crypto_command(args)
    
    def _handle_probe_hardware_command(self, args: Any) -> bool:
        """Handle hardware probing."""
        self.logger.info("Executing hardware probe via bridge")
        return self.bridge.execute_probe_hardware_command(args)
        
        if args.type in ["all", "nfc"]:
            try:
                from core.nfc_manager import NFCManager
                nfc_manager = NFCManager()
                
                # This would probe NFC hardware
                print("NFC hardware probing not yet implemented")
                
            except ImportError:
                self.logger.warning("NFC manager not available")
        
        if args.type in ["all", "pcsc"]:
            # This would probe PC/SC readers
            print("PC/SC reader probing not yet implemented")
        
        return True