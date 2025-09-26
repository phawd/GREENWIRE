#!/usr/bin/env python3
"""
GREENWIRE Import Management System
Centralized, simplified import handling with clear fallbacks
"""

import importlib
import sys
from typing import Dict, List, Optional, Any
from core.logging_system import get_logger, handle_errors

class ModuleManager:
    """Centralized module import and availability management."""
    
    def __init__(self):
        self.available_modules = {}
        self.failed_imports = {}
        self.logger = get_logger()
        
        # Core module mappings
        self.module_map = {
            # NFC/Hardware modules
            'nfc': ['pyscard', 'smartcard'],
            'android_nfc': ['subprocess'],  # Built-in, always available
            'nfc_emulation': ['pyscard'],
            
            # Card/EMV modules  
            'emv': ['cryptography', 'pycryptodome'],
            'smartcard_ops': ['pyscard', 'smartcard'],
            'cap_file': [],  # Custom implementation
            
            # Fuzzing modules
            'apdu_fuzzer': [],  # Custom implementation
            'file_fuzzer': ['pillow'],
            'protocol_fuzzer': ['scapy'],
            
            # Crypto modules
            'crypto': ['cryptography', 'pycryptodome'],
            'key_manager': ['cryptography'],
            
            # System modules
            'device_detection': ['pyudev'],  # Optional
            'process_manager': [],  # Built-in
        }
    
    @handle_errors("Module availability check", return_on_error=False)
    def check_module_availability(self, module_name: str) -> bool:
        """Check if a module and its dependencies are available."""
        if module_name in self.available_modules:
            return self.available_modules[module_name]
        
        if module_name not in self.module_map:
            self.logger.warning(f"Unknown module: {module_name}")
            return False
        
        dependencies = self.module_map[module_name]
        available = True
        
        for dep in dependencies:
            try:
                importlib.import_module(dep)
                self.logger.debug(f"✅ {dep} available for {module_name}")
            except ImportError as e:
                self.logger.debug(f"❌ {dep} not available for {module_name}: {e}")
                available = False
                if module_name not in self.failed_imports:
                    self.failed_imports[module_name] = []
                self.failed_imports[module_name].append(str(e))
        
        self.available_modules[module_name] = available
        return available
    
    def has_module(self, module_name: str) -> bool:
        """Check if a module is available (alias for check_module_availability)."""
        try:
            importlib.import_module(module_name)
            return True
        except ImportError:
            return False
    
    def import_module(self, module_name: str, static: bool = False):
        """Import a module dynamically."""
        try:
            return importlib.import_module(module_name)
        except ImportError:
            return None
    
    def get_class(self, module_name: str, class_name: str):
        """Get a class from a module."""
        try:
            module = importlib.import_module(module_name)
            return getattr(module, class_name)
        except (ImportError, AttributeError):
            return None
    
    def get_function(self, module_name: str, function_name: str):
        """Get a function from a module."""
        try:
            module = importlib.import_module(module_name)
            return getattr(module, function_name)
        except (ImportError, AttributeError):
            return None
    
    def get_available_modules(self) -> List[str]:
        """Get list of all available modules."""
        available = []
        for module in self.module_map.keys():
            if self.check_module_availability(module):
                available.append(module)
        return available
    
    def get_unavailable_modules(self) -> Dict[str, List[str]]:
        """Get unavailable modules with their error messages."""
        unavailable = {}
        for module in self.module_map.keys():
            if not self.check_module_availability(module):
                unavailable[module] = self.failed_imports.get(module, ['Unknown error'])
        return unavailable
    
    def print_module_status(self):
        """Print status of all modules."""
        self.logger.info("=" * 60)
        self.logger.info("MODULE AVAILABILITY STATUS")
        self.logger.info("=" * 60)
        
        available = self.get_available_modules()
        unavailable = self.get_unavailable_modules()
        
        self.logger.info(f"Available modules ({len(available)}):")
        for module in available:
            self.logger.info(f"  ✅ {module}")
        
        if unavailable:
            self.logger.info(f"\nUnavailable modules ({len(unavailable)}):")
            for module, errors in unavailable.items():
                self.logger.info(f"  ❌ {module}: {errors[0]}")
        
        self.logger.info("=" * 60)

    @handle_errors("Safe import", return_on_error=None)
    def safe_import(self, module_name: str, class_name: Optional[str] = None) -> Any:
        """Safely import a module or class with fallback."""
        try:
            module = importlib.import_module(module_name)
            if class_name:
                return getattr(module, class_name)
            return module
        except ImportError as e:
            self.logger.debug(f"Import failed: {module_name}.{class_name or ''}: {e}")
            return None
        except AttributeError as e:
            self.logger.debug(f"Attribute not found: {module_name}.{class_name}: {e}")
            return None

# Global module manager instance
_module_manager = None

def get_module_manager() -> ModuleManager:
    """Get the global module manager instance."""
    global _module_manager
    if _module_manager is None:
        _module_manager = ModuleManager()
    return _module_manager

# Convenience functions for common imports
def import_nfc_modules():
    """Import NFC-related modules with fallbacks."""
    manager = get_module_manager()
    modules = {}
    
    # Try to import pyscard/smartcard
    if manager.check_module_availability('nfc'):
        modules['smartcard_available'] = True
        modules['CardType'] = manager.safe_import('smartcard.CardType', 'CardType')
        modules['CardRequest'] = manager.safe_import('smartcard.CardRequest', 'CardRequest')
        modules['readers'] = manager.safe_import('smartcard.System', 'readers')
    else:
        modules['smartcard_available'] = False
    
    # Android NFC is always available (uses subprocess)
    modules['android_available'] = True
    modules['subprocess'] = manager.safe_import('subprocess')
    
    return modules

def import_crypto_modules():
    """Import cryptography modules with fallbacks."""
    manager = get_module_manager()
    modules = {}
    
    if manager.check_module_availability('crypto'):
        modules['crypto_available'] = True
        modules['Cipher'] = manager.safe_import('cryptography.hazmat.primitives.ciphers', 'Cipher')
        modules['algorithms'] = manager.safe_import('cryptography.hazmat.primitives.ciphers', 'algorithms')
        modules['modes'] = manager.safe_import('cryptography.hazmat.primitives.ciphers', 'modes')
    else:
        modules['crypto_available'] = False
    
    return modules

def import_emv_modules():
    """Import EMV/card-related modules with fallbacks."""
    manager = get_module_manager()
    modules = {}
    
    if manager.check_module_availability('emv'):
        modules['emv_available'] = True
        # Import EMV-specific classes here
    else:
        modules['emv_available'] = False
    
    return modules

def import_fuzzing_modules():
    """Import fuzzing-related modules with fallbacks.""" 
    manager = get_module_manager()
    modules = {}
    
    # APDU fuzzer is always available (custom implementation)
    modules['apdu_fuzzer_available'] = True
    
    # File fuzzing depends on PIL/Pillow
    modules['file_fuzzer_available'] = manager.check_module_availability('file_fuzzer')
    if modules['file_fuzzer_available']:
        modules['PIL'] = manager.safe_import('PIL', 'Image')
    
    # Protocol fuzzing depends on scapy
    modules['protocol_fuzzer_available'] = manager.check_module_availability('protocol_fuzzer')
    if modules['protocol_fuzzer_available']:
        modules['scapy'] = manager.safe_import('scapy')
    
    return modules

# Module availability flags (computed once)
def get_module_flags():
    """Get boolean flags for module availability."""
    manager = get_module_manager()
    return {
        'HAS_NFC': manager.check_module_availability('nfc'),
        'HAS_ANDROID_NFC': True,  # Always available
        'HAS_EMV': manager.check_module_availability('emv'),
        'HAS_CRYPTO': manager.check_module_availability('crypto'),
        'HAS_FUZZING': True,  # Core fuzzing always available
        'HAS_FILE_FUZZING': manager.check_module_availability('file_fuzzer'),
        'HAS_PROTOCOL_FUZZING': manager.check_module_availability('protocol_fuzzer'),
        'HAS_DEVICE_DETECTION': manager.check_module_availability('device_detection'),
    }

def print_startup_info():
    """Print startup information about available modules."""
    logger = get_logger()
    manager = get_module_manager()
    flags = get_module_flags()
    
    logger.info("🚀 GREENWIRE Starting Up")
    logger.info(f"🔧 Core Features Available:")
    logger.info(f"   📡 NFC Operations: {'✅' if flags['HAS_NFC'] else '❌'}")
    logger.info(f"   📱 Android NFC: {'✅' if flags['HAS_ANDROID_NFC'] else '❌'}")
    logger.info(f"   💳 EMV Operations: {'✅' if flags['HAS_EMV'] else '❌'}")
    logger.info(f"   🔒 Cryptography: {'✅' if flags['HAS_CRYPTO'] else '❌'}")
    logger.info(f"   🧪 Fuzzing: {'✅' if flags['HAS_FUZZING'] else '❌'}")
    logger.info(f"   📁 File Fuzzing: {'✅' if flags['HAS_FILE_FUZZING'] else '❌'}")
    logger.info(f"   🌐 Protocol Fuzzing: {'✅' if flags['HAS_PROTOCOL_FUZZING'] else '❌'}")
    
    # Show any missing dependencies
    unavailable = manager.get_unavailable_modules()
    if unavailable:
        logger.info(f"⚠️  Missing Optional Dependencies:")
        for module, errors in unavailable.items():
            logger.info(f"   {module}: {errors[0]}")
    
    logger.info("="*50)