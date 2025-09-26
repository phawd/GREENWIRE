#!/usr/bin/env python3
"""
GREENWIRE Core Configuration System
Centralized configuration management for all GREENWIRE operations
"""

import json, logging, os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional
from pathlib import Path  # noqa: F401

@dataclass
class AppConfig:
    """Application configuration settings."""
    name: str = "GREENWIRE"
    version: str = "3.0"
    description: str = "Advanced Payment Card Security Suite"
    environment: str = "development"
    static_mode: bool = False

@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: Optional[str] = None
    console: bool = True

@dataclass
class NFCConfig:
    """NFC-specific configuration settings."""
    use_android: bool = True
    use_hardware: bool = True
    timeout: int = 30
    retry_attempts: int = 3
    protocol: str = "all"
    continuous_scan: bool = False
    adb_path: Optional[str] = None

@dataclass
class MenuConfig:
    """Menu system configuration."""
    structure: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.structure is None:
            self.structure = {}

@dataclass
class SecurityConfig:
    """Security and testing configuration."""
    enable_scanning: bool = True
    scan_schedule: str = "daily"
    trusted_sources: List[str] = None
    enable_fuzzing: bool = True
    max_fuzzing_iterations: int = 1000
    enable_logging: bool = True
    log_sensitive_data: bool = False
    require_confirmation: bool = True
    
    def __post_init__(self):
        if self.trusted_sources is None:
            self.trusted_sources = []

@dataclass
class CardConfig:
    """Card generation and operation settings."""
    default_scheme: str = "visa"
    default_region: str = "us" 
    cardholder_name: str = "GREENWIRE USER"
    expiry_offset_months: int = 36
    floor_limit: int = 50
    risk_level: str = "very_low"
    cvm_method: str = "no_cvm"
    
@dataclass
class SystemConfig:
    """System-level configuration."""
    output_dir: str = "output"
    temp_dir: str = "temp"
    ca_file: Optional[str] = None
    verbose: bool = False
    production: bool = False
    debug: bool = False
    
@dataclass 
class GreenwireConfig:
    """Master configuration for all GREENWIRE operations."""
    app: AppConfig
    logging: LoggingConfig
    nfc: NFCConfig
    menu: MenuConfig
    security: SecurityConfig
    card: CardConfig
    system: SystemConfig
    
    def __post_init__(self):
        """Ensure output directories exist."""
        os.makedirs(self.system.output_dir, exist_ok=True)
        os.makedirs(self.system.temp_dir, exist_ok=True)
    
    @classmethod
    def from_file(cls, config_path: str) -> 'GreenwireConfig':
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return cls(
                app=AppConfig(**data.get('app', {})),
                logging=LoggingConfig(**data.get('logging', {})),
                nfc=NFCConfig(**data.get('nfc', {})),
                menu=MenuConfig(**data.get('menu', {})),
                security=SecurityConfig(**data.get('security', {})),
                card=CardConfig(**data.get('card', {})),
                system=SystemConfig(**data.get('system', {}))
            )
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logging.warning(f"Could not load config from {config_path}: {e}")
            return cls.default()
    
    @classmethod
    def from_args(cls, args) -> 'GreenwireConfig':
        """Create configuration from command line arguments."""
        config = cls.default()
        
        # Map common arguments
        if hasattr(args, 'verbose') and args.verbose:
            config.system.verbose = True
        if hasattr(args, 'production') and args.production:
            config.system.production = True
        if hasattr(args, 'debug') and args.debug:
            config.system.debug = True
        if hasattr(args, 'ca_file') and args.ca_file:
            config.system.ca_file = args.ca_file
        if hasattr(args, 'output_dir') and args.output_dir:
            config.system.output_dir = args.output_dir
            
        # NFC-specific arguments
        if hasattr(args, 'timeout') and args.timeout:
            config.nfc.timeout = args.timeout
        if hasattr(args, 'protocol') and args.protocol:
            config.nfc.protocol = args.protocol
        if hasattr(args, 'continuous') and args.continuous:
            config.nfc.continuous_scan = args.continuous
            
        # Card-specific arguments
        if hasattr(args, 'scheme') and args.scheme:
            config.card.default_scheme = args.scheme
        if hasattr(args, 'region') and args.region:
            config.card.default_region = args.region
        if hasattr(args, 'cardholder_name') and args.cardholder_name:
            config.card.cardholder_name = args.cardholder_name
            
        return config
    
    @classmethod
    def default(cls) -> 'GreenwireConfig':
        """Create default configuration."""
        return cls(
            app=AppConfig(),
            logging=LoggingConfig(),
            nfc=NFCConfig(),
            menu=MenuConfig(),
            security=SecurityConfig(),
            card=CardConfig(),
            system=SystemConfig()
        )
    
    def save_to_file(self, config_path: str):
        """Save configuration to JSON file."""
        try:
            with open(config_path, 'w') as f:
                json.dump(asdict(self), f, indent=2)
        except Exception as e:
            logging.error(f"Could not save config to {config_path}: {e}")
    
    def update_from_dict(self, updates: Dict[str, Any]):
        """Update configuration from dictionary."""
        for section, values in updates.items():
            if hasattr(self, section):
                section_obj = getattr(self, section)
                for key, value in values.items():
                    if hasattr(section_obj, key):
                        setattr(section_obj, key, value)

# Global configuration instance
_config = None

def get_config() -> GreenwireConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        # Try to load from settings.json first
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.json')
        if os.path.exists(config_path):
            _config = GreenwireConfig.from_file(config_path)
        else:
            _config = GreenwireConfig.default()
    return _config

def set_config(config: GreenwireConfig):
    """Set the global configuration instance."""
    global _config
    _config = config

def load_config(config_path: str = None) -> GreenwireConfig:
    """Load configuration from file or create default."""
    if config_path and os.path.exists(config_path):
        config = GreenwireConfig.from_file(config_path)
    else:
        config = GreenwireConfig.default()
    
    set_config(config)
    return config