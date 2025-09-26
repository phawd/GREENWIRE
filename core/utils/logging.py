"""
GREENWIRE Logging Utilities
============================
Logging setup and utilities for GREENWIRE.
"""

import logging, os, sys  # noqa: F401
from typing import Optional
from datetime import datetime  # noqa: F401


class GreenwireFormatter(logging.Formatter):
    """Custom formatter for GREENWIRE logs."""
    
    def __init__(self, include_timestamp: bool = True):
        self.include_timestamp = include_timestamp
        if include_timestamp:
            fmt = '[%(asctime)s] %(name)s:%(levelname)s - %(message)s'
        else:
            fmt = '%(name)s:%(levelname)s - %(message)s'
        
        super().__init__(fmt, datefmt='%H:%M:%S')
    
    def format(self, record):
        # Add GREENWIRE prefix to logger names
        if not record.name.startswith('greenwire'):
            record.name = f'greenwire.{record.name}'
        return super().format(record)


class GreenwireLogger:
    """GREENWIRE logger wrapper."""
    
    def __init__(self, name: str):
        """Initialize GREENWIRE logger."""
        self.logger = logging.getLogger(f'greenwire.{name}')
        self._setup_default_handler()
    
    def _setup_default_handler(self):
        """Setup default console handler if none exists."""
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(GreenwireFormatter())
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def debug(self, msg, *args, **kwargs):
        """Log debug message."""
        self.logger.debug(msg, *args, **kwargs)
    
    def info(self, msg, *args, **kwargs):
        """Log info message."""
        self.logger.info(msg, *args, **kwargs)
    
    def warning(self, msg, *args, **kwargs):
        """Log warning message."""
        self.logger.warning(msg, *args, **kwargs)
    
    def error(self, msg, *args, **kwargs):
        """Log error message."""
        self.logger.error(msg, *args, **kwargs)
    
    def critical(self, msg, *args, **kwargs):
        """Log critical message."""
        self.logger.critical(msg, *args, **kwargs)
    
    def set_level(self, level: str):
        """Set logging level."""
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL,
        }
        self.logger.setLevel(level_map.get(level.upper(), logging.INFO))


def setup_greenwire_logging(level: str = 'INFO', log_file: Optional[str] = None, 
                           include_timestamp: bool = True, quiet: bool = False) -> logging.Logger:
    """
    Setup GREENWIRE logging configuration.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to log to
        include_timestamp: Whether to include timestamps in logs
        quiet: If True, suppress console output
    
    Returns:
        Root GREENWIRE logger
    """
    # Get root GREENWIRE logger
    root_logger = logging.getLogger('greenwire')
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Setup formatter
    formatter = GreenwireFormatter(include_timestamp)
    
    # Add console handler unless quiet mode
    if not quiet:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(GreenwireFormatter(True))  # Always include timestamp in files
            root_logger.addHandler(file_handler)
        except Exception as e:
            print(f"Warning: Could not setup file logging: {e}", file=sys.stderr)
    
    # Prevent propagation to avoid duplicate messages
    root_logger.propagate = False
    
    return root_logger


def get_greenwire_logger(name: str = '') -> GreenwireLogger:
    """Get a GREENWIRE logger instance."""
    return GreenwireLogger(name)