#!/usr/bin/env python3
"""
GREENWIRE Unified Logging and Error Handling System
Provides consistent logging, error handling, and operation tracking
"""

import logging, sys, traceback  # noqa: F401
from functools import wraps
from typing import Any, Callable, Optional
from pathlib import Path
from datetime import datetime

class GreenwireFormatter(logging.Formatter):
    """Custom formatter with color support and structured output."""
    
    # Color codes for different log levels
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green  
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record):
        # Add timestamp and level with colors
        if hasattr(record, 'operation'):
            log_format = f"{self.COLORS.get(record.levelname, '')}{record.levelname:<8}{self.COLORS['RESET']} " \
                        f"[{record.operation}] {record.getMessage()}"
        else:
            log_format = f"{self.COLORS.get(record.levelname, '')}{record.levelname:<8}{self.COLORS['RESET']} " \
                        f"{record.getMessage()}"
        
        # Add exception info if present
        if record.exc_info:
            log_format += f"\n{self.formatException(record.exc_info)}"
            
        return log_format

class GreenwireLogger:
    """Centralized logging system for GREENWIRE operations."""
    
    def __init__(self, name: str = "greenwire", log_file: Optional[str] = None, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler with color formatting
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(GreenwireFormatter())
        self.logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def debug(self, msg: str, operation: Optional[str] = None):
        """Log debug message."""
        self._log(logging.DEBUG, msg, operation)
    
    def info(self, msg: str, operation: Optional[str] = None):
        """Log info message."""
        self._log(logging.INFO, msg, operation)
    
    def warning(self, msg: str, operation: Optional[str] = None):
        """Log warning message."""
        self._log(logging.WARNING, msg, operation)
    
    def error(self, msg: str, operation: Optional[str] = None, exc_info: bool = False):
        """Log error message."""
        self._log(logging.ERROR, msg, operation, exc_info=exc_info)
    
    def critical(self, msg: str, operation: Optional[str] = None, exc_info: bool = False):
        """Log critical message."""
        self._log(logging.CRITICAL, msg, operation, exc_info=exc_info)
    
    def _log(self, level: int, msg: str, operation: Optional[str] = None, exc_info: bool = False):
        """Internal logging method."""
        extra = {'operation': operation} if operation else {}
        self.logger.log(level, msg, extra=extra, exc_info=exc_info)

# Global logger instance
_logger = None

def get_logger() -> GreenwireLogger:
    """Get the global logger instance."""
    global _logger
    if _logger is None:
        _logger = GreenwireLogger()
    return _logger

def setup_logging(verbose: bool = False, debug: bool = False, log_file: Optional[str] = None):
    """Setup global logging configuration."""
    level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    
    global _logger
    _logger = GreenwireLogger(
        name="greenwire",
        log_file=log_file,
        level=level
    )
    return _logger

# Error handling decorators
def handle_errors(operation_name: str, return_on_error: Any = None, log_errors: bool = True):
    """Decorator for consistent error handling across operations."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger()
            try:
                logger.debug(f"Starting {operation_name}", operation_name)
                result = func(*args, **kwargs)
                logger.debug(f"Completed {operation_name}", operation_name)
                return result
                
            except ImportError as e:
                if log_errors:
                    logger.error(f"{operation_name} failed - missing dependency: {e}", operation_name)
                return return_on_error
                
            except FileNotFoundError as e:
                if log_errors:
                    logger.error(f"{operation_name} failed - file not found: {e}", operation_name)
                return return_on_error
                
            except PermissionError as e:
                if log_errors:
                    logger.error(f"{operation_name} failed - permission denied: {e}", operation_name)
                return return_on_error
                
            except Exception as e:
                if log_errors:
                    logger.error(f"{operation_name} failed: {e}", operation_name, exc_info=True)
                return return_on_error
                
        return wrapper
    return decorator

def require_dependencies(*dependencies):
    """Decorator to check for required dependencies before execution."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger()
            missing_deps = []
            
            for dep in dependencies:
                try:
                    __import__(dep)
                except ImportError:
                    missing_deps.append(dep)
            
            if missing_deps:
                error_msg = f"Missing dependencies: {', '.join(missing_deps)}"
                logger.error(error_msg, func.__name__)
                raise ImportError(error_msg)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def log_operation(operation_name: Optional[str] = None):
    """Decorator to log operation start/completion."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger()
            op_name = operation_name or func.__name__
            
            logger.info(f"Starting {op_name}", op_name)
            try:
                result = func(*args, **kwargs)
                logger.info(f"Completed {op_name}", op_name)
                return result
            except Exception as e:
                logger.error(f"Failed {op_name}: {e}", op_name)
                raise
        return wrapper
    return decorator

class OperationTracker:
    """Track operation success/failure statistics."""
    
    def __init__(self):
        self.operations = {}
        self.start_time = datetime.now()
    
    def record_success(self, operation: str):
        """Record successful operation."""
        if operation not in self.operations:
            self.operations[operation] = {'success': 0, 'failure': 0}
        self.operations[operation]['success'] += 1
    
    def record_failure(self, operation: str):
        """Record failed operation."""
        if operation not in self.operations:
            self.operations[operation] = {'success': 0, 'failure': 0}
        self.operations[operation]['failure'] += 1
    
    def get_summary(self) -> dict:
        """Get operation summary statistics."""
        total_success = sum(op['success'] for op in self.operations.values())
        total_failure = sum(op['failure'] for op in self.operations.values())
        total_ops = total_success + total_failure
        
        return {
            'operations': self.operations,
            'total_operations': total_ops,
            'total_success': total_success,
            'total_failure': total_failure,
            'success_rate': (total_success / total_ops * 100) if total_ops > 0 else 0,
            'duration': datetime.now() - self.start_time
        }
    
    def print_summary(self):
        """Print formatted operation summary."""
        logger = get_logger()
        summary = self.get_summary()
        
        logger.info("=" * 60)
        logger.info("OPERATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total Operations: {summary['total_operations']}")
        logger.info(f"Successful: {summary['total_success']}")
        logger.info(f"Failed: {summary['total_failure']}")
        logger.info(f"Success Rate: {summary['success_rate']:.1f}%")
        logger.info(f"Duration: {summary['duration']}")
        logger.info("-" * 60)
        
        for operation, stats in summary['operations'].items():
            total = stats['success'] + stats['failure']
            rate = (stats['success'] / total * 100) if total > 0 else 0
            logger.info(f"{operation}: {stats['success']}/{total} ({rate:.1f}%)")
        
        logger.info("=" * 60)

# Global operation tracker
_tracker = None

def get_tracker() -> OperationTracker:
    """Get the global operation tracker."""
    global _tracker
    if _tracker is None:
        _tracker = OperationTracker()
    return _tracker

def track_operation(operation_name: str):
    """Decorator to track operation success/failure."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            tracker = get_tracker()
            try:
                result = func(*args, **kwargs)
                tracker.record_success(operation_name)
                return result
            except Exception as e:
                tracker.record_failure(operation_name)
                raise
        return wrapper
    return decorator