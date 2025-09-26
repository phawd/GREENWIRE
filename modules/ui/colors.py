"""
GREENWIRE Color Utilities
=========================
Color output and formatting utilities.
"""

import sys
from typing import Optional  # noqa: F401


class Colors:
    """ANSI color codes for terminal output."""
    
    # Text colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    # Styles
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    STRIKETHROUGH = '\033[9m'


def supports_color() -> bool:
    """Check if terminal supports color output."""
    if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
        return False
    
    # Check environment variables
    term = sys.platform
    if 'win' in term:
        # Windows 10+ supports ANSI colors
        import os
        return 'ANSICON' in os.environ or 'WT_SESSION' in os.environ or 'TERM_PROGRAM' in os.environ
    
    return True


def print_colored(text: str, color: str = '', bg_color: str = '', style: str = '', 
                  end: str = '\n', file=None):
    """Print colored text to terminal."""
    if file is None:
        file = sys.stdout
    
    if supports_color():
        output = color + bg_color + style + text + Colors.RESET
    else:
        output = text
    
    print(output, end=end, file=file)


def colorize(text: str, color: str = '', bg_color: str = '', style: str = '') -> str:
    """Return colorized string."""
    if supports_color():
        return color + bg_color + style + text + Colors.RESET
    else:
        return text


def print_banner(title: str, width: int = 60, char: str = '=', color: str = ''):
    """Print a banner with title."""
    border = char * width
    title_line = f"{char}{char} {title.center(width - 6)} {char}{char}"
    
    if color and supports_color():
        print_colored(border, color)
        print_colored(title_line, color)
        print_colored(border, color)
    else:
        print(border)
        print(title_line)
        print(border)


def print_success(message: str):
    """Print success message in green."""
    print_colored(f"✓ {message}", Colors.BRIGHT_GREEN)


def print_error(message: str):
    """Print error message in red."""
    print_colored(f"✗ {message}", Colors.BRIGHT_RED)


def print_warning(message: str):
    """Print warning message in yellow."""
    print_colored(f"⚠ {message}", Colors.BRIGHT_YELLOW)


def print_info(message: str):
    """Print info message in blue."""
    print_colored(f"ℹ {message}", Colors.BRIGHT_BLUE)


def format_hex_colored(data: bytes, bytes_per_line: int = 16) -> str:
    """Format hex data with colors."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        offset = colorize(f"{i:08X}:", Colors.BRIGHT_BLACK)
        
        hex_parts = []
        for b in chunk:
            if 32 <= b < 127:  # Printable ASCII
                hex_parts.append(colorize(f"{b:02X}", Colors.BRIGHT_WHITE))
            else:
                hex_parts.append(colorize(f"{b:02X}", Colors.DIM))
        
        hex_line = " ".join(hex_parts).ljust(bytes_per_line * 3)
        
        ascii_parts = []
        for b in chunk:
            if 32 <= b < 127:
                ascii_parts.append(colorize(chr(b), Colors.BRIGHT_CYAN))
            else:
                ascii_parts.append(colorize('.', Colors.DIM))
        
        ascii_line = "".join(ascii_parts)
        lines.append(f"{offset} {hex_line} |{ascii_line}|")
    
    return '\n'.join(lines)