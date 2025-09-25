"""
GREENWIRE Encoding Utilities
=============================
Encoding and decoding functions.
"""

import base64
import binascii
from typing import Union, List, Tuple


def hex_encode(data: bytes, separator: str = '') -> str:
    """Encode bytes as hexadecimal string."""
    hex_str = data.hex().upper()
    if separator:
        # Insert separator between each pair of hex digits
        return separator.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    return hex_str


def hex_decode(hex_string: str) -> bytes:
    """Decode hexadecimal string to bytes."""
    # Remove common separators
    cleaned = hex_string.replace(' ', '').replace(':', '').replace('-', '')
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {hex_string}") from e


def base64_encode(data: bytes) -> str:
    """Encode bytes as base64 string."""
    return base64.b64encode(data).decode('ascii')


def base64_decode(b64_string: str) -> bytes:
    """Decode base64 string to bytes."""
    try:
        return base64.b64decode(b64_string)
    except Exception as e:
        raise ValueError(f"Invalid base64 string: {b64_string}") from e


def url_safe_base64_encode(data: bytes) -> str:
    """Encode bytes as URL-safe base64 string."""
    return base64.urlsafe_b64encode(data).decode('ascii')


def url_safe_base64_decode(b64_string: str) -> bytes:
    """Decode URL-safe base64 string to bytes."""
    try:
        return base64.urlsafe_b64decode(b64_string)
    except Exception as e:
        raise ValueError(f"Invalid URL-safe base64 string: {b64_string}") from e


def ascii_encode(text: str) -> bytes:
    """Encode text as ASCII bytes."""
    return text.encode('ascii')


def ascii_decode(data: bytes) -> str:
    """Decode ASCII bytes to text."""
    return data.decode('ascii')


def utf8_encode(text: str) -> bytes:
    """Encode text as UTF-8 bytes."""
    return text.encode('utf-8')


def utf8_decode(data: bytes) -> str:
    """Decode UTF-8 bytes to text."""
    return data.decode('utf-8')


def print_hex_dump(data: bytes, width: int = 16, show_ascii: bool = True) -> str:
    """Create a hex dump string representation of data."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        
        # Offset
        offset = f"{i:08X}: "
        
        # Hex representation
        hex_part = ' '.join(f"{b:02X}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        
        # ASCII representation
        ascii_part = ""
        if show_ascii:
            ascii_part = " |" + ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk) + "|"
        
        lines.append(offset + hex_part + ascii_part)
    
    return '\n'.join(lines)