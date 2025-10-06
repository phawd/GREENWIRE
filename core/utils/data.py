"""
GREENWIRE Data Utilities
=========================
Data processing and TLV parsing utilities.
"""

from typing import Any, Dict, List, Tuple, Union  # noqa: F401
import struct  # noqa: F401


class TLVError(Exception):
    """Exception raised for TLV parsing errors."""
    pass


def tlv_parse(data: bytes, offset: int = 0) -> List[Tuple[int, bytes]]:
    """
    Parse TLV (Tag-Length-Value) data.
    
    Returns:
        List of (tag, value) tuples
    """
    result = []
    pos = offset
    
    while pos < len(data):
        if pos >= len(data):
            break
        
        # Parse tag
        tag, pos = _parse_tlv_tag(data, pos)
        if pos >= len(data):
            break
        
        # Parse length
        length, pos = _parse_tlv_length(data, pos)
        if pos + length > len(data):
            raise TLVError(f"TLV length {length} exceeds remaining data")
        
        # Extract value
        value = data[pos:pos + length]
        pos += length
        
        result.append((tag, value))
    
    return result


def _parse_tlv_tag(data: bytes, pos: int) -> Tuple[int, int]:
    """Parse TLV tag and return (tag, new_position)."""
    if pos >= len(data):
        raise TLVError("Unexpected end of data while parsing tag")
    
    tag = data[pos]
    pos += 1
    
    # Check if this is a multi-byte tag
    if (tag & 0x1F) == 0x1F:
        # Multi-byte tag
        tag = tag << 8
        while pos < len(data):
            byte = data[pos]
            tag = (tag << 8) | byte
            pos += 1
            if (byte & 0x80) == 0:  # Last byte of tag
                break
        else:
            raise TLVError("Incomplete multi-byte tag")
    
    return tag, pos


def _parse_tlv_length(data: bytes, pos: int) -> Tuple[int, int]:
    """Parse TLV length and return (length, new_position)."""
    if pos >= len(data):
        raise TLVError("Unexpected end of data while parsing length")
    
    length_byte = data[pos]
    pos += 1
    
    if (length_byte & 0x80) == 0:
        # Short form
        return length_byte, pos
    else:
        # Long form
        length_bytes = length_byte & 0x7F
        if length_bytes == 0:
            raise TLVError("Indefinite length not supported")
        
        if pos + length_bytes > len(data):
            raise TLVError("Incomplete length field")
        
        length = 0
        for _ in range(length_bytes):
            length = (length << 8) | data[pos]
            pos += 1
        
        return length, pos


def tlv_encode(tag: int, value: bytes) -> bytes:
    """Encode tag and value as TLV."""
    # Encode tag
    if tag < 0x1F:
        tag_bytes = bytes([tag])
    else:
        # Multi-byte tag encoding
        tag_bytes = []
        temp_tag = tag
        while temp_tag > 0:
            if len(tag_bytes) == 0:
                tag_bytes.append(temp_tag & 0x7F)
            else:
                tag_bytes.append((temp_tag & 0x7F) | 0x80)
            temp_tag >>= 7
        tag_bytes.reverse()
        tag_bytes = bytes(tag_bytes)
    
    # Encode length
    length = len(value)
    if length < 0x80:
        length_bytes = bytes([length])
    else:
        # Long form
        length_bytes = []
        temp_length = length
        while temp_length > 0:
            length_bytes.append(temp_length & 0xFF)
            temp_length >>= 8
        length_bytes.reverse()
        length_bytes = bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)
    
    return tag_bytes + length_bytes + value


def tlv_find(data: bytes, target_tag: int) -> bytes:
    """Find and return the value for a specific tag in TLV data."""
    tlv_list = tlv_parse(data)
    for tag, value in tlv_list:
        if tag == target_tag:
            return value
    raise TLVError(f"Tag {target_tag:X} not found")


def dol_parse(dol_data: bytes) -> List[Tuple[int, int]]:
    """
    Parse DOL (Data Object List) data.
    
    Returns:
        List of (tag, length) tuples
    """
    result = []
    pos = 0
    
    while pos < len(dol_data):
        # Parse tag
        tag, pos = _parse_tlv_tag(dol_data, pos)
        if pos >= len(dol_data):
            break
        
        # Parse length (single byte for DOL)
        length = dol_data[pos]
        pos += 1
        
        result.append((tag, length))
    
    return result


def construct_dol_data(dol: List[Tuple[int, int]], data_dict: Dict[int, bytes]) -> bytes:
    """Construct data according to DOL specification."""
    result = b''
    
    for tag, length in dol:
        if tag in data_dict:
            value = data_dict[tag]
            if len(value) > length:
                # Truncate if too long
                value = value[:length]
            elif len(value) < length:
                # Pad with zeros if too short
                value = value + b'\x00' * (length - len(value))
            result += value
        else:
            # Missing data, fill with zeros
            result += b'\x00' * length
    
    return result


def bcd_encode(number_str: str) -> bytes:
    """Encode decimal string as BCD (Binary Coded Decimal)."""
    # Pad with leading zero if odd length
    if len(number_str) % 2 == 1:
        number_str = '0' + number_str
    
    result = b''
    for i in range(0, len(number_str), 2):
        high = int(number_str[i])
        low = int(number_str[i + 1])
        result += bytes([(high << 4) | low])
    
    return result


def bcd_decode(bcd_data: bytes) -> str:
    """Decode BCD data to decimal string."""
    result = ''
    for byte in bcd_data:
        high = (byte >> 4) & 0x0F
        low = byte & 0x0F
        result += f'{high}{low}'
    
    return result