"""
Robust TLV library wrapper for EMV and ISO 7816 TLV parsing/building.
"""
import binascii
from typing import Dict, Any, Tuple

class TLVLib:
    @staticmethod
    def parse_tlv(data: str) -> Dict[str, Any]:
        """Parse TLV string into a tag dictionary."""
        tlv_data = {}
        i = 0
        data_bytes = binascii.unhexlify(data) if isinstance(data, str) else data
        while i < len(data_bytes):
            # Parse tag
            tag = data_bytes[i]
            i += 1
            if tag & 0x1F == 0x1F:  # Multi-byte tag
                tag_bytes = [tag]
                while i < len(data_bytes) and data_bytes[i] & 0x80:
                    tag_bytes.append(data_bytes[i])
                    i += 1
                if i < len(data_bytes):
                    tag_bytes.append(data_bytes[i])
                    i += 1
                tag_str = ''.join(f'{b:02X}' for b in tag_bytes)
            else:
                tag_str = f'{tag:02X}'
            if i >= len(data_bytes):
                break
            # Parse length
            length = data_bytes[i]
            i += 1
            if length & 0x80:  # Multi-byte length
                length_bytes = length & 0x7F
                if length_bytes > 0 and i + length_bytes <= len(data_bytes):
                    length = 0
                    for j in range(length_bytes):
                        length = (length << 8) | data_bytes[i]
                        i += 1
            # Parse value
            if i + length <= len(data_bytes):
                value = data_bytes[i:i+length]
                tlv_data[tag_str] = value.hex().upper()
                i += length
            else:
                break
        return tlv_data

    @staticmethod
    def build_tlv(tag: str, value: bytes) -> str:
        """Build a TLV string from tag and value."""
        tag_bytes = bytes.fromhex(tag)
        length = len(value)
        if length < 0x80:
            length_bytes = bytes([length])
        else:
            lenlen = 1
            while length > (1 << (8 * lenlen)):
                lenlen += 1
            length_bytes = bytes([0x80 | lenlen]) + length.to_bytes(lenlen, 'big')
        return tag_bytes.hex().upper() + length_bytes.hex().upper() + value.hex().upper()
