"""In-memory read/write handlers for NFC standards."""

from __future__ import annotations

from typing import Dict


class _BaseReaderWriter:
    """Simple in-memory storage for NFC blocks."""

    def __init__(self) -> None:
        self._storage: Dict[int, bytes] = {}

    def write_block(self, block: int, data: bytes) -> None:
        if not isinstance(block, int):
            raise TypeError("block must be an integer")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        self._storage[block] = bytes(data)

    def read_block(self, block: int) -> bytes:
        return self._storage.get(block, b"")


class ISO14443ReaderWriter(_BaseReaderWriter):
    """Stub reader/writer for ISO 14443."""


class ISO15693ReaderWriter(_BaseReaderWriter):
    """Stub reader/writer for ISO/IEC 15693."""


class ISO18092ReaderWriter(_BaseReaderWriter):
    """Stub reader/writer for ISO 18092."""

