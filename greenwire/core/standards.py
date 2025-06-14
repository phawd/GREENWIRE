"""Definitions and minimal handlers for common smartcard and NFC standards."""

from enum import Enum
from typing import Dict, List


class Standard(Enum):
    """Enumeration of supported standards."""

    ISO_IEC_7810 = "ISO/IEC 7810"
    ISO_IEC_7816 = "ISO/IEC 7816"
    ISO_7816_T0_T1 = "T=0/T=1 (ISO 7816-3)"
    EMV = "EMV"
    GLOBALPLATFORM = "GlobalPlatform"
    GLOBALPLATFORM_ISSUER = "GlobalPlatform Issuer"
    GLOBALPLATFORM_CARDHOLDER = "GlobalPlatform Cardholder"
    CARD_OS = "Card OS"
    ICAO_9303 = "ICAO 9303"
    ISO_IEC_18000 = "ISO/IEC 18000-x"
    ISO_IEC_15693 = "ISO/IEC 15693"
    EPCGLOBAL = "EPCglobal"
    ISO_IEC_29167 = "ISO/IEC 29167"
    ISO_14443 = "ISO 14443"
    ISO_18092 = "ISO 18092"
    NDEF = "NDEF"
    LLCP = "LLCP"
    RTD = "RTD"
    SNEP = "SNEP"


# Simple in-memory data stores simulating tag memory for supported NFC standards
ISO_DATA_STORES: Dict[Standard, bytearray] = {
    Standard.ISO_14443: bytearray(256),
    Standard.ISO_IEC_15693: bytearray(256),
    Standard.ISO_18092: bytearray(256),
}


class StandardHandler:
    """Stub handler demonstrating how standards might be processed."""

    def __init__(self) -> None:
        # Maintain the enumeration order for deterministic behavior
        self.supported = list(Standard)

    def handle(self, standard: Standard) -> str:
        """Return a simple message acknowledging the standard."""
        if standard not in self.supported:
            raise ValueError(f"Unsupported standard: {standard}")
        return f"Handling {standard.value}"

    def check_compliance(self, standard: Standard) -> str:
        """Return a message indicating compliance with the given standard."""
        if standard not in self.supported:
            raise ValueError(f"Unsupported standard: {standard}")
        return f"Following {standard.value} standard"

    def list_supported(self) -> List[str]:
        """Return a list of supported standard names."""
        return [s.value for s in self.supported]

    # ------------------------------------------------------------------
    # Basic read/write operations for ISO 14443/15693/18092
    # ------------------------------------------------------------------
    def read_block(self, standard: Standard, block: int) -> bytes:
        """Return a 4-byte block from the in-memory store for the given standard."""
        if standard not in ISO_DATA_STORES:
            raise NotImplementedError(f"Read not implemented for {standard.value}")

        store = ISO_DATA_STORES[standard]
        start = block * 4
        end = start + 4
        if end > len(store):
            raise ValueError("Block out of range")
        return bytes(store[start:end])

    def write_block(self, standard: Standard, block: int, data: bytes) -> None:
        """Write a 4-byte block to the in-memory store for the given standard."""
        if standard not in ISO_DATA_STORES:
            raise NotImplementedError(f"Write not implemented for {standard.value}")

        if len(data) != 4:
            raise ValueError("Data must be exactly 4 bytes")

        store = ISO_DATA_STORES[standard]
        start = block * 4
        end = start + 4
        if end > len(store):
            raise ValueError("Block out of range")
        store[start:end] = data
