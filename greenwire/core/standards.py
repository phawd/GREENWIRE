"""Definitions and minimal handlers for common smartcard and NFC standards."""

from enum import Enum
from typing import List


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
