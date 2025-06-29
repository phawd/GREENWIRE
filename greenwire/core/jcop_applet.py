from __future__ import annotations

"""Simulated JCOP card applet for terminal probing."""

from typing import List, Dict, Optional
from greenwire.core.nfc_iso import ISO14443ReaderWriter


class JCOPProbeApplet:
    """Emulate a JCOP applet that probes terminals and logs interactions."""

    def __init__(self) -> None:
        self.transaction_log: List[Dict[str, str]] = []

    def probe_terminal(
        self,
        reader: Optional[ISO14443ReaderWriter] = None,
        terminal_name: str = "UNKNOWN",
    ) -> None:
        """Attempt to interact with a terminal and log the result."""
        if reader is None:
            reader = ISO14443ReaderWriter()

        success = False
        if reader.connect():
            try:
                # SELECT PPSE as a simple capability probe
                reader.transceive(bytes.fromhex("00A404000E325041592E5359532E444446303100"))
                # GET PROCESSING OPTIONS to check terminal response
                reader.transceive(bytes.fromhex("80A8000002830000"))
                success = True
            except Exception:
                success = False
            finally:
                reader.disconnect()

        self.transaction_log.append(
            {
                "terminal": terminal_name,
                "status": "OK" if success else "FAIL",
            }
        )

    def insert_code(self, code: bytes) -> None:
        """Simulate deploying code to the card applet storage."""
        self.transaction_log.append({"inserted_code": code.hex()})

    def get_transaction_log(self) -> List[Dict[str, str]]:
        """Return the stored transaction records."""
        return list(self.transaction_log)
