from __future__ import annotations

"""Simulated JCOP-based applet for terminal probing."""

from typing import List, Dict, Optional
from greenwire.core.nfc_iso import ISO14443ReaderWriter


class GreenProbeApplet:
    """Emulate a JCOP applet that probes terminals and logs interactions.

    The class name is simplified for usage in Python code while the
    actual card content mimics a standard EMV applet so that terminals
    treat it as compliant.  It records all probing attempts for later
    analysis.
    """

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

    def fuzz_after_identification(
        self,
        terminal_type: str,
        reader: Optional[ISO14443ReaderWriter] = None,
    ) -> None:
        """Fuzz a terminal after identifying its type.

        When an ATM is detected the applet uses the crypto engine as a
        minimal stand‑in for an HSM to generate a key before sending
        mutated APDUs.  All results are stored in the transaction log.
        """
        if reader is None:
            reader = ISO14443ReaderWriter()

        key_used = ""
        if terminal_type.upper() == "ATM":
            from greenwire.core.crypto_engine import generate_rsa_key

            key = generate_rsa_key()
            key_used = f"RSA-{key.key_size}"

        self.probe_terminal(reader, terminal_type)
        self.transaction_log.append({"fuzzed": terminal_type, "key": key_used})

    # ------------------------------------------------------------------
    # Extended attack logic
    # ------------------------------------------------------------------
    ATM_COMMANDS = [
        bytes.fromhex("00A404000E325041592E5359532E444446303100"),
        bytes.fromhex("80CA9F1700"),
        bytes.fromhex("80AE800000"),
    ]

    BASIC_APDUS = [
        bytes.fromhex("00A404000E325041592E5359532E444446303100"),
        bytes.fromhex("80A8000002830000"),
        bytes.fromhex("00B2010C00"),
    ]

    GENERATE_AC = bytes.fromhex("80AE800000")

    def attack_terminal(
        self,
        terminal_type: str,
        reader: Optional[ISO14443ReaderWriter] = None,
    ) -> None:
        """Run ATM or APDU fuzzing sequences then attempt a transaction."""
        if reader is None:
            reader = ISO14443ReaderWriter()

        cmds_sent = 0
        if reader.connect():
            try:
                if terminal_type.upper() == "ATM":
                    for apdu in self.ATM_COMMANDS:
                        reader.transceive(apdu)
                        cmds_sent += 1
                else:
                    for _ in range(50):
                        for apdu in self.BASIC_APDUS:
                            reader.transceive(apdu)
                            cmds_sent += 1
                    for _ in range(50):
                        reader.transceive(self.GENERATE_AC)
                        cmds_sent += 1

                # Attempt a simplified transaction
                reader.transceive(bytes.fromhex("00A404000E315041592E5359532E444446303100"))
                reader.transceive(bytes.fromhex("80A8000002830000"))
            finally:
                reader.disconnect()

        self.transaction_log.append({"attack": terminal_type, "count": str(cmds_sent)})
