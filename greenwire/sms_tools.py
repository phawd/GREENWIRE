"""SMS PDU helpers used by the interactive menu."""
from __future__ import annotations

from typing import List

# Example list of SMSC numbers used for educational purposes
DEFAULT_SMSC_LIST: List[str] = [
    "+12063130004",
    "+12063130005",
    "+12063130006",
    "+447785016005",
    "+447785016006",
    "+447785016007",
    "+919082001000",
    "+919082001010",
    "+919082001020",
    "+61294682000",
    "+61294682001",
    "+61294682002",
]


def encode_payload(text: str) -> str:
    """Convert text to a hex representation using UTF-16BE."""
    return text.encode("utf-16-be").hex().upper()


def build_pdu(destination: str, message: str, *, smsc: str | None = None, flash: bool = False, stk: bool = False) -> str:
    """Return a rudimentary SMS PDU string.

    This is a simplified encoder suitable for demonstration in tests. It does not
    implement the full GSM 03.40 specification but provides basic payload
    conversion and DCS handling.
    """
    if stk:
        message = "STK:" + message

    payload_hex = encode_payload(message)
    dcs = "10" if flash else "00"
    smsc_hex = "" if not smsc else encode_payload(smsc)
    dest_hex = encode_payload(destination)
    pdu = f"{smsc_hex}{dest_hex}{dcs}{payload_hex}"
    return pdu
