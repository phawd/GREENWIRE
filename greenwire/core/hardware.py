from typing import List, Optional
import logging

from smartcard.System import readers
from smartcard.util import toHexString, toBytes
import smartcard
from smartcard.CardConnection import CardConnection

import nfc


def list_pcsc_readers() -> List[str]:
    """Return a list of connected PC/SC smartcard readers."""
    return [str(r) for r in readers()]


def connect_pcsc(reader_index: int = 0):
    """Connect to a smartcard using pyscard."""
    r = readers()
    if not r or reader_index >= len(r):
        raise RuntimeError("No smartcard reader available")
    connection = r[reader_index].createConnection()
    connection.connect()
    return connection


def send_apdu(apdu: bytes, connection=None, reader_index: int = 0):
    """Send an APDU and return response data and status words."""
    if connection is None:
        connection = connect_pcsc(reader_index)
    data, sw1, sw2 = connection.transmit(list(apdu))
    return bytes(data), sw1, sw2


def list_nfc_devices() -> List[str]:
    """List available NFC devices using nfcpy."""
    devices = []
    try:
        clf = nfc.ContactlessFrontend('usb')
        if clf:
            devices.append('usb')
            clf.close()
    except Exception:
        pass
    return devices


def read_nfc_uid() -> Optional[bytes]:
    """Read the UID of an NFC tag if present."""
    try:
        with nfc.ContactlessFrontend('usb') as clf:
            tag = clf.connect(rdwr={'on-connect': lambda tag: False})
            if tag and hasattr(tag, 'identifier'):
                return bytes(tag.identifier)
    except Exception as e:
        logging.error(f"Failed to read NFC UID: {e}")
    return None
