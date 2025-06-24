from typing import Tuple
from smartcard.System import readers

class JCOPManager:
    """Minimal JCOP card helper for demo purposes."""

    GET_DATA_OS_VERSION = [0x80, 0xCA, 0x9F, 0x7F, 0x00]

    def __init__(self) -> None:
        self.connection = None

    def connect(self) -> None:
        available = readers()
        if not available:
            raise RuntimeError("No smart card readers available")
        self.connection = available[0].createConnection()
        self.connection.connect()

    def get_os_version(self) -> Tuple[list, int, int]:
        if not self.connection:
            self.connect()
        data, sw1, sw2 = self.connection.transmit(self.GET_DATA_OS_VERSION)
        return data, sw1, sw2
