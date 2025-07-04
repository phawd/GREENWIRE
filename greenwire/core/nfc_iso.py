"""NFC reader/writer helpers for common ISO standards.

These classes provide an in-memory fallback implementation used in the unit
tests, while also exposing methods that utilise ``nfcpy`` when available.  The
goal is to offer simple read/write operations in environments without NFC
hardware and a more advanced interface when a contactless reader is present.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Dict, Optional, Sequence
import subprocess

try:  # Optional nfcpy import
    import nfc
except Exception:  # pragma: no cover - nfcpy may not be installed during tests
    nfc = None


class _BaseReaderWriter:
    """Simple in-memory storage for NFC blocks."""

    def __init__(self) -> None:
        self._storage: Dict[int, bytes] = {}
        self.clf: Optional[object] = None  # ContactlessFrontend when available
        self.tag: Optional[object] = None

    def write_block(self, block: int, data: bytes) -> None:
        if not isinstance(block, int):
            raise TypeError("block must be an integer")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        if self.tag and hasattr(self.tag, "write_block"):
            try:
                self.tag.write_block(block, bytes(data))
                return
            except Exception:
                pass  # fall back to in-memory
        self._storage[block] = bytes(data)

    def read_block(self, block: int) -> bytes:
        if self.tag and hasattr(self.tag, "read_block"):
            try:
                data = self.tag.read_block(block)
                if isinstance(data, (bytes, bytearray)):
                    return bytes(data)
            except Exception:
                pass
        return self._storage.get(block, b"")

    # ------------------------------------------------------------------
    # NFC helper functionality
    # ------------------------------------------------------------------
    def connect(
        self,
        device: str = "usb",
        targets: Optional[Sequence[str]] = None,
    ) -> bool:
        """Attempt to connect to an NFC tag using nfcpy.

        Parameters
        ----------
        device:
            The nfcpy device string, usually ``"usb"``.
        targets:
            Optional list of target identifiers passed to ``clf.connect``.

        Returns ``True`` if a tag was successfully connected.
        On failure or when ``nfcpy`` is unavailable, ``False`` is returned and
        the object continues to operate in in-memory mode.
        """

        if nfc is None:
            return False
        try:
            self.clf = nfc.ContactlessFrontend(device)
            if hasattr(self.clf, "connect"):
                self.tag = self.clf.connect(rdwr={
                    "targets": targets,
                    "on-connect": lambda tag: True,
                })
            return self.tag is not None
        except Exception:
            # Ensure cleanup on failure
            if self.clf is not None:
                try:
                    self.clf.close()
                finally:
                    self.clf = None
            self.tag = None
            return False

    def disconnect(self) -> None:
        """Close any open NFC connection."""

        if self.clf is not None:
            try:
                if hasattr(self.clf, "close"):
                    self.clf.close()
            finally:
                self.clf = None
                self.tag = None

    @contextmanager
    def session(
        self,
        device: str = "usb",
        targets: Optional[Sequence[str]] = None,
    ):
        """Context manager to manage an NFC connection."""

        if self.connect(device, targets):
            try:
                yield self
            finally:
                self.disconnect()
        else:
            yield self

    def transceive(self, data: bytes) -> bytes:
        """Send raw data to the connected tag and return the response."""

        if self.tag and hasattr(self.tag, "transceive"):
            return self.tag.transceive(data)
        raise RuntimeError("No NFC tag connected")

    def authenticate(self, block: int, key: bytes) -> bool:
        """Authenticate to a MIFARE Classic block using ``key``.

        This is a best-effort helper that relies on ``nfcpy`` when available.
        When running in pure in-memory mode, authentication always fails.
        """

        if self.tag and hasattr(self.tag, "authenticate"):
            try:
                return bool(self.tag.authenticate(block, key))
            except Exception:
                return False
        return False


class ISO14443ReaderWriter(_BaseReaderWriter):
    """Reader/writer for ISO 14443 tags."""

    def connect(self, device: str = "usb") -> bool:
        # pragma: no cover - hardware dependent
        return super().connect(device, targets=["106A", "106B"])


class ISO15693ReaderWriter(_BaseReaderWriter):
    """Reader/writer for ISO/IEC 15693 tags."""

    def connect(self, device: str = "usb") -> bool:
        # pragma: no cover - hardware dependent
        return super().connect(device, targets=["iso15693"])


class ISO18092ReaderWriter(_BaseReaderWriter):
    """Reader/writer for ISO 18092 (NFC Forum) devices."""

    def connect(self, device: str = "usb") -> bool:
        # pragma: no cover - hardware dependent
        return super().connect(device, targets=["212F", "424F"])


class AndroidReaderWriter(_BaseReaderWriter):
    """Reader/writer using an Android device over ADB.

    This helper enables basic NFC operations when an Android phone is
    connected via the Android Debug Bridge. It relies on the ``adb`` tool to
    forward APDU commands to a helper application running on the device. The
    implementation is intentionally lightweight so that unit tests can run
    without requiring hardware.
    """

    def __init__(self, serial: Optional[str] = None) -> None:
        super().__init__()
        self.serial = serial

    def _adb(self, *args: str) -> str:
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += list(args)
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return proc.stdout.strip()

    def connect(self, device: str = "adb") -> bool:  # pragma: no cover
        self._adb("shell", "svc", "nfc", "enable")
        return True

    def disconnect(self) -> None:  # pragma: no cover
        self._adb("shell", "svc", "nfc", "disable")
        super().disconnect()

    def transceive(self, data: bytes) -> bytes:
        hex_data = data.hex()
        resp = self._adb("shell", "cmd", "nfc", "transceive", hex_data)
        try:
            return bytes.fromhex(resp)
        except ValueError:
            return b""
