"""
Native Python GlobalPlatform executor.

Implements the GP card management command set (SELECT ISD, GET STATUS,
INSTALL FOR LOAD, LOAD, INSTALL FOR INSTALL, DELETE, STORE DATA, GET DATA,
PUT KEY) using only Python and the existing apdu4j_data APDU builders.

Secure channel support is provided by core.scp_crypto (SCP02/SCP03).
No subprocess calls to gp.jar are made by this module.

All command structures are defined by the GlobalPlatform Card Specification
v2.3 (public standard).
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.globalplatform_reference import GP_DEFAULT_TEST_KEY
from core.scp_crypto import SCP02Session, SCP03Session, make_scp02_session, make_scp03_session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants  (GP Card Spec v2.3)
# ---------------------------------------------------------------------------

GP_CLA          = 0x80
GP_CLA_SECURE   = 0x84
ISO_CLA         = 0x00

INS_SELECT              = 0xA4
INS_INITIALIZE_UPDATE   = 0x50
INS_EXTERNAL_AUTH       = 0x82
INS_GET_STATUS          = 0xF2
INS_INSTALL             = 0xE6
INS_LOAD                = 0xE8
INS_DELETE              = 0xE4
INS_GET_DATA            = 0xCA
INS_PUT_KEY             = 0xD8
INS_STORE_DATA          = 0xE2
INS_SET_STATUS          = 0xF0

# INSTALL P1 bits
INSTALL_FOR_LOAD              = 0x02
INSTALL_FOR_INSTALL           = 0x04
INSTALL_FOR_MAKE_SELECTABLE   = 0x08
INSTALL_FOR_PERSONALIZATION   = 0x20
INSTALL_FOR_EXTRADITION       = 0x10

# GET STATUS P1
STATUS_ISD              = 0x80
STATUS_APPS_SDS         = 0x40
STATUS_ELF              = 0x20
STATUS_ELF_MODULES      = 0x10

# App lifecycle states
STATE_LOADED        = 0x01
STATE_INSTALLED     = 0x03
STATE_SELECTABLE    = 0x07
STATE_LOCKED        = 0x83
STATE_TERMINATED    = 0xFF

_STATE_NAMES = {
    STATE_LOADED:     "LOADED",
    STATE_INSTALLED:  "INSTALLED",
    STATE_SELECTABLE: "SELECTABLE",
    STATE_LOCKED:     "LOCKED",
    STATE_TERMINATED: "TERMINATED",
}

# Well-known ISD AID
ISD_AID = bytes.fromhex("A000000151000000")

# Max APDU data payload for LOAD blocks (conservative, works on most cards)
LOAD_BLOCK_SIZE = 200

SW_SUCCESS       = 0x9000
SW_MORE_DATA_6C  = 0x6C00
SW_MORE_DATA_61  = 0x6100


# ---------------------------------------------------------------------------
# APDU helpers
# ---------------------------------------------------------------------------

def _tlv(tag: int, value: bytes) -> bytes:
    """Encode a simple BER-TLV item (single-byte or two-byte tag, definite short length)."""
    if tag > 0xFF:
        tag_bytes = bytes([(tag >> 8) & 0xFF, tag & 0xFF])
    else:
        tag_bytes = bytes([tag & 0xFF])
    length = len(value)
    if length > 127:
        len_bytes = bytes([0x81, length]) if length < 256 else bytes([0x82, length >> 8, length & 0xFF])
    else:
        len_bytes = bytes([length])
    return tag_bytes + len_bytes + value


def _aid(aid_input: str | bytes) -> bytes:
    if isinstance(aid_input, str):
        return bytes.fromhex(aid_input.replace(":", "").replace(" ", ""))
    return aid_input


def _hex(b: bytes) -> str:
    return b.hex().upper()


def _build_apdu(cla: int, ins: int, p1: int, p2: int,
                data: bytes = b'', le: Optional[int] = None) -> bytes:
    lc = len(data)
    apdu = bytes([cla, ins, p1, p2])
    if lc:
        apdu += bytes([lc]) + data
    if le is not None:
        apdu += bytes([le & 0xFF])
    return apdu


# ---------------------------------------------------------------------------
# Communicator protocol
# ---------------------------------------------------------------------------

class GPCommunicator:
    """
    Abstract communicator interface.
    Subclass or replace with a real PC/SC or mock implementation.
    """

    def send(self, apdu: bytes) -> Tuple[bytes, int]:
        """
        Send raw APDU bytes and return (response_data, sw).
        sw is a 16-bit integer: 0x9000 = success.
        """
        raise NotImplementedError


class MockCommunicator(GPCommunicator):
    """
    In-memory mock communicator for testing.
    Pre-load responses with register_response().
    """

    def __init__(self) -> None:
        self._responses: List[Tuple[bytes, int]] = []
        self._log: List[bytes] = []

    def register_response(self, data: bytes, sw: int = SW_SUCCESS) -> None:
        self._responses.append((data, sw))

    def send(self, apdu: bytes) -> Tuple[bytes, int]:
        self._log.append(apdu)
        if not self._responses:
            return b'', SW_SUCCESS
        return self._responses.pop(0)

    @property
    def sent(self) -> List[bytes]:
        return list(self._log)


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------

@dataclass
class AppRecord:
    aid: str
    state: str
    state_code: int
    privileges: bytes = field(default_factory=bytes)
    extra: bytes = field(default_factory=bytes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "aid":        self.aid,
            "state":      self.state,
            "state_code": f"0x{self.state_code:02X}",
            "privileges": _hex(self.privileges) if self.privileges else "",
        }


def _parse_status_response(data: bytes) -> List[AppRecord]:
    """
    Parse concatenated GET STATUS TLV records (GP spec §11.4).
    Each record: [aid_len][aid][lifecycle][priv_len][privileges?]
    """
    records: List[AppRecord] = []
    offset = 0
    while offset < len(data):
        if offset >= len(data):
            break
        aid_len = data[offset]; offset += 1
        if offset + aid_len > len(data):
            break
        aid = data[offset:offset + aid_len]; offset += aid_len
        if offset >= len(data):
            break
        state_byte = data[offset]; offset += 1
        privs = b''
        if offset < len(data):
            priv_len = data[offset]; offset += 1
            privs = data[offset:offset + priv_len]; offset += priv_len
        records.append(AppRecord(
            aid=_hex(aid),
            state=_STATE_NAMES.get(state_byte, f"UNKNOWN(0x{state_byte:02X})"),
            state_code=state_byte,
            privileges=privs,
        ))
    return records


# ---------------------------------------------------------------------------
# GP Native Executor
# ---------------------------------------------------------------------------

class GPNativeExecutor:
    """
    Pure-Python GlobalPlatform card management executor.

    Usage (no secure channel, e.g. open-platform card):
        gp = GPNativeExecutor(comm)
        gp.select_isd()
        apps = gp.get_status()
        gp.install_cap(cap_bytes, package_aid, applet_aid, instance_aid)

    Usage (SCP02 secure channel):
        gp = GPNativeExecutor(comm, scp="scp02", master_key_hex="4041...4F")
        gp.open_secure_channel()
        gp.install_cap(...)

    Usage (SCP03):
        gp = GPNativeExecutor(comm, scp="scp03", master_key_hex="4041...4F")
        gp.open_secure_channel()
    """

    def __init__(
        self,
        communicator: GPCommunicator,
        *,
        scp: str = "none",
        master_key_hex: str = GP_DEFAULT_TEST_KEY,
        key_version: int = 0,
        security_level: int = 0x01,
        reader: Optional[str] = None,
    ) -> None:
        self.comm = communicator
        self.scp = scp.lower()
        self.master_key_hex = master_key_hex
        self.key_version = key_version
        self.security_level = security_level
        self.reader = reader
        self._session: Optional[SCP02Session | SCP03Session] = None
        self._secure = False

    # ------------------------------------------------------------------
    # Low-level transport
    # ------------------------------------------------------------------

    def _send(self, apdu: bytes) -> Tuple[bytes, int]:
        logger.debug(">> %s", _hex(apdu))
        data, sw = self.comm.send(apdu)
        logger.debug("<< %s SW=%04X", _hex(data) if data else "", sw)
        return data, sw

    def _send_check(self, apdu: bytes, context: str = "") -> bytes:
        data, sw = self._send(apdu)
        if sw != SW_SUCCESS:
            raise GPError(f"{context} failed: SW={sw:04X}")
        return data

    def _wrap(self, cla: int, ins: int, p1: int, p2: int,
              data: bytes = b'', le: Optional[int] = None) -> bytes:
        """Build (and optionally MAC-wrap) an APDU."""
        if self._secure and self._session is not None:
            return self._session.wrap_apdu(cla, ins, p1, p2, data)
        return _build_apdu(cla, ins, p1, p2, data, le)

    # ------------------------------------------------------------------
    # Secure channel
    # ------------------------------------------------------------------

    def open_secure_channel(self) -> None:
        """Perform INITIALIZE UPDATE + EXTERNAL AUTHENTICATE."""
        if self.scp == "scp02":
            self._open_scp02()
        elif self.scp == "scp03":
            self._open_scp03()
        else:
            logger.info("No secure channel requested (scp=none)")

    def _open_scp02(self) -> None:
        session = make_scp02_session(self.master_key_hex)
        host_challenge = SCP02Session.generate_host_challenge()
        init_apdu = session.build_initialize_update(host_challenge, self.key_version)
        resp = self._send_check(init_apdu, "INITIALIZE UPDATE (SCP02)")
        parsed = session.parse_initialize_update_response(resp)
        seq = parsed["seq_counter"]
        card_challenge = parsed["card_challenge"]
        card_cryptogram_received = parsed["card_cryptogram"]
        session.derive_session_keys(seq)
        # Verify card cryptogram
        expected = session.compute_card_cryptogram(host_challenge, card_challenge)
        if expected != card_cryptogram_received:
            raise GPError("SCP02 card cryptogram verification failed — wrong key?")
        host_cryptogram = session.compute_host_cryptogram(host_challenge, card_challenge)
        ext_auth = session.build_external_authenticate(host_cryptogram, self.security_level)
        self._send_check(ext_auth, "EXTERNAL AUTHENTICATE (SCP02)")
        self._session = session
        self._secure = True
        logger.info("SCP02 secure channel established (seq=%s)", _hex(seq))

    def _open_scp03(self) -> None:
        session = make_scp03_session(self.master_key_hex)
        host_challenge = SCP03Session.generate_host_challenge()
        init_apdu = session.build_initialize_update(host_challenge, self.key_version)
        resp = self._send_check(init_apdu, "INITIALIZE UPDATE (SCP03)")
        parsed = session.parse_initialize_update_response(resp)
        card_challenge = parsed["card_challenge"]
        card_cryptogram_received = parsed["card_cryptogram"]
        session.derive_session_keys(host_challenge, card_challenge)
        expected = session.compute_card_cryptogram(host_challenge, card_challenge)
        if expected != card_cryptogram_received:
            raise GPError("SCP03 card cryptogram verification failed — wrong key?")
        host_cryptogram = session.compute_host_cryptogram(host_challenge, card_challenge)
        ext_auth = session.build_external_authenticate(host_cryptogram, self.security_level)
        self._send_check(ext_auth, "EXTERNAL AUTHENTICATE (SCP03)")
        self._session = session
        self._secure = True
        logger.info("SCP03 secure channel established")

    def close_secure_channel(self) -> None:
        self._session = None
        self._secure = False

    # ------------------------------------------------------------------
    # Card management commands
    # ------------------------------------------------------------------

    def select_isd(self, aid: bytes = ISD_AID) -> bytes:
        """SELECT the Issuer Security Domain."""
        apdu = _build_apdu(ISO_CLA, INS_SELECT, 0x04, 0x00, aid, 0x00)
        return self._send_check(apdu, "SELECT ISD")

    def select_application(self, aid: str | bytes) -> bytes:
        """SELECT an application by AID."""
        apdu = _build_apdu(ISO_CLA, INS_SELECT, 0x04, 0x00, _aid(aid), 0x00)
        return self._send_check(apdu, f"SELECT {_hex(_aid(aid))}")

    def get_status(self, element: int = STATUS_APPS_SDS) -> List[AppRecord]:
        """
        GET STATUS for ISD, applications+SDs, or ELFs.
        Handles chained responses (SW 6310).
        """
        cla = GP_CLA_SECURE if self._secure else GP_CLA
        data_out = b''
        p2 = 0x00
        while True:
            apdu = self._wrap(cla, INS_GET_STATUS, element, p2, b'\x4F\x00', 0x00)
            raw, sw = self._send(apdu)
            data_out += raw
            if sw == SW_SUCCESS:
                break
            if sw == 0x6310:  # more data
                p2 = 0x01
                continue
            raise GPError(f"GET STATUS failed: SW={sw:04X}")
        return _parse_status_response(data_out)

    def get_data(self, tag: int) -> bytes:
        """GET DATA by tag."""
        p1 = (tag >> 8) & 0xFF
        p2 = tag & 0xFF
        cla = GP_CLA_SECURE if self._secure else GP_CLA
        apdu = self._wrap(cla, INS_GET_DATA, p1, p2, b'', 0x00)
        return self._send_check(apdu, f"GET DATA {tag:04X}")

    def get_card_data(self) -> bytes:
        return self.get_data(0x0066)

    def delete(self, aid: str | bytes, delete_related: bool = False) -> None:
        """DELETE application or package by AID."""
        tlv = _tlv(0x4F, _aid(aid))
        p2 = 0x80 if delete_related else 0x00
        cla = GP_CLA_SECURE if self._secure else GP_CLA
        apdu = self._wrap(cla, INS_DELETE, 0x00, p2, tlv)
        self._send_check(apdu, f"DELETE {_hex(_aid(aid))}")

    def install_for_load(self, package_aid: str | bytes,
                          sd_aid: str | bytes = b'') -> None:
        """INSTALL [for load] — prepare card to receive a CAP file."""
        pkg = _aid(package_aid)
        sd  = _aid(sd_aid) if sd_aid else b''
        data = bytes([len(pkg)]) + pkg + bytes([len(sd)]) + sd + b'\x00\x00\x00'
        cla = GP_CLA_SECURE if self._secure else GP_CLA
        apdu = self._wrap(cla, INS_INSTALL, INSTALL_FOR_LOAD, 0x00, data)
        self._send_check(apdu, "INSTALL [for load]")

    def load(self, cap_bytes: bytes,
             block_size: int = LOAD_BLOCK_SIZE,
             progress_cb: Optional[Callable[[int, int], None]] = None) -> None:
        """
        LOAD the CAP file in blocks.
        progress_cb(block_num, total_blocks) called after each block.
        """
        total = math.ceil(len(cap_bytes) / block_size)
        cla = GP_CLA_SECURE if self._secure else GP_CLA
        for i in range(total):
            chunk = cap_bytes[i * block_size:(i + 1) * block_size]
            is_last = (i == total - 1)
            p1 = 0x00 if is_last else 0x80
            p2 = i & 0xFF
            apdu = self._wrap(cla, INS_LOAD, p1, p2, chunk)
            self._send_check(apdu, f"LOAD block {i}/{total - 1}")
            if progress_cb:
                progress_cb(i + 1, total)
        logger.info("LOAD complete (%d blocks, %d bytes)", total, len(cap_bytes))

    def install_for_install(
        self,
        package_aid: str | bytes,
        applet_aid: str | bytes,
        instance_aid: str | bytes,
        privileges: bytes = b'\x00',
        install_params: bytes = b'',
    ) -> None:
        """INSTALL [for install and make selectable]."""
        pkg  = _aid(package_aid)
        app  = _aid(applet_aid)
        inst = _aid(instance_aid)
        data = (
            bytes([len(pkg)]) + pkg +
            bytes([len(app)]) + app +
            bytes([len(inst)]) + inst +
            bytes([len(privileges)]) + privileges +
            bytes([len(install_params)]) + install_params +
            b'\x00'  # install token length
        )
        cla = GP_CLA_SECURE if self._secure else GP_CLA
        p1 = INSTALL_FOR_INSTALL | INSTALL_FOR_MAKE_SELECTABLE
        apdu = self._wrap(cla, INS_INSTALL, p1, 0x00, data)
        self._send_check(apdu, "INSTALL [for install]")

    def store_data(self, data: bytes, encrypt: bool = False) -> None:
        """STORE DATA for post-issuance personalisation."""
        payload = self._session.encrypt_data(data) if (encrypt and self._session) else data
        cla = GP_CLA_SECURE if self._secure else GP_CLA
        apdu = self._wrap(cla, INS_STORE_DATA, 0x80, 0x00, payload)
        self._send_check(apdu, "STORE DATA")

    def put_key(self, key_version: int, key_id: int, key_data: bytes) -> None:
        """PUT KEY — update or add a key."""
        header = bytes([key_version, key_id, len(key_data)]) + key_data
        cla = GP_CLA_SECURE if self._secure else GP_CLA
        apdu = self._wrap(cla, INS_PUT_KEY, 0x00, key_id, header)
        self._send_check(apdu, f"PUT KEY ver={key_version} id={key_id}")

    def set_status(self, aid: str | bytes, lifecycle: int) -> None:
        """SET STATUS — change application lifecycle state."""
        cla = GP_CLA_SECURE if self._secure else GP_CLA
        apdu = self._wrap(cla, INS_SET_STATUS, 0x40, lifecycle, _aid(aid))
        self._send_check(apdu, f"SET STATUS {lifecycle:02X}")

    # ------------------------------------------------------------------
    # Convenience: full CAP install workflow
    # ------------------------------------------------------------------

    def install_cap(
        self,
        cap_bytes: bytes,
        package_aid: str | bytes,
        applet_aid: str | bytes,
        instance_aid: Optional[str | bytes] = None,
        privileges: bytes = b'\x00',
        install_params: bytes = b'',
        sd_aid: str | bytes = b'',
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """
        Full load-and-install workflow:
          1. INSTALL [for load]
          2. LOAD (chunked)
          3. INSTALL [for install and make selectable]
        """
        if instance_aid is None:
            instance_aid = applet_aid
        self.install_for_load(package_aid, sd_aid)
        self.load(cap_bytes, progress_cb=progress_cb)
        self.install_for_install(package_aid, applet_aid, instance_aid,
                                  privileges, install_params)
        return {
            "success": True,
            "package_aid": _hex(_aid(package_aid)),
            "applet_aid":  _hex(_aid(applet_aid)),
            "instance_aid": _hex(_aid(instance_aid)),
        }

    # ------------------------------------------------------------------
    # Info / listing helpers
    # ------------------------------------------------------------------

    def list_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return ISD, applications+SDs, and ELF records as dicts."""
        return {
            "isd":          [r.to_dict() for r in self.get_status(STATUS_ISD)],
            "applications": [r.to_dict() for r in self.get_status(STATUS_APPS_SDS)],
            "packages":     [r.to_dict() for r in self.get_status(STATUS_ELF)],
        }


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------

class GPError(Exception):
    """Raised on GP command failures."""


__all__ = [
    "GPNativeExecutor",
    "GPCommunicator",
    "MockCommunicator",
    "AppRecord",
    "GPError",
    "ISD_AID",
    "LOAD_BLOCK_SIZE",
    "STATUS_ISD",
    "STATUS_APPS_SDS",
    "STATUS_ELF",
]
