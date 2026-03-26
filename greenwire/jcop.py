"""
JCOP card manager and integration for GREENWIRE.

Wraps core.gp_native.GPNativeExecutor with JCOP-specific defaults:
  - NXP JCOP uses the standard GP test key by default
  - EMV key diversification (INITIALIZE UPDATE response-driven)
  - JCOP-specific AID conventions (package AID prefix A000000003)

Supports SCP02 and SCP03; defaults to SCP02 which most JCOP cards implement.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from core.gp_native import (
    AppRecord,
    GPCommunicator,
    GPError,
    GPNativeExecutor,
    MockCommunicator,
    STATUS_APPS_SDS,
    STATUS_ELF,
    STATUS_ISD,
)
from core.globalplatform_reference import GP_DEFAULT_TEST_KEY

logger = logging.getLogger(__name__)

# JCOP default package AID prefix (NXP)
JCOP_PACKAGE_AID_PREFIX = "A000000003"
# JCOP default Card Manager AID
JCOP_ISD_AID = "A000000151000000"


class JCOPManager:
    """
    High-level JCOP card management interface.

    Example — list installed apps (no secure channel):
        comm = <your PCscCommunicator or MockCommunicator>
        mgr = JCOPManager(comm)
        mgr.connect()
        print(mgr.list_applications())

    Example — install a CAP file over SCP02:
        mgr = JCOPManager(comm, scp="scp02", master_key_hex="4041424344454647...")
        mgr.connect()
        with open("applet.cap", "rb") as f:
            cap = f.read()
        mgr.install_cap(cap, "A0000003000000", "A0000003000001", "A0000003000001")
    """

    def __init__(
        self,
        communicator: GPCommunicator,
        *,
        scp: str = "scp02",
        master_key_hex: str = GP_DEFAULT_TEST_KEY,
        key_version: int = 0,
        security_level: int = 0x01,
    ) -> None:
        self._comm = communicator
        self._scp = scp
        self._master_key_hex = master_key_hex
        self._key_version = key_version
        self._security_level = security_level
        self._gp: Optional[GPNativeExecutor] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Select ISD and (optionally) establish secure channel."""
        self._gp = GPNativeExecutor(
            self._comm,
            scp=self._scp,
            master_key_hex=self._master_key_hex,
            key_version=self._key_version,
            security_level=self._security_level,
        )
        self._gp.select_isd()
        if self._scp != "none":
            self._gp.open_secure_channel()
        logger.info("JCOP connected (scp=%s)", self._scp)

    def disconnect(self) -> None:
        if self._gp:
            self._gp.close_secure_channel()
        self._gp = None

    def _require(self) -> GPNativeExecutor:
        if self._gp is None:
            raise GPError("Not connected — call connect() first")
        return self._gp

    # ------------------------------------------------------------------
    # Card info
    # ------------------------------------------------------------------

    def card_info(self) -> Dict[str, Any]:
        """Return raw card data (GP tag 0x0066) as hex."""
        gp = self._require()
        try:
            data = gp.get_card_data()
            return {"success": True, "card_data": data.hex().upper()}
        except GPError as exc:
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def list_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """List ISD, installed applications+SDs, and ELF packages."""
        return self._require().list_all()

    def list_applications(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._require().get_status(STATUS_APPS_SDS)]

    def list_packages(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._require().get_status(STATUS_ELF)]

    # ------------------------------------------------------------------
    # CAP management
    # ------------------------------------------------------------------

    def install_cap(
        self,
        cap_bytes: bytes,
        package_aid: str,
        applet_aid: str,
        instance_aid: Optional[str] = None,
        privileges: bytes = b'\x00',
        install_params: bytes = b'',
        progress_cb: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """Load and install a CAP file onto the JCOP card."""
        gp = self._require()
        try:
            result = gp.install_cap(
                cap_bytes,
                package_aid,
                applet_aid,
                instance_aid or applet_aid,
                privileges,
                install_params,
                progress_cb=progress_cb,
            )
            logger.info("CAP installed: %s", result["applet_aid"])
            return result
        except GPError as exc:
            return {"success": False, "error": str(exc)}

    def delete(self, aid: str, delete_related: bool = True) -> Dict[str, Any]:
        """Delete an application or package by AID."""
        gp = self._require()
        try:
            gp.delete(aid, delete_related=delete_related)
            return {"success": True, "deleted": aid.upper()}
        except GPError as exc:
            return {"success": False, "error": str(exc)}

    def store_data(self, data: bytes, encrypt: bool = False) -> Dict[str, Any]:
        """Send STORE DATA for post-issuance personalisation."""
        gp = self._require()
        try:
            gp.store_data(data, encrypt=encrypt)
            return {"success": True}
        except GPError as exc:
            return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def make_jcop_manager(
    communicator: GPCommunicator,
    scp: str = "scp02",
    master_key_hex: str = GP_DEFAULT_TEST_KEY,
) -> JCOPManager:
    """Instantiate a JCOPManager with common lab defaults."""
    return JCOPManager(communicator, scp=scp, master_key_hex=master_key_hex)


__all__ = [
    "JCOPManager",
    "make_jcop_manager",
    "JCOP_ISD_AID",
    "JCOP_PACKAGE_AID_PREFIX",
]
