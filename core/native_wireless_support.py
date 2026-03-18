"""Native wireless transport support planning for Android, iOS, and PC/SC readers."""

from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Sequence


_ACR_READER_RE = re.compile(r"\b(?:ACR\d+[A-Z0-9-]*|ACS)\b", re.IGNORECASE)


@dataclass(frozen=True)
class WirelessBackend:
    backend_id: str
    family: str
    connection_mode: str
    host_platform: str
    available: bool
    native_host_support: bool
    supported_targets: tuple[str, ...]
    reader_names: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    notes: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def normalize_host_platform(platform_name: str | None = None) -> str:
    value = (platform_name or sys.platform).lower()
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    if value.startswith("darwin") or value.startswith("mac"):
        return "macos"
    return "other"


def is_acr_reader(reader_name: str) -> bool:
    return bool(_ACR_READER_RE.search(reader_name or ""))


def detect_adb_available() -> bool:
    return shutil.which("adb") is not None


def detect_pcsc_reader_names() -> List[str]:
    try:
        from smartcard.System import readers  # type: ignore

        return [str(reader) for reader in readers()]
    except Exception:
        return []


def ios_companion_available() -> bool:
    return bool(
        os.getenv("GREENWIRE_IOS_COMPANION_ENDPOINT")
        or os.getenv("GREENWIRE_IOS_DEVICE_NAME")
    )


def build_wireless_support_matrix(
    *,
    host_platform: str | None = None,
    adb_available: bool | None = None,
    pcsc_readers: Sequence[str] | None = None,
    ios_available: bool | None = None,
) -> Dict[str, object]:
    normalized_host = normalize_host_platform(host_platform)
    adb_ready = detect_adb_available() if adb_available is None else bool(adb_available)
    reader_names = list(detect_pcsc_reader_names() if pcsc_readers is None else pcsc_readers)
    ios_ready = ios_companion_available() if ios_available is None else bool(ios_available)

    acr_readers = [name for name in reader_names if is_acr_reader(name)]
    backends = [
        WirelessBackend(
            backend_id="android_adb",
            family="android",
            connection_mode="adb_hce",
            host_platform=normalized_host,
            available=adb_ready,
            native_host_support=normalized_host in {"windows", "linux", "macos"},
            supported_targets=("nfc", "rfid", "emv_contactless", "wallet_hce"),
            notes="Android devices can expose NFC workflows through ADB-hosted control and HCE-capable apps.",
        ),
        WirelessBackend(
            backend_id="ios_companion",
            family="ios",
            connection_mode="companion_wallet",
            host_platform=normalized_host,
            available=ios_ready,
            native_host_support=normalized_host in {"windows", "linux", "macos"},
            supported_targets=("apple_wallet", "nfc_tag", "iso7816_tag"),
            limitations=(
                "requires_ios_companion_or_wallet_flow",
                "no_host_side_hce_on_windows_linux",
            ),
            notes="iOS support is modeled as a native host-managed companion/provisioning path, not host-side card emulation.",
        ),
        WirelessBackend(
            backend_id="acr_pcsc",
            family="acr",
            connection_mode="pcsc_ccid",
            host_platform=normalized_host,
            available=bool(acr_readers),
            native_host_support=normalized_host in {"windows", "linux", "macos"},
            supported_targets=("nfc", "rfid", "iso14443", "mifare", "desfire"),
            reader_names=tuple(acr_readers),
            notes="ACR/ACS-class readers use native PC/SC and CCID transports on desktop hosts.",
        ),
        WirelessBackend(
            backend_id="generic_pcsc",
            family="pcsc",
            connection_mode="pcsc_ccid",
            host_platform=normalized_host,
            available=bool(reader_names),
            native_host_support=normalized_host in {"windows", "linux", "macos"},
            supported_targets=("nfc", "rfid", "iso14443", "iso7816"),
            reader_names=tuple(reader_names),
            notes="Generic PC/SC readers cover contactless readers beyond ACR-branded hardware.",
        ),
    ]
    return {
        "host_platform": normalized_host,
        "backends": [backend.to_dict() for backend in backends],
    }


def select_wireless_backend(
    *,
    requested_transport: str,
    wallets: Iterable[str],
    support_matrix: Dict[str, object],
) -> Dict[str, object]:
    backends = {
        str(entry["backend_id"]): entry
        for entry in support_matrix.get("backends", [])
        if isinstance(entry, dict)
    }
    requested = (requested_transport or "auto").strip().lower()
    wallet_set = {str(wallet).lower() for wallet in wallets}

    aliases = {
        "android": "android_adb",
        "ios": "ios_companion",
        "apple": "ios_companion",
        "acr": "acr_pcsc",
        "pcsc": "generic_pcsc",
        "generic": "generic_pcsc",
    }

    if requested != "auto":
        backend_id = aliases.get(requested, requested)
        backend = backends.get(backend_id)
        if backend is None:
            return {
                "backend_id": backend_id,
                "available": False,
                "execution_mode": "unsupported",
                "reason": f"Unknown transport '{requested_transport}'",
            }
        return {
            "backend_id": backend["backend_id"],
            "available": bool(backend["available"]),
            "execution_mode": "native" if backend["available"] else "planned",
            "reason": "explicitly requested",
        }

    candidates = []
    if "apple" in wallet_set:
        candidates.append("ios_companion")
    if wallet_set & {"google", "samsung"}:
        candidates.append("android_adb")
    candidates.extend(["acr_pcsc", "generic_pcsc", "ios_companion", "android_adb"])

    seen: set[str] = set()
    for backend_id in candidates:
        if backend_id in seen:
            continue
        seen.add(backend_id)
        backend = backends.get(backend_id)
        if backend and backend.get("available"):
            return {
                "backend_id": backend["backend_id"],
                "available": True,
                "execution_mode": "native",
                "reason": "auto-selected from detected support",
            }

    for backend_id in candidates:
        backend = backends.get(backend_id)
        if backend:
            return {
                "backend_id": backend["backend_id"],
                "available": bool(backend["available"]),
                "execution_mode": "planned",
                "reason": "no native device detected, using planned transport",
            }

    return {
        "backend_id": "generic_pcsc",
        "available": False,
        "execution_mode": "planned",
        "reason": "no supported backend candidates available",
    }


__all__ = [
    "WirelessBackend",
    "build_wireless_support_matrix",
    "detect_adb_available",
    "detect_pcsc_reader_names",
    "ios_companion_available",
    "is_acr_reader",
    "normalize_host_platform",
    "select_wireless_backend",
]
