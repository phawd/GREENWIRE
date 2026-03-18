"""Reference GlobalPlatform test keys and public tooling metadata.

This module centralizes the non-production card manager keys that GREENWIRE
uses for emulator and lab workflows. The values here are public test material
documented by GlobalPlatformPro and related JavaCard development references.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List


GP_DEFAULT_TEST_KEY = "404142434445464748494A4B4C4D4E4F"
GEMALTO_VISA2_TEST_KEY = "47454D5850524553534F53414D504C45"

GP_ORACLE_DOWNLOADS_PAGE = "https://www.oracle.com/java/technologies/javacard-downloads.html"
GP_GITHUB_RELEASE_URL = "https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar"


@dataclass(frozen=True)
class GPTestKeyProfile:
    """Public non-production key profile for lab and emulator use."""

    name: str
    key_hex: str
    diversification: str
    protocols: List[str]
    source: str
    notes: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


TEST_KEY_PROFILES: Dict[str, GPTestKeyProfile] = {
    "default": GPTestKeyProfile(
        name="default",
        key_hex=GP_DEFAULT_TEST_KEY,
        diversification="none",
        protocols=["scp01", "scp02", "scp03"],
        source="GlobalPlatformPro wiki",
        notes="GPPro uses the 40..4F lab key by default when `-key default` is omitted.",
    ),
    "emv_default": GPTestKeyProfile(
        name="emv_default",
        key_hex=GP_DEFAULT_TEST_KEY,
        diversification="emv",
        protocols=["scp02"],
        source="GlobalPlatformPro wiki",
        notes="Use as `-key emv:default` for EMV diversification from INITIALIZE UPDATE data.",
    ),
    "gemalto_visa2": GPTestKeyProfile(
        name="gemalto_visa2",
        key_hex=GEMALTO_VISA2_TEST_KEY,
        diversification="visa2",
        protocols=["scp02"],
        source="GlobalPlatformPro wiki",
        notes="Documented sample VISA2 master key used on many Thales/Gemalto development cards.",
    ),
}


def get_test_key_profile(name: str = "default") -> GPTestKeyProfile:
    return TEST_KEY_PROFILES[name]


def list_test_key_profiles() -> List[Dict[str, object]]:
    return [profile.to_dict() for profile in TEST_KEY_PROFILES.values()]


def common_test_keys() -> List[str]:
    """Return the well-known GP lab keys first, then compatibility aliases."""

    return [
        GP_DEFAULT_TEST_KEY,
        GEMALTO_VISA2_TEST_KEY,
        "000102030405060708090A0B0C0D0E0F",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "00000000000000000000000000000000",
        "0123456789ABCDEF0123456789ABCDEF",
        "FEDCBA9876543210FEDCBA9876543210",
    ]


def gp_jar_candidates(root: Path | str | None = None) -> List[Path]:
    """Return likely GlobalPlatformPro jar locations in repository order."""

    base = Path(root) if root is not None else Path.cwd()
    return [
        base / "static" / "java" / "gp.jar",
        base / "lib" / "GlobalPlatformPro.jar",
        base / "lib" / "gp.jar",
        base / "gp.jar",
    ]


def resolve_gp_jar(root: Path | str | None = None) -> Path | None:
    """Resolve the first available GlobalPlatformPro jar without machine-specific paths."""

    for candidate in gp_jar_candidates(root):
        if candidate.exists():
            return candidate
    return None


__all__ = [
    "GEMALTO_VISA2_TEST_KEY",
    "GP_DEFAULT_TEST_KEY",
    "GP_GITHUB_RELEASE_URL",
    "GP_ORACLE_DOWNLOADS_PAGE",
    "GPTestKeyProfile",
    "TEST_KEY_PROFILES",
    "common_test_keys",
    "gp_jar_candidates",
    "get_test_key_profile",
    "list_test_key_profiles",
    "resolve_gp_jar",
]
