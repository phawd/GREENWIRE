#!/usr/bin/env python3
"""Smartcard standards profile definitions for GREENWIRE.
Provides lightweight data-only profiles for generating test cards across common platforms.
"""
from __future__ import annotations  # noqa: F401
from dataclasses import dataclass, field
from typing import Any, Dict, List
import secrets
from core.globalplatform_reference import get_test_key_profile
from core.synthetic_identity import generate_pan

@dataclass
class CardProfile:
    name: str
    standard: str
    atref: str
    historical_bytes: str
    aid_list: List[str]
    description: str
    capabilities: List[str]
    kcv: str | None = None
    keys: Dict[str, str] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "standard": self.standard,
            "atr": self.atref,
            "historical_bytes": self.historical_bytes,
            "aids": self.aid_list,
            "description": self.description,
            "capabilities": self.capabilities,
            "kcv": self.kcv,
            "keys": self.keys,
            "extra": self.extra,
        }

def _rand_pan(iin: str = "535522") -> str:
    return generate_pan("mastercard", iin=iin, length=16)

def _gen_key(size_bytes: int) -> str:
    return secrets.token_hex(size_bytes)


def _triple_use_key(key_hex: str) -> Dict[str, str]:
    return {
        "ENC": key_hex,
        "MAC": key_hex,
        "DEK": key_hex,
    }


_DEFAULT_GP = get_test_key_profile("default")
_EMV_GP = get_test_key_profile("emv_default")
_GEMALTO_GP = get_test_key_profile("gemalto_visa2")

# Base profiles
JCOP_PROFILE = CardProfile(
    name="JCOP Test Card",
    standard="JCOP",
    atref="3B FF 18 00 FF 81 31 FE 45 80 31 A0 73 BE 21 13 67 43",
    historical_bytes="80 31 A0 73 BE 21 13 67 43",
    aid_list=["A000000003000000", "A000000151000000"],
    description="General purpose JCOP platform supporting JavaCard 3.x with GlobalPlatform secure channel.",
    capabilities=["javacard3", "globalplatform2.3", "scp02", "scp03", "contactless"],
    kcv=None,
    keys={
        "SCP02_MASTER_KEY": _GEMALTO_GP.key_hex,
        "SCP02_DIVERSIFICATION": _GEMALTO_GP.diversification,
        "SCP03_MASTER_KEY": _DEFAULT_GP.key_hex,
        **{f"SCP03_{name}": value for name, value in _triple_use_key(_DEFAULT_GP.key_hex).items()},
    },
    extra={
        "issuer_country": "US",
        "test_pan": _rand_pan(),
        "cvm": "ALWAYS_APPROVE",
        "gp_profiles": [_GEMALTO_GP.to_dict(), _DEFAULT_GP.to_dict()],
    }
)

DESFIRE_PROFILE = CardProfile(
    name="MIFARE DESFire EV2",
    standard="DESFIRE",
    atref="3B 81 80 01 80 80",
    historical_bytes="80 80",
    aid_list=["A000000396564541"],
    description="High security MIFARE DESFire EV2 platform (simulated baseline).",
    capabilities=["iso14443-4", "aes", "desfire-native"],
    keys={"MASTER_KEY": _gen_key(16)},
    extra={"picc_aid": "000000"}
)

PIV_PROFILE = CardProfile(
    name="PIV Test Card",
    standard="PIV",
    atref="3B 7D 96 00 00 73 C8 40 21 13 67",
    historical_bytes="73 C8 40 21 13 67",
    aid_list=["A000000308000010000100"],
    description="Personal Identity Verification (PIV) card test profile.",
    capabilities=["pkix", "rsa2048", "piv-auth", "piv-pin"],
    keys={"PIV_AUTH": _gen_key(16)},
    extra={"pin": "123456", "puk": "12345678"}
)

GLOBALPLATFORM_TEST_PROFILE = CardProfile(
    name="GP Reference Test Card",
    standard="GLOBALPLATFORM",
    atref="3B 9F 96 81 31 FE 45 80 31 81 66",
    historical_bytes="80 31 81 66",
    aid_list=["A000000151000000", "A0000001515350"],
    description="Generic GlobalPlatform reference with multiple security domains.",
    capabilities=["scp02", "scp03", "delegated-management"],
    keys={
        "SCP02_MASTER_KEY": _EMV_GP.key_hex,
        "SCP02_DIVERSIFICATION": _EMV_GP.diversification,
        "SCP03_MASTER_KEY": _DEFAULT_GP.key_hex,
        **{f"SCP03_{name}": value for name, value in _triple_use_key(_DEFAULT_GP.key_hex).items()},
    },
    extra={
        "life_cycle": "SECURED",
        "gp_profiles": [_DEFAULT_GP.to_dict(), _EMV_GP.to_dict()],
        "scp02_note": "Use SCP02 master key with EMV diversification against INITIALIZE UPDATE data.",
    }
)

PROFILES = [JCOP_PROFILE, DESFIRE_PROFILE, PIV_PROFILE, GLOBALPLATFORM_TEST_PROFILE]
PROFILE_MAP = {p.standard.lower(): p for p in PROFILES}

def list_profiles() -> List[Dict[str, Any]]:
    return [p.to_dict() for p in PROFILES]

def get_profile(standard: str) -> Dict[str, Any] | None:
    return PROFILE_MAP.get(standard.lower()).to_dict() if standard.lower() in PROFILE_MAP else None

__all__ = ["list_profiles", "get_profile", "PROFILES"]
