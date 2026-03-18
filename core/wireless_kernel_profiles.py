from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from core.emv_kernel_registry import infer_kernel_from_scheme


@dataclass(frozen=True)
class WirelessKernelProfile:
    profile_id: str
    display_name: str
    base_kernel_id: int
    schemes: tuple[str, ...]
    channels: tuple[str, ...]
    merchant_config: Dict[str, object]
    hsm_config: Dict[str, object]
    atm_config: Dict[str, object]
    ai_biases: Dict[str, object]
    notes: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


WIRELESS_KERNEL_PROFILES: Dict[str, WirelessKernelProfile] = {
    "gw_retail_bridge": WirelessKernelProfile(
        profile_id="gw_retail_bridge",
        display_name="GREENWIRE Retail Bridge Kernel",
        base_kernel_id=8,
        schemes=("visa", "mastercard", "amex", "discover"),
        channels=("nfc", "merchant", "wallet", "gp", "jcop"),
        merchant_config={
            "cvm_floor_limit": 5000,
            "supports_contactless": True,
            "supports_cdcvm": True,
            "fallback_mode": "contact",
            "risk_window": "retail",
        },
        hsm_config={
            "expects_arqc": True,
            "script_window": "post_auth",
            "session_key_mode": "scp02_or_scp03",
            "velocity_weight": "medium",
        },
        atm_config={
            "enabled": False,
            "force_online": False,
        },
        ai_biases={
            "focus": ["cvm_transition", "floor_limit_edge", "wallet_token_binding"],
            "mutation_rate": 0.55,
        },
        notes="General-purpose contactless merchant profile with wallet-aware CVM behavior.",
    ),
    "gw_transit_wave": WirelessKernelProfile(
        profile_id="gw_transit_wave",
        display_name="GREENWIRE Transit Wave Kernel",
        base_kernel_id=8,
        schemes=("emvco", "visa", "mastercard", "cup"),
        channels=("nfc", "rfid", "merchant", "atm"),
        merchant_config={
            "cvm_floor_limit": 0,
            "supports_contactless": True,
            "supports_cdcvm": False,
            "fallback_mode": "deny",
            "risk_window": "transit",
        },
        hsm_config={
            "expects_arqc": True,
            "script_window": "deferred",
            "session_key_mode": "fast_online",
            "velocity_weight": "high",
        },
        atm_config={
            "enabled": True,
            "force_online": True,
        },
        ai_biases={
            "focus": ["tap_latency", "duplicate_tap", "offline_to_online_transition"],
            "mutation_rate": 0.7,
        },
        notes="Low-latency transit and gate-oriented wireless profile with strict replay scrutiny.",
    ),
    "gw_secure_vault": WirelessKernelProfile(
        profile_id="gw_secure_vault",
        display_name="GREENWIRE Secure Vault Kernel",
        base_kernel_id=3,
        schemes=("visa", "mastercard", "amex", "jcb", "discover"),
        channels=("nfc", "merchant", "hsm", "gp", "jcop"),
        merchant_config={
            "cvm_floor_limit": 1,
            "supports_contactless": True,
            "supports_cdcvm": True,
            "fallback_mode": "online_only",
            "risk_window": "high_security",
        },
        hsm_config={
            "expects_arqc": True,
            "script_window": "pre_auth_and_post_auth",
            "session_key_mode": "scp03_preferred",
            "velocity_weight": "very_high",
        },
        atm_config={
            "enabled": True,
            "force_online": True,
        },
        ai_biases={
            "focus": ["arqc_mismatch", "issuer_script_abuse", "secure_channel_downgrade"],
            "mutation_rate": 0.45,
        },
        notes="HSM-centric high-assurance profile intended for secure-channel and issuer-script testing.",
    ),
    "gw_lab_chaos": WirelessKernelProfile(
        profile_id="gw_lab_chaos",
        display_name="GREENWIRE Lab Chaos Kernel",
        base_kernel_id=8,
        schemes=("generic", "emvco", "visa", "mastercard", "amex", "discover", "cup"),
        channels=("nfc", "rfid", "merchant", "hsm", "atm", "gp", "jcop"),
        merchant_config={
            "cvm_floor_limit": 2500,
            "supports_contactless": True,
            "supports_cdcvm": True,
            "fallback_mode": "randomized",
            "risk_window": "lab",
        },
        hsm_config={
            "expects_arqc": True,
            "script_window": "any",
            "session_key_mode": "mixed",
            "velocity_weight": "adaptive",
        },
        atm_config={
            "enabled": True,
            "force_online": False,
        },
        ai_biases={
            "focus": ["pattern_injection", "cvm_downgrade", "kernel_switching", "unexpected_mode"],
            "mutation_rate": 0.9,
        },
        notes="Research-oriented profile for aggressive emulator mutation and cross-channel anomalies.",
    ),
}


def list_wireless_kernels() -> List[Dict[str, object]]:
    return [profile.to_dict() for profile in WIRELESS_KERNEL_PROFILES.values()]


def get_wireless_kernel(profile_id: str) -> WirelessKernelProfile:
    return WIRELESS_KERNEL_PROFILES[profile_id]


def infer_wireless_kernel(
    *,
    scheme: Optional[str] = None,
    merchant_mode: Optional[str] = None,
    hsm_mode: Optional[str] = None,
    channel: Optional[str] = None,
) -> WirelessKernelProfile:
    normalized_channel = (channel or "").lower()
    normalized_merchant = (merchant_mode or "").lower()
    normalized_hsm = (hsm_mode or "").lower()

    if "transit" in normalized_merchant or normalized_channel == "rfid":
        return WIRELESS_KERNEL_PROFILES["gw_transit_wave"]
    if "secure" in normalized_hsm or normalized_hsm == "scp03":
        return WIRELESS_KERNEL_PROFILES["gw_secure_vault"]
    if normalized_merchant in {"chaos", "lab", "fuzz"}:
        return WIRELESS_KERNEL_PROFILES["gw_lab_chaos"]

    scheme_profile = infer_kernel_from_scheme(scheme)
    if scheme_profile.kernel_id in {3, 4, 6}:
        return WIRELESS_KERNEL_PROFILES["gw_retail_bridge"]
    return WIRELESS_KERNEL_PROFILES["gw_lab_chaos"]


def simulate_wireless_decision(
    *,
    profile_id: str,
    amount_cents: int,
    channel: str,
    cdcvm: bool = False,
    force_online: bool = False,
) -> Dict[str, object]:
    profile = get_wireless_kernel(profile_id)
    floor_limit = int(profile.merchant_config.get("cvm_floor_limit", 0))
    atm_enabled = bool(profile.atm_config.get("enabled", False))
    hsm_mode = str(profile.hsm_config.get("session_key_mode", "mixed"))

    cvm_required = amount_cents > floor_limit and floor_limit >= 0
    if cdcvm:
        cvm_result = "cdcvm"
    elif cvm_required:
        cvm_result = "online_pin" if force_online or profile.atm_config.get("force_online") else "offline_pin"
    else:
        cvm_result = "no_cvm"

    route = "online" if force_online or bool(profile.atm_config.get("force_online")) or cvm_required else "offline_allowed"
    if channel == "atm" and not atm_enabled:
        route = "unsupported"

    return {
        "profile_id": profile.profile_id,
        "display_name": profile.display_name,
        "amount_cents": amount_cents,
        "channel": channel,
        "merchant": profile.merchant_config,
        "hsm": profile.hsm_config,
        "atm": profile.atm_config,
        "decision": {
            "cvm_required": cvm_required,
            "cvm_result": cvm_result,
            "route": route,
            "session_key_mode": hsm_mode,
        },
        "ai_biases": profile.ai_biases,
    }


def build_wireless_kernel_examples() -> List[Dict[str, object]]:
    return [
        {
            "use_case": "Retail wallet token acceptance",
            "command": "python greenwire_modern.py wireless-kernel simulate --profile gw_retail_bridge --amount-cents 1250 --channel nfc --cdcvm",
        },
        {
            "use_case": "Transit replay and tap-latency testing",
            "command": "python greenwire_modern.py wireless-kernel simulate --profile gw_transit_wave --amount-cents 275 --channel rfid",
        },
        {
            "use_case": "Secure HSM-first SCP03-oriented testing",
            "command": "python greenwire_modern.py wireless-kernel simulate --profile gw_secure_vault --amount-cents 9999 --channel merchant --force-online",
        },
        {
            "use_case": "Lab chaos mode for AI mutation-heavy testing",
            "command": "python greenwire_modern.py wireless-kernel simulate --profile gw_lab_chaos --amount-cents 3333 --channel nfc --force-online",
        },
    ]


__all__ = [
    "WirelessKernelProfile",
    "WIRELESS_KERNEL_PROFILES",
    "build_wireless_kernel_examples",
    "get_wireless_kernel",
    "infer_wireless_kernel",
    "list_wireless_kernels",
    "simulate_wireless_decision",
]
