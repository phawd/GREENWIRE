from __future__ import annotations

from core.wireless_kernel_profiles import infer_wireless_kernel, simulate_wireless_decision


def test_infer_wireless_kernel_uses_transit_for_rfid() -> None:
    profile = infer_wireless_kernel(scheme="visa", merchant_mode="transit", channel="rfid")
    assert profile.profile_id == "gw_transit_wave"


def test_simulate_wireless_decision_requires_cvm_above_floor() -> None:
    result = simulate_wireless_decision(
        profile_id="gw_retail_bridge",
        amount_cents=6000,
        channel="nfc",
        cdcvm=False,
        force_online=False,
    )
    assert result["decision"]["cvm_required"] is True
    assert result["decision"]["cvm_result"] in {"offline_pin", "online_pin"}
