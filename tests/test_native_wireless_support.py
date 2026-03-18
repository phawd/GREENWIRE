from __future__ import annotations

from core.native_wireless_support import (
    build_wireless_support_matrix,
    is_acr_reader,
    normalize_host_platform,
    select_wireless_backend,
)


def test_normalize_host_platform_handles_windows_and_linux() -> None:
    assert normalize_host_platform("win32") == "windows"
    assert normalize_host_platform("linux") == "linux"


def test_is_acr_reader_matches_acs_hardware() -> None:
    assert is_acr_reader("ACS ACR1252 1S CL Reader PICC 0") is True
    assert is_acr_reader("Generic PC/SC Reader") is False


def test_build_wireless_support_matrix_reports_android_ios_and_acr() -> None:
    matrix = build_wireless_support_matrix(
        host_platform="linux",
        adb_available=True,
        ios_available=True,
        pcsc_readers=["ACS ACR1252 1S CL Reader PICC 0", "Generic PC/SC Reader"],
    )
    backends = {entry["backend_id"]: entry for entry in matrix["backends"]}
    assert matrix["host_platform"] == "linux"
    assert backends["android_adb"]["available"] is True
    assert backends["ios_companion"]["available"] is True
    assert backends["acr_pcsc"]["available"] is True
    assert backends["generic_pcsc"]["available"] is True


def test_select_wireless_backend_prefers_ios_for_apple_when_available() -> None:
    matrix = build_wireless_support_matrix(
        host_platform="windows",
        adb_available=False,
        ios_available=True,
        pcsc_readers=[],
    )
    selected = select_wireless_backend(
        requested_transport="auto",
        wallets=["apple"],
        support_matrix=matrix,
    )
    assert selected["backend_id"] == "ios_companion"
    assert selected["execution_mode"] == "native"


def test_select_wireless_backend_honors_requested_acr_transport() -> None:
    matrix = build_wireless_support_matrix(
        host_platform="linux",
        adb_available=False,
        ios_available=False,
        pcsc_readers=["ACS ACR1252 1S CL Reader PICC 0"],
    )
    selected = select_wireless_backend(
        requested_transport="acr",
        wallets=["generic_nfc"],
        support_matrix=matrix,
    )
    assert selected["backend_id"] == "acr_pcsc"
    assert selected["available"] is True
