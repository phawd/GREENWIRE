from __future__ import annotations

from commands.wallet_commands import wallet_provision
from core.pipeline_providers import EmulatorMobileWalletIntegrator


class _Args:
    wallets = ["google", "apple", "samsung", "generic_nfc", "transit_rfid"]
    card_type = "visa"
    transport = "auto"
    pan = None
    amount = 19.25
    currency = "USD"
    cdcvm = "biometric"
    device_account_id = None
    device_account_number = None
    secure_element_id = None
    uid = None
    transit_agency = None
    simulate_pos = True


def test_wallet_provision_returns_mobile_and_rfid_targets() -> None:
    result = wallet_provision(_Args())
    assert result.success is True
    data = result.data or {}
    wallet_results = data["wallet_results"]
    assert {entry["wallet_type"] for entry in wallet_results} == {
        "google",
        "apple",
        "samsung",
        "generic_nfc",
        "transit_rfid",
    }
    assert "wireless_support" in data
    assert "selected_transport" in data
    assert data["contactless_result"]["status"] == "approved"


def test_wallet_provision_supports_explicit_transport_selection() -> None:
    args = _Args()
    args.transport = "ios"
    result = wallet_provision(args)
    assert result.success is True
    assert result.data["selected_transport"]["backend_id"] == "ios_companion"


def test_mobile_wallet_integrator_supports_extended_targets() -> None:
    integrator = EmulatorMobileWalletIntegrator()
    artifacts = {"pan": "4003123412341234", "track2": "4003123412341234=31122010000000000000"}

    samsung = integrator.provision_samsung_wallet(artifacts=artifacts, device_metadata={})
    generic_nfc = integrator.provision_generic_nfc(artifacts=artifacts, device_metadata={})
    transit = integrator.provision_transit_rfid(artifacts=artifacts, device_metadata={})

    assert samsung.wallet_type == "samsung"
    assert generic_nfc.wallet_type == "generic_nfc"
    assert transit.wallet_type == "transit_rfid"
    assert len(samsung.token_reference) == 24
