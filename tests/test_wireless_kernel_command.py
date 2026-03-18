from __future__ import annotations

from argparse import Namespace

from commands.wireless_kernel_commands import wireless_kernel_command


def test_wireless_kernel_examples_command() -> None:
    result = wireless_kernel_command(
        Namespace(
            wireless_action="examples",
            profile="gw_retail_bridge",
            scheme=None,
            merchant_mode=None,
            hsm_mode=None,
            channel="nfc",
            amount_cents=1000,
            cdcvm=False,
            force_online=False,
        )
    )
    assert result.success is True
    assert result.data["examples"]


def test_wireless_kernel_simulate_command() -> None:
    result = wireless_kernel_command(
        Namespace(
            wireless_action="simulate",
            profile="gw_secure_vault",
            scheme=None,
            merchant_mode=None,
            hsm_mode=None,
            channel="merchant",
            amount_cents=9999,
            cdcvm=False,
            force_online=True,
        )
    )
    assert result.success is True
    assert result.data["decision"]["route"] == "online"
