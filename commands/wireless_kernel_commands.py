from __future__ import annotations

import argparse

from core.wireless_kernel_profiles import (
    build_wireless_kernel_examples,
    get_wireless_kernel,
    infer_wireless_kernel,
    list_wireless_kernels,
    simulate_wireless_decision,
)
from greenwire_modern import CommandResult, GreenwireCLI


def wireless_kernel_command(args: argparse.Namespace) -> CommandResult:
    action = args.wireless_action
    if action == "list":
        return CommandResult(True, "Wireless kernel profiles listed", data={"kernels": list_wireless_kernels()})
    if action == "examples":
        return CommandResult(True, "Wireless kernel examples listed", data={"examples": build_wireless_kernel_examples()})
    if action == "show":
        profile = get_wireless_kernel(args.profile)
        return CommandResult(True, "Wireless kernel profile loaded", data={"kernel": profile.to_dict()})
    if action == "infer":
        profile = infer_wireless_kernel(
            scheme=args.scheme,
            merchant_mode=args.merchant_mode,
            hsm_mode=args.hsm_mode,
            channel=args.channel,
        )
        return CommandResult(True, "Wireless kernel inferred", data={"kernel": profile.to_dict()})

    simulation = simulate_wireless_decision(
        profile_id=args.profile,
        amount_cents=args.amount_cents,
        channel=args.channel,
        cdcvm=args.cdcvm,
        force_online=args.force_online,
    )
    return CommandResult(True, "Wireless kernel simulation completed", data=simulation)


def register_wireless_kernel_commands(cli: GreenwireCLI) -> None:
    cli.register_command(
        name="wireless-kernel",
        func=wireless_kernel_command,
        description="List, infer, and simulate GREENWIRE wireless emulator kernels",
        args=[
            {"name": "wireless_action", "choices": ["list", "show", "infer", "simulate", "examples"]},
            {"name": "--profile", "choices": ["gw_retail_bridge", "gw_transit_wave", "gw_secure_vault", "gw_lab_chaos"], "default": "gw_retail_bridge"},
            {"name": "--scheme", "type": str, "help": "Scheme hint for kernel inference"},
            {"name": "--merchant-mode", "type": str, "help": "Merchant mode hint such as retail or transit"},
            {"name": "--hsm-mode", "type": str, "help": "HSM mode hint such as scp03 or secure"},
            {"name": "--channel", "choices": ["nfc", "rfid", "merchant", "hsm", "atm", "gp", "jcop"], "default": "nfc"},
            {"name": "--amount-cents", "type": int, "default": 1000},
            {"name": "--cdcvm", "action": "store_true"},
            {"name": "--force-online", "action": "store_true"},
        ],
        aliases=["wireless", "kernel-wireless"],
    )
