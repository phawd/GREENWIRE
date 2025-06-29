"""Tree-based interactive CLI for GREENWIRE operations.

This script presents a hierarchical menu where the user first selects a
standard/card type and then chooses an action specific to that
selection.  It reuses helpers from ``menu_cli`` and ``crypto_engine``.

Hardware support includes PC/SC readers such as ACR122U, PN532, and
Android 13+ devices connected over ADB.
"""

from __future__ import annotations

import argparse
from typing import Callable, Dict

from greenwire.core.crypto_engine import generate_rsa_key, generate_ec_key
from greenwire.core.nfc_emv import ContactlessEMVTerminal
from greenwire.core.nfc_iso import AndroidReaderWriter
from greenwire.core.standards import Standard, StandardHandler
from greenwire.menu_cli import (
    dump_atr,
    dump_memory,
    brute_force_pin,
    fuzz_apdu,
    fuzz_transaction,
    scan_for_cards,
    dump_filesystem,
    export_data,
    import_data,
    reset_card,
    detect_card_os,
    jcop_attack,
    hsm_crypto_test,
    nfc_delay_attack,
)
from greenwire.core.backend import init_backend

# ---------------------------------------------------------------------------
# Action implementations
# ---------------------------------------------------------------------------


def _terminal_test() -> None:
    """Perform a minimal EMV transaction as a terminal."""
    terminal = ContactlessEMVTerminal(["A0000000031010"])
    results = terminal.run()
    for res in results:
        print(res)


def _atm_hsm_test() -> None:
    """Placeholder for ATM/HSM specific tests."""
    print("[SIMULATION] Running ATM/HSM test sequence")
    _terminal_test()


def _generate_cert() -> None:
    """Generate a simple RSA and ECC test certificate pair."""
    rsa_key = generate_rsa_key()
    ecc_key = generate_ec_key()
    print(f"Generated RSA modulus bits: {rsa_key.key_size}")
    print(f"Generated ECC curve: {ecc_key.curve.name}")


def _android_connect(root: bool) -> None:
    """Connect to an Android device, printing a status message."""
    reader = AndroidReaderWriter(root_required=root)
    reader.connect()
    mode = "root" if root else "non-root"
    print(f"Connected to Android device ({mode})")
    reader.disconnect()


# Mapping of menu actions
Action = Callable[[], None]


def _make_actions(std: Standard) -> Dict[str, tuple[str, Action]]:
    handler = StandardHandler()

    return {
        "1": (
            "Check compliance",
            lambda s=std: print(handler.check_compliance(s)),
        ),
        "2": ("Handle standard", lambda s=std: print(handler.handle(s))),
        "3": ("Dump ATR", dump_atr),
        "4": ("Scan for cards", scan_for_cards),
    }


MENU_TREE: Dict[str, Dict[str, tuple[str, Action]]] = {
    std.value: _make_actions(std) for std in Standard
}

# Extend EMV entry with extra actions
MENU_TREE[Standard.EMV.value].update({
    "5": ("Terminal test", _terminal_test),
    "6": ("ATM/HSM test", _atm_hsm_test),
    "7": ("Generate certificates", _generate_cert),
})

# Generic card operations
MENU_TREE["General Card Ops"] = {
    "1": ("Dump memory", dump_memory),
    "2": ("Brute force PIN", brute_force_pin),
    "3": ("Fuzz APDU", fuzz_apdu),
    "4": ("Fuzz transaction", fuzz_transaction),
    "5": ("Dump filesystem", dump_filesystem),
    "6": ("Export DB", lambda: export_data(init_backend())),
    "7": ("Import DB", import_data),
    "8": ("Reset card", reset_card),
    "9": ("Detect card OS", detect_card_os),
    "10": ("Android connect (root)", lambda: _android_connect(True)),
    "11": ("Android connect (non-root)", lambda: _android_connect(False)),
    "12": ("JCOP card attack", jcop_attack),
    "13": ("HSM crypto test", hsm_crypto_test),
    "14": ("NFC delay attack", nfc_delay_attack),
}

# ---------------------------------------------------------------------------
# Menu helpers
# ---------------------------------------------------------------------------


def _print_menu(options: Dict[str, tuple[str, Action]]) -> None:
    for key, (label, _) in sorted(options.items(), key=lambda x: int(x[0])):
        print(f"{key}. {label}")


def run_tree_cli() -> None:
    """Entry point for the tree-based menu."""
    parser = argparse.ArgumentParser(description="GREENWIRE tree menu")
    parser.add_argument("--db", default="card_data.db")
    args = parser.parse_args()  # noqa: F841 - reserved for future DB selection

    while True:
        print("\nSelect standard/card type:")
        for i, std in enumerate(MENU_TREE, start=1):
            print(f"{i}. {std}")
        print("Q. Quit")
        choice = input("Choice: ").strip().upper()
        if choice == "Q":
            break
        try:
            selected = list(MENU_TREE.keys())[int(choice) - 1]
        except (IndexError, ValueError):
            print("Invalid selection")
            continue

        actions = MENU_TREE[selected]
        while True:
            print(f"\n-- {selected} --")
            _print_menu(actions)
            print("B. Back")
            opt = input("Select action: ").strip().upper()
            if opt == "B":
                break
            action = actions.get(opt)
            if not action:
                print("Invalid option")
                continue
            label, func = action
            print(f"[RUNNING] {label}")
            func()


if __name__ == "__main__":
    run_tree_cli()
