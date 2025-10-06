"""Tree-based interactive CLI for GREENWIRE operations.

This script presents a hierarchical menu where the user first selects a
standard/card type and then chooses an action specific to that
selection.  It reuses helpers from ``menu_cli`` and ``crypto_engine``.
"""

from __future__ import annotations  # noqa: F401

import argparse
from typing import Callable, Dict

from greenwire.core.crypto_engine import generate_ec_key, generate_rsa_key
from greenwire.core.nfc_emv import ContactlessEMVTerminal
from greenwire.core.standards import Standard
from greenwire.menu_cli import brute_force_pin, detect_card_os, dump_atr, dump_filesystem, dump_memory, export_data, fuzz_apdu, fuzz_transaction, import_data, reset_card, scan_for_cards
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


# Mapping of menu actions
Action = Callable[[], None]

MENU_TREE: Dict[str, Dict[str, tuple[str, Action]]] = {
    Standard.EMV.value: {
        "1": ("Terminal test", _terminal_test),
        "2": ("ATM/HSM test", _atm_hsm_test),
        "3": ("Generate certificates", _generate_cert),
    },
    "Card Ops": {
        "1": ("Dump ATR", dump_atr),
        "2": ("Dump memory", dump_memory),
        "3": ("Brute force PIN", brute_force_pin),
        "4": ("Fuzz APDU", fuzz_apdu),
        "5": ("Fuzz transaction", fuzz_transaction),
        "6": ("Scan for cards", scan_for_cards),
        "7": ("Dump filesystem", dump_filesystem),
        "8": ("Export DB", lambda: export_data(init_backend())),
        "9": ("Import DB", import_data),
        "10": ("Reset card", reset_card),
        "11": ("Detect card OS", detect_card_os),
    },
}

# ---------------------------------------------------------------------------
# Menu helpers
# ---------------------------------------------------------------------------


def _print_menu(options: Dict[str, tuple[str, Action]]) -> None:
    print(f"({len(options)} options)")
    for key, (label, _) in sorted(options.items(), key=lambda x: int(x[0])):
        print(f"{key}. {label}")


def run_tree_cli() -> None:
    """Entry point for the tree-based menu."""
    parser = argparse.ArgumentParser(description="GREENWIRE tree menu")
    parser.add_argument("--db", default="card_data.db")
    args = parser.parse_args()

    conn = init_backend(args.db)
    while True:
        print(f"\nSelect standard/card type ({len(MENU_TREE)} categories):")
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
            if func in {export_data}:
                func(conn)  # requires db connection
            else:
                func()


if __name__ == "__main__":
    run_tree_cli()
