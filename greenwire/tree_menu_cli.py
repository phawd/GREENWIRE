"""Tree-based interactive CLI for GREENWIRE operations.

This script presents a hierarchical menu where the user first selects a
standard/card type and then chooses an action specific to that
selection.  It reuses helpers from ``menu_cli`` and ``crypto_engine``.
"""

from __future__ import annotations

import argparse
from typing import Callable, Dict, Union

from greenwire.core.crypto_engine import generate_rsa_key, generate_ec_key
from greenwire.core.nfc_emv import ContactlessEMVTerminal, NFCEMVProcessor
from greenwire.core.standards import Standard
from greenwire.menu_cli import (
    brute_force_pin,
    detect_card_os,
    dump_atr,
    dump_filesystem,
    dump_memory,
    export_data,
    fuzz_apdu,
    fuzz_file_menu,
    fuzz_pcsc,
    fuzz_transaction,
    import_data,
    issue_new_card,
    list_cards,
    read_nfc_block,
    reset_card,
    run_contactless_txn,
    scan_for_cards,
    scan_vulnerabilities,
    show_card_count,
    show_uid,
    write_nfc_block,
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


# Mapping of menu actions
Action = Callable[[], None]
MenuDict = Dict[str, tuple[str, Union[Action, "MenuDict"]]]


def _build_menu(conn, processor) -> MenuDict:
    """Return the nested menu tree using ``conn`` and ``processor``."""

    def _conn_action(func: Callable[[object], None]) -> Action:
        return lambda: func(conn)

    def _uid_action() -> None:
        show_uid(processor)

    return {
        "1": (
            Standard.EMV.value,
            {
                "1": ("Terminal test", _terminal_test),
                "2": ("ATM/HSM test", _atm_hsm_test),
                "3": ("Generate certificates", _generate_cert),
            },
        ),
        "2": (
            "Card Operations",
            {
                "1": (
                    "Information",
                    {
                        "1": ("Dump ATR", dump_atr),
                        "2": ("Dump memory", dump_memory),
                        "3": ("Show UID", _uid_action),
                        "4": ("Detect card OS", detect_card_os),
                    },
                ),
                "2": (
                    "Fuzzing",
                    {
                        "1": ("Fuzz APDU", fuzz_apdu),
                        "2": ("Fuzz transaction", fuzz_transaction),
                        "3": ("Fuzz file parser", fuzz_file_menu),
                        "4": ("Random PC/SC fuzz", fuzz_pcsc),
                    },
                ),
                "3": (
                    "Database",
                    {
                        "1": ("Issue new card", _conn_action(issue_new_card)),
                        "2": ("Card count", _conn_action(show_card_count)),
                        "3": ("List cards", _conn_action(list_cards)),
                        "4": ("Export DB", _conn_action(export_data)),
                        "5": ("Import DB", import_data),
                    },
                ),
                "4": (
                    "NFC Tools",
                    {
                        "1": ("Read block", read_nfc_block),
                        "2": ("Write block", write_nfc_block),
                        "3": ("Scan for cards", scan_for_cards),
                        "4": ("Reset card", reset_card),
                        "5": ("Scan vulnerabilities", scan_vulnerabilities),
                        "6": ("Dump filesystem", dump_filesystem),
                        "7": ("Contactless transaction", run_contactless_txn),
                    },
                ),
            },
        ),
    }

# ---------------------------------------------------------------------------
# Menu helpers
# ---------------------------------------------------------------------------


def _print_menu(options: MenuDict) -> None:
    print(f"({len(options)} options)")
    for key, (label, _) in sorted(options.items(), key=lambda x: x[0]):
        print(f"{key}. {label}")


def _run_menu(menu: MenuDict, conn, root: bool = False) -> None:
    while True:
        _print_menu(menu)
        print("Q. Quit" if root else "B. Back")
        choice = input("Choice: ").strip().upper()
        if (root and choice == "Q") or (not root and choice == "B"):
            break
        item = menu.get(choice)
        if not item:
            print("Invalid selection")
            continue
        label, target = item
        print(f"[RUNNING] {label}")
        if isinstance(target, dict):
            _run_menu(target, conn)
        else:
            target()


def run_tree_cli() -> None:
    """Entry point for the tree-based menu."""
    parser = argparse.ArgumentParser(description="GREENWIRE tree menu")
    parser.add_argument("--db", default="card_data.db")
    args = parser.parse_args()

    conn = init_backend(args.db)
    processor = NFCEMVProcessor()
    menu = _build_menu(conn, processor)

    _run_menu(menu, conn, root=True)


if __name__ == "__main__":
    run_tree_cli()
