from __future__ import annotations

"""Interactive standards menu for GREENWIRE."""

from typing import List

from .core.standards import Standard, StandardHandler

# Categories of standards
WIRED_STANDARDS: List[Standard] = [
    Standard.ISO_IEC_7810,
    Standard.ISO_IEC_7816,
    Standard.ISO_7816_T0_T1,
    Standard.EMV,
    Standard.GLOBALPLATFORM,
    Standard.GLOBALPLATFORM_ISSUER,
    Standard.GLOBALPLATFORM_CARDHOLDER,
    Standard.CARD_OS,
    Standard.ICAO_9303,
]

WIRELESS_STANDARDS: List[Standard] = [
    Standard.ISO_IEC_18000,
    Standard.ISO_IEC_15693,
    Standard.EPCGLOBAL,
    Standard.ISO_IEC_29167,
    Standard.ISO_14443,
    Standard.ISO_18092,
    Standard.NDEF,
    Standard.LLCP,
    Standard.RTD,
    Standard.SNEP,
]


def _run_category(name: str, standards: List[Standard]) -> None:
    handler = StandardHandler()
    while True:
        print(f"{name} Standards")
        for i, std in enumerate(standards, start=1):
            print(f" {i}. {std.value}")
        print(f" {len(standards) + 1}. Back")
        choice = input("Select standard: ").strip()
        if choice == str(len(standards) + 1):
            break
        try:
            idx = int(choice) - 1
        except ValueError:
            print("Invalid choice")
            continue
        if 0 <= idx < len(standards):
            msg = handler.check_compliance(standards[idx])
            print(msg)
        else:
            print("Invalid choice")


def main() -> None:
    while True:
        print("Standards Menu")
        print(" 1. Wired")
        print(" 2. Wireless")
        print(" 3. Quit")
        choice = input("Select option: ").strip()
        if choice == "1":
            _run_category("Wired", WIRED_STANDARDS)
        elif choice == "2":
            _run_category("Wireless", WIRELESS_STANDARDS)
        elif choice == "3":
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
