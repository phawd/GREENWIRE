#!/usr/bin/env python3
"""
Merchant Emulator
-----------------

Provides a minimal EMV purchase flow using EMVTerminalFlow. This module focuses
on exercising card interactions through PC/SC and validating baseline parsing.
"""

from typing import Dict, Optional

from emv_data.terminal_flows import EMVTerminalFlow


class MerchantEmulator:
    def __init__(self, reader: Optional[str] = None, verbose: bool = False):
        self.flow = EMVTerminalFlow(reader=reader, verbose=verbose)

    def list_readers(self):
        return self.flow.list_readers()

    def purchase(self, amount_cents: int, pin: Optional[str] = None) -> Dict:
        return self.flow.run_purchase(amount_cents=amount_cents, pin=pin)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Merchant Emulator")
    parser.add_argument("amount", type=float, help="Purchase amount in currency units (e.g., 9.99)")
    parser.add_argument("--reader", help="PC/SC reader name")
    parser.add_argument("--pin", help="PIN to verify (plaintext demo)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    emulator = MerchantEmulator(reader=args.reader, verbose=args.verbose)
    summary = emulator.purchase(int(round(args.amount * 100)), pin=args.pin)
    print(summary)


if __name__ == "__main__":
    main()
