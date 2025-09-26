#!/usr/bin/env python3
"""
ATM Emulator
------------

Provides a simple ATM emulator that orchestrates a minimal EMV withdrawal
interaction using the EMVTerminalFlow helper.

This is an MVP to exercise hardware and baseline flows; it is intentionally
conservative and focuses on command sequencing, not issuer risk engines.
"""

from typing import Dict, Optional

from emv_data.terminal_flows import EMVTerminalFlow


class ATMEmulator:
    def __init__(self, reader: Optional[str] = None, verbose: bool = False):
        self.flow = EMVTerminalFlow(reader=reader, verbose=verbose)

    def list_readers(self):
        return self.flow.list_readers()

    def withdraw(self, amount_cents: int, pin: Optional[str] = None) -> Dict:
        return self.flow.run_withdrawal(amount_cents=amount_cents, pin=pin)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ATM Emulator")
    parser.add_argument("amount", type=float, help="Withdrawal amount in currency units (e.g., 20.00)")
    parser.add_argument("--reader", help="PC/SC reader name")
    parser.add_argument("--pin", help="PIN to verify (plaintext demo)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    emulator = ATMEmulator(reader=args.reader, verbose=args.verbose)
    summary = emulator.withdraw(int(round(args.amount * 100)), pin=args.pin)
    print(summary)


if __name__ == "__main__":
    main()
