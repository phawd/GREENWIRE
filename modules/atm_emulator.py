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
        import getpass
        # 1. Get ATR
        atr = self.flow.get_atr()
        # 2. Select PPSE and AID to get FCI
        data, ok = self.flow._select_ppse()
        aid, fci = self.flow._select_aid(self.flow.DEFAULT_PREFERRED_AIDS)
        # 3. Card type report
        card_type_info = self.flow.report_card_type(fci_data=fci, aid=aid)
        # 4. Extract PDOL
        pdol = self.flow.extract_pdol(fci)
        # 4b. Extract TTQ and CVM list if present
        emv_proc = self.flow.emv_processor
        tlvs = emv_proc.parse_tlv_data(fci)
        ttq = None
        cvm_list = None
        for tlv in tlvs:
            if tlv['tag'] == '9F66':
                ttq = tlv['value'].hex().upper()
            if tlv['tag'] == '8E':
                cvm_list = tlv['value'].hex().upper()
        # 5. Run withdrawal (which will also extract CDOL via AFL records)
        # For ATM withdrawals, PIN is typically required
        if not pin:
            print("PIN required for ATM withdrawal. Please enter PIN:")
            pin = getpass.getpass("Enter PIN: ")
        summary = self.flow.run_withdrawal(amount_cents=amount_cents, pin=pin)
        # 6. Extract CDOL1 from AFL records if possible
        gpo, _ = self.flow._gpo()
        records = self.flow._read_records_from_afl(gpo)
        cdol1 = self.flow.extract_cdol(records, cdol_tag='8C')
        cdol2 = self.flow.extract_cdol(records, cdol_tag='8D')
        # Attach extra info to summary
        summary['atr'] = atr
        summary['card_type'] = card_type_info
        summary['pdol'] = pdol
        summary['cdol1'] = cdol1
        summary['cdol2'] = cdol2
        summary['ttq'] = ttq
        summary['cvm_list'] = cvm_list
        return summary


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
    print("\n--- EMV Terminal/Card Info ---")
    print(f"ATR: {summary.get('atr')}")
    print(f"Card Type: {summary.get('card_type')}")
    print(f"PDOL: {summary.get('pdol')}")
    print(f"CDOL1: {summary.get('cdol1')}")
    print(f"CDOL2: {summary.get('cdol2')}")
    print(f"TTQ: {summary.get('ttq')}")
    print(f"CVM List: {summary.get('cvm_list')}")
    print("\n--- Transaction Summary ---")
    print(summary)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nATM emulator stopped.")
    except Exception as e:
        print(f"Error: {e}")
