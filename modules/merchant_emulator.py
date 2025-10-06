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
        # 5. Run purchase (which will also extract CDOL via AFL records)
        # If CVM list present and offline PIN required, prompt for PIN if not supplied
        offline_pin_required = False
        if cvm_list:
            # EMV CVM list parsing: look for 0x01 (plaintext offline PIN) or 0x02 (enciphered offline PIN)
            if '01' in cvm_list or '02' in cvm_list:
                offline_pin_required = True
        if offline_pin_required and not pin:
            print("Offline PIN required by card. Please enter PIN:")
            pin = getpass.getpass("Enter PIN: ")
        summary = self.flow.run_purchase(amount_cents=amount_cents, pin=pin)
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
        summary['offline_pin_required'] = offline_pin_required
        return summary


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
    print("\n--- EMV Terminal/Card Info ---")
    print(f"ATR: {summary.get('atr')}")
    print(f"Card Type: {summary.get('card_type')}")
    print(f"PDOL: {summary.get('pdol')}")
    print(f"CDOL1: {summary.get('cdol1')}")
    print(f"CDOL2: {summary.get('cdol2')}")
    print(f"TTQ: {summary.get('ttq')}")
    print(f"CVM List: {summary.get('cvm_list')}")
    if summary.get('offline_pin_required'):
        print("Offline PIN was required and processed.")
    print("\n--- Transaction Summary ---")
    print(summary)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nMerchant emulator stopped.")
    except Exception as e:
        print(f"Error: {e}")
