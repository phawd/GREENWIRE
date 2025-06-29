#!/usr/bin/env python3

import argparse
import sys
from greenwire.core import fuzzer
from greenwire.core.backend import init_backend, generate_certifications

def main():
    parser = argparse.ArgumentParser(description="Greenwire EMV/JCOP Smartcard Fuzzer CLI")
    parser.add_argument('--dry-run', action='store_true', help='Simulate actions without card access')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--attack', type=str, help='Run a specific attack scenario (e.g., SDA_DOWNGRADE)')
    parser.add_argument('--compliance', type=str, help='Check compliance with a specific EMV standard (e.g., EMV_BOOK2)')
    parser.add_argument('--section', type=str, help='Section of the EMV standard to check')
    # JCOP/JavaCard-specific options
    parser.add_argument('--jcop-issue', action='store_true', help='Issue a DDA-compliant JCOP card')
    parser.add_argument('--jcop-read', action='store_true', help='Read data from a JCOP card')
    parser.add_argument('--jcop-fuzz', action='store_true', help='Fuzz APDU commands on JCOP card')
    parser.add_argument('--card-type', type=str, help='Card type (visa, mc, amex, etc.)')
    parser.add_argument('--lun', type=str, help='Logical Unit Number (LUN) for card, optional')
    parser.add_argument('--key-data', type=str, help='Key data for DDA issuance')
    parser.add_argument('--fuzz', action='store_true', help='Run fuzzing operations')
    parser.add_argument('--fuzz-pattern', type=str, help='Specify a fuzzing pattern')
    parser.add_argument('--fuzz-iterations', type=int, help='Number of iterations for fuzzing')
    parser.add_argument('--emv-command', type=str, help='EMV command for transaction verification')
    parser.add_argument('--auth-data', type=str, help='Authentication data for CVM')
    parser.add_argument('--nfc-data', type=str, help='Data for NFC4 wireless test')
    args = parser.parse_args()

    conn = init_backend()
    cards = generate_certifications(conn)
    print("Generated sample certifications:")
    for card in cards:
        print(card)

    options = {'dry_run': args.dry_run, 'verbose': args.verbose}
    try:
        fuzz = fuzzer.SmartcardFuzzer(options)
    except Exception as e:
        print(f"[ERROR] Could not initialize SmartcardFuzzer: {e}")
        sys.exit(1)

    # JCOP/JavaCard CLI options
    if args.jcop_issue:
        card_type = args.card_type or input("Enter card type (visa, mc, amex, etc.): ")
        lun = args.lun or input("Enter LUN (leave blank for random): ")
        key_data = args.key_data or input("Enter key data for DDA issuance: ")
        try:
            result = fuzz.issue_jcop_card(card_type, lun, key_data)
            print("JCOP card issuance result:", result)
        except Exception as e:
            print(f"[ERROR] JCOP card issuance failed: {e}")
    elif args.jcop_read:
        try:
            result = fuzz.read_jcop_card()
            print("JCOP card read result:", result)
        except Exception as e:
            print(f"[ERROR] JCOP card read failed: {e}")
    elif args.jcop_fuzz:
        fuzz_pattern = args.fuzz_pattern or input("Enter APDU fuzz pattern: ")
        try:
            result = fuzz.fuzz_jcop_apdu(fuzz_pattern)
            print("JCOP APDU fuzz result:", result)
        except Exception as e:
            print(f"[ERROR] JCOP APDU fuzz failed: {e}")
    # EMV/attack/compliance options
    elif args.attack:
        try:
            result = fuzz.simulate_attack_scenario(args.attack)
            print("Attack scenario result:", result)
        except Exception as e:
            print(f"[ERROR] Attack scenario failed: {e}")
    elif args.compliance:
        try:
            result = fuzz.check_standard_compliance(args.compliance, args.section)
            print("Compliance check result:", result)
        except Exception as e:
            print(f"[ERROR] Compliance check failed: {e}")
    elif args.fuzz:
        fuzz_pattern = args.fuzz_pattern or input("Enter fuzzing pattern: ")
        iterations = args.fuzz_iterations or int(input("Enter number of iterations: "))
        try:
            result = fuzz.run_fuzzing(fuzz_pattern, iterations)
            print("Fuzzing result:", result)
        except Exception as e:
            print(f"[ERROR] Fuzzing failed: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
