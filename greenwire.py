#!/usr/bin/env python3

import argparse
import sys
from greenwire.core import fuzzer

def main():
    parser = argparse.ArgumentParser(description="Greenwire EMV Smartcard Fuzzer CLI")
    parser.add_argument('--dry-run', action='store_true', help='Simulate actions without card access')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--attack', type=str, help='Run a specific attack scenario (e.g., SDA_DOWNGRADE)')
    parser.add_argument('--compliance', type=str, help='Check compliance with a specific EMV standard (e.g., EMV_BOOK2)')
    parser.add_argument('--section', type=str, help='Section of the EMV standard to check')
    args = parser.parse_args()

    options = {'dry_run': args.dry_run, 'verbose': args.verbose}
    fuzz = fuzzer.SmartcardFuzzer(options)

    if args.attack:
        result = fuzz.simulate_attack_scenario(args.attack)
        print("Attack scenario result:", result)
    elif args.compliance:
        result = fuzz.check_standard_compliance(args.compliance, args.section)
        print("Compliance check result:", result)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
