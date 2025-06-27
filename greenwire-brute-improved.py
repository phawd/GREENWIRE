#!/usr/bin/env python3
"""GREENWIRE command line interface.

A simplified entry point for performing smartcard fuzzing, NFC tasks and
EMV terminal/card emulation.

[EMULATION] This script supports wireless terminal mode (--wireless) and
optional Dynamic Data Authentication (--dda).
"""

from __future__ import annotations

import argparse
import logging
from typing import List

from greenwire.core.fuzzer import SmartcardFuzzer
from greenwire.core.nfc_emv import (
    NFCEMVProcessor,
    ContactlessEMVTerminal,
    CAPublicKey,
    load_ca_keys,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GREENWIRE CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    fuzz = sub.add_parser("fuzz", help="Run smartcard fuzzing")
    fuzz.add_argument("--iterations", type=int, default=1)
    fuzz.add_argument("--contactless-fuzz", action="store_true")
    fuzz.add_argument("--aids", type=str, help="Comma separated AIDs")
    fuzz.add_argument("--ca-file", type=str, help="CA key JSON file")

    nfc = sub.add_parser("nfc", help="Perform NFC operations")
    nfc.add_argument(
        "action",
        choices=["read-uid", "read-block", "write-block", "scan"],
    )
    nfc.add_argument("--block", type=int)
    nfc.add_argument("--data", type=str)

    emu = sub.add_parser("emulate", help="Emulate terminal or card")
    emu.add_argument("mode", choices=["terminal", "card"])
    emu.add_argument("--wireless", action="store_true")
    emu.add_argument("--aids", type=str)
    emu.add_argument("--ca-file", type=str)
    emu.add_argument("--issuer", type=str)
    emu.add_argument("--dda", action="store_true")

    return parser.parse_args()


def run_fuzz(args: argparse.Namespace) -> None:
    fuzzer = SmartcardFuzzer({"dry_run": True})
    if args.contactless_fuzz:
        aids: List[str] = (
            [a.strip() for a in args.aids.split(",") if a.strip()] if args.aids else ["A0000000031010"]
        )
        results = fuzzer.fuzz_contactless(aids, args.iterations, args.ca_file)
        for res in results:
            print(f"AID {res['aid']} SELECT {res['select'].hex()} GPO {res['gpo'].hex()}")
    else:
        out = fuzzer.simulate_attack_scenario("SDA_DOWNGRADE")
        print(out)


def run_nfc(args: argparse.Namespace) -> None:
    proc = NFCEMVProcessor()
    if args.action == "read-uid":
        uid = proc.read_uid()
        print(uid or "No tag")
    elif args.action == "read-block":
        if args.block is None:
            raise SystemExit("--block required")
        data = proc.read_block(args.block)
        print(data.hex())
    elif args.action == "write-block":
        if args.block is None or args.data is None:
            raise SystemExit("--block and --data required")
        proc.write_block(args.block, bytes.fromhex(args.data))
    elif args.action == "scan":
        from greenwire.nfc_vuln import scan_nfc_vulnerabilities
        vulns = scan_nfc_vulnerabilities(proc)
        if vulns:
            for v in vulns:
                print(v)
        else:
            print("No vulnerabilities detected")


def run_emulation(args: argparse.Namespace) -> None:
    if args.mode == "terminal":
        aids = [a.strip() for a in args.aids.split(",")] if args.aids else ["A0000000031010"]
        ca = {k: CAPublicKey(**v) for k, v in load_ca_keys(args.ca_file).items()} if args.ca_file else None
        term = ContactlessEMVTerminal(aids, ca_keys=ca) if args.wireless else None
        if term:
            for res in term.run():
                print(f"AID {res['aid']} SELECT {res['select'].hex()} GPO {res['gpo'].hex()}")
        else:
            print("Terminal emulation requires --wireless for contactless demo")
    else:
        print("Card emulation requires hardware and nfcpy support")


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.command == "fuzz":
        run_fuzz(args)
    elif args.command == "nfc":
        run_nfc(args)
    elif args.command == "emulate":
        run_emulation(args)


if __name__ == "__main__":
    main()

