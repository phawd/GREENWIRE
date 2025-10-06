#!/usr/bin/env python3
"""
EMV CLI wrapper: programmatic, non-interactive operations for EMV CA and key management.

Commands:
  emv_cli.py gen-root --out-dir ca --common-name "Greenwire Root CA" --rsa-size 4096
  emv_cli.py gen-intermediate --out-dir ca --common-name "Greenwire Int CA" --rsa-size 2048
  emv_cli.py issue-card --out-dir ca/cards --count 5 --bank "Example Bank" --merchant "Example Merchant"
  emv_cli.py issue-terminal --out-dir ca/terminals --common-name "POS Terminal 1"

This script calls `core.emv_auth` functions and writes PEMs and minimal SDA artifacts.
"""
import argparse
from pathlib import Path
import sys

# locate project root heuristically
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import emv_auth


def write_file(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print('Wrote', path)


def cmd_gen_root(args):
    key = emv_auth.generate_rsa_key(args.rsa_size)
    cert = emv_auth.build_self_signed_cert(key, subject_name=args.common_name)

    write_file(Path(args.out_dir) / 'root-ca.key.pem', emv_auth.serialize_private_key_pem(key))
    write_file(Path(args.out_dir) / 'root-ca.pem', emv_auth.serialize_cert_pem(cert))


def cmd_gen_intermediate(args):
    key = emv_auth.generate_rsa_key(args.rsa_size)
    cert = emv_auth.build_self_signed_cert(key, subject_name=args.common_name)
    write_file(Path(args.out_dir) / 'intermediate-ca.key.pem', emv_auth.serialize_private_key_pem(key))
    write_file(Path(args.out_dir) / 'intermediate-ca.pem', emv_auth.serialize_cert_pem(cert))


def cmd_issue_card(args):
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for i in range(1, args.count + 1):
        cn = f"{args.bank} Card {i}"
        key = emv_auth.generate_rsa_key(2048)
        cert = emv_auth.build_self_signed_cert(key, subject_name=cn)
        write_file(out_dir / f'card-{i}.key.pem', emv_auth.serialize_private_key_pem(key))
        write_file(out_dir / f'card-{i}.pem', emv_auth.serialize_cert_pem(cert))
        # produce a simple static auth data blob (SDA-like) for testing
        sda = emv_auth.emv_create_static_auth_data(cert, issuer=args.bank, holder=cn, merchant=args.merchant)
        write_file(out_dir / f'card-{i}.sda', sda)


def cmd_issue_terminal(args):
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key = emv_auth.generate_rsa_key(2048)
    cert = emv_auth.build_self_signed_cert(key, subject_name=args.common_name)
    write_file(out_dir / 'terminal.key.pem', emv_auth.serialize_private_key_pem(key))
    write_file(out_dir / 'terminal.pem', emv_auth.serialize_cert_pem(cert))


def main():
    p = argparse.ArgumentParser(prog='emv_cli')
    sp = p.add_subparsers(dest='cmd')

    a = sp.add_parser('gen-root')
    a.add_argument('--out-dir', default='ca')
    a.add_argument('--common-name', default='Greenwire Root CA')
    a.add_argument('--rsa-size', type=int, default=4096)
    a.set_defaults(func=cmd_gen_root)

    a = sp.add_parser('gen-intermediate')
    a.add_argument('--out-dir', default='ca')
    a.add_argument('--common-name', default='Greenwire Intermediate CA')
    a.add_argument('--rsa-size', type=int, default=2048)
    a.set_defaults(func=cmd_gen_intermediate)

    a = sp.add_parser('issue-card')
    a.add_argument('--out-dir', default='ca/cards')
    a.add_argument('--count', type=int, default=1)
    a.add_argument('--bank', default='Example Bank')
    a.add_argument('--merchant', default='Example Merchant')
    a.set_defaults(func=cmd_issue_card)

    a = sp.add_parser('issue-terminal')
    a.add_argument('--out-dir', default='ca/terminals')
    a.add_argument('--common-name', default='POS Terminal 1')
    a.set_defaults(func=cmd_issue_terminal)

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        return 2
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
