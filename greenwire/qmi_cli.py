"""Wrapper around the external ``qmicli`` command line utility."""

from __future__ import annotations

import subprocess
from typing import List, Optional


def _run_qmicli(args: List[str]) -> str:
    """Run ``qmicli`` with ``args`` and return stdout."""
    cmd = ["qmicli"] + args
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.stdout.strip()


def get_device_ids(device: str = "/dev/cdc-wdm0") -> str:
    """Return device identifiers using ``--dms-get-ids``."""
    return _run_qmicli(["-d", device, "--dms-get-ids"])


def get_signal_strength(device: str = "/dev/cdc-wdm0") -> str:
    """Return signal strength using ``--nas-get-signal-strength``."""
    return _run_qmicli(["-d", device, "--nas-get-signal-strength"])


def send_raw_message(message: str, device: str = "/dev/cdc-wdm0") -> str:
    """Send a raw QMI message in hex format."""
    return _run_qmicli(["-d", device, "--device-open-proxy", f"--qmi-proxy={message}"])


def main(argv: Optional[List[str]] = None) -> None:
    import argparse

    parser = argparse.ArgumentParser(description="qmicli wrapper")
    parser.add_argument("command", choices=["ids", "signal", "raw"])
    parser.add_argument("--device", default="/dev/cdc-wdm0")
    parser.add_argument("message", nargs="?", help="hex data for raw mode")
    args = parser.parse_args(argv)

    if args.command == "ids":
        print(get_device_ids(args.device))
    elif args.command == "signal":
        print(get_signal_strength(args.device))
    else:
        if not args.message:
            parser.error("raw command requires message argument")
        print(send_raw_message(args.message, args.device))


if __name__ == "__main__":  # pragma: no cover - manual CLI
    main()
