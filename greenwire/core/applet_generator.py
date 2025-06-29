from __future__ import annotations
"""Generate placeholder JCOP/CardOS EMV applets."""


from pathlib import Path
import argparse
import secrets


APPLET_TEMPLATES = {
    "JCOP": b"JCOP_APPLET",
    "CARDOS": b"CARDOS_APPLET",
    "EMV": b"EMV_APPLET",
}


def generate_applet(os_type: str = "JCOP", aid: str | None = None) -> bytes:
    """Return a binary blob representing a simple applet."""
    template = APPLET_TEMPLATES.get(os_type.upper(), APPLET_TEMPLATES["EMV"])
    if aid is None:
        aid = secrets.token_hex(5).upper()
    return template + bytes.fromhex(aid) + secrets.token_bytes(32)


def save_applet(data: bytes, path: Path) -> None:
    """Save applet data to the specified path."""
    path.write_bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a sample EMV applet")
    parser.add_argument("--os", dest="os_type", default="JCOP",
                        help="Target card OS (JCOP, CardOS, EMV)")
    parser.add_argument("--aid", help="Applet identifier (hex bytes)")
    parser.add_argument("--output", default="applet.cap",
                        help="Output file path")
    args = parser.parse_args()

    blob = generate_applet(args.os_type, args.aid)
    save_applet(blob, Path(args.output))
    print(f"Generated {args.os_type} applet with AID {args.aid or 'random'} -> {args.output}")


if __name__ == "__main__":
    main()
