import argparse
from pathlib import Path
from typing import Callable, Dict, Tuple
"""Simple interactive CLI exposing most GREENWIRE features."""

from greenwire.core.backend import init_backend, issue_card
from greenwire.core.nfc_emv import ContactlessEMVTerminal, NFCEMVProcessor
from greenwire.core.nfc_iso import ISO14443ReaderWriter
from greenwire.nfc_vuln import scan_nfc_vulnerabilities
from greenwire.core.fuzzer import SmartcardFuzzer
from greenwire.core.file_fuzzer import (
    fuzz_image_file,
    fuzz_binary_file,
    fuzz_unusual_input,
)
from greenwire.sms_tools import build_pdu, DEFAULT_SMSC_LIST


MENU_HEADER = "GREENWIRE Menu"


# ---------------------------------------------------------------------------
# Helper functions for each menu option
# ---------------------------------------------------------------------------

def dump_atr() -> None:
    """Attempt to print the card ATR/ATS if available."""
    reader = ISO14443ReaderWriter()
    if reader.connect():
        atr = (
            getattr(reader.tag, "ats", None)
            or getattr(reader.tag, "atr", None)
        )
        if atr:
            print(f"ATR/ATS: {atr.hex()}")
        else:
            print("ATR/ATS not available")
        reader.disconnect()
    else:
        print("No reader or tag detected")


def dump_memory(blocks: int = 16) -> None:
    """Read and display a range of blocks from the card."""
    reader = ISO14443ReaderWriter()
    for blk in range(blocks):
        try:
            data = reader.read_block(blk)
            print(f"Block {blk}: {data.hex()}")
        except Exception as exc:  # noqa: BLE001
            print(f"Error reading block {blk}: {exc}")


def brute_force_pin() -> None:
    """Placeholder for PIN brute forcing."""
    print("[SIMULATION] Bruteforcing PIN ... done (no result)")


def fuzz_apdu() -> None:
    """Placeholder for APDU fuzzing."""
    print("[SIMULATION] Fuzzing APDU commands")


def fuzz_transaction() -> None:
    """Run a contactless fuzzing transaction using SmartcardFuzzer."""
    fuzzer = SmartcardFuzzer({"dry_run": True})
    results = fuzzer.fuzz_contactless(["A0000000031010"], iterations=1)
    for r in results:
        print(r)


def scan_for_cards() -> None:
    """Placeholder for scanning for nearby contactless cards."""
    reader = ISO14443ReaderWriter()
    if reader.connect():
        print("Card detected")
        reader.disconnect()
    else:
        print("No card detected")


def dump_filesystem() -> None:
    """Placeholder for dumping the card filesystem."""
    print("[SIMULATION] Dumping filesystem")


def export_data(conn) -> None:
    """Export card table to JSON."""
    rows = conn.execute("SELECT * FROM cards").fetchall()
    print(rows)


def import_data() -> None:
    """Placeholder for importing card data."""
    print("[SIMULATION] Importing card data")


def reset_card() -> None:
    """Placeholder for card reset."""
    print("[SIMULATION] Resetting card")


def detect_card_os() -> None:
    """Attempt to identify the card OS based on ATR patterns."""
    reader = ISO14443ReaderWriter()
    if reader.connect():
        atr = (
            getattr(reader.tag, "ats", None)
            or getattr(reader.tag, "atr", None)
        )
        if atr and atr.startswith(bytes.fromhex("3B8F")):
            print(f"Detected card OS: JCOP (ATR {atr.hex()})")
        else:
            print(f"Unknown card OS (ATR {atr.hex() if atr else 'N/A'})")
        reader.disconnect()
    else:
        print("No reader or tag detected")


def fuzz_file_menu() -> None:
    """Prompt for a file and fuzz its parser."""
    path = Path(input("Seed file path: ").strip())
    category = input("Type (image/binary/unusual): ").strip().lower()
    if category == "image":
        results = fuzz_image_file(path)
    elif category == "binary":
        results = fuzz_binary_file(path)
    else:
        base = path.read_text(errors="ignore")
        results = fuzz_unusual_input(lambda s: s.encode("utf-8"), base)
    for r in results:
        print(r)


# ---------------------------------------------------------------------------
# Menu option helpers
# ---------------------------------------------------------------------------

def issue_new_card(conn) -> None:
    card = issue_card(conn)
    print("Issued card:\n", card)


def show_card_count(conn) -> None:
    count = conn.execute("SELECT COUNT(*) FROM cards").fetchone()[0]
    print(f"{count} cards stored")


def list_cards(conn) -> None:
    rows = conn.execute(
        "SELECT verification_code, pan_hash FROM cards"
    ).fetchall()
    for row in rows:
        print(row)


def run_contactless_txn() -> None:
    terminal = ContactlessEMVTerminal(["A0000000031010"])
    for res in terminal.run():
        print(res)


def scan_vulnerabilities() -> None:
    reader = ISO14443ReaderWriter()
    vulns = scan_nfc_vulnerabilities(reader)
    if vulns:
        for v in vulns:
            print(v)
    else:
        print("No vulnerabilities detected")


def read_nfc_block() -> None:
    reader = ISO14443ReaderWriter()
    blk = int(input("Block number: "))
    data = reader.read_block(blk)
    print(data.hex())


def write_nfc_block() -> None:
    reader = ISO14443ReaderWriter()
    blk = int(input("Block number: "))
    data = bytes.fromhex(input("Hex data: "))
    reader.write_block(blk, data)
    print("Wrote block")


def show_uid(processor: NFCEMVProcessor) -> None:
    uid = processor.read_uid()
    print(f"UID: {uid}")


def fuzz_pcsc() -> None:
    sf = SmartcardFuzzer({"dry_run": False})
    results = sf.fuzz_pcsc_random()
    for r in results:
        print(r)


def send_sms() -> None:
    """Build and display an SMS PDU."""
    smsc = input("SMSC (blank for default): ").strip()
    if not smsc:
        smsc = DEFAULT_SMSC_LIST[0]
    dest = input("Destination number: ").strip()
    msg = input("Message text: ")
    flash = input("Flash SMS? (y/n): ").strip().lower() == "y"
    stk = input("STK payload? (y/n): ").strip().lower() == "y"
    pdu = build_pdu(dest, msg, smsc=smsc, flash=flash, stk=stk)
    print(f"PDU: {pdu}")


OPTIONS: Dict[str, Tuple[str, Callable[[object, object], None] | None]] = {
    "1": ("Issue new card", lambda conn, proc: issue_new_card(conn)),
    "2": ("Card count", lambda conn, proc: show_card_count(conn)),
    "3": ("List issued cards", lambda conn, proc: list_cards(conn)),
    "4": ("Contactless EMV transaction", lambda conn, proc: run_contactless_txn()),
    "5": ("Scan NFC vulnerabilities", lambda conn, proc: scan_vulnerabilities()),
    "6": ("Fuzz contactless card", lambda conn, proc: fuzz_transaction()),
    "7": ("Read NFC block", lambda conn, proc: read_nfc_block()),
    "8": ("Write NFC block", lambda conn, proc: write_nfc_block()),
    "9": ("Show NFC tag UID", lambda conn, proc: show_uid(proc)),
    "10": ("Dump ATR", lambda conn, proc: dump_atr()),
    "11": ("Dump full card memory", lambda conn, proc: dump_memory()),
    "12": ("Brute force PIN", lambda conn, proc: brute_force_pin()),
    "13": ("Fuzz APDU sequence", lambda conn, proc: fuzz_apdu()),
    "14": ("Fuzz contactless transaction", lambda conn, proc: fuzz_transaction()),
    "15": ("Scan for contactless cards", lambda conn, proc: scan_for_cards()),
    "16": ("Dump card filesystem", lambda conn, proc: dump_filesystem()),
    "17": ("Export card data to JSON", lambda conn, proc: export_data(conn)),
    "18": ("Import card data from JSON", lambda conn, proc: import_data()),
    "19": ("Reset card", lambda conn, proc: reset_card()),
    "20": ("Detect card OS", lambda conn, proc: detect_card_os()),
    "21": ("Fuzz file parser", lambda conn, proc: fuzz_file_menu()),
    "22": ("Random fuzz PC/SC", lambda conn, proc: fuzz_pcsc()),
    "23": ("Build SMS PDU", lambda conn, proc: send_sms()),
    "Q": ("Quit", None),
}

# ---------------------------------------------------------------------------
# Main interactive loop
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="GREENWIRE interactive menu")
    parser.add_argument("--db", default="card_data.db", help="Database path")
    args = parser.parse_args()

    conn = init_backend(Path(args.db))
    processor = NFCEMVProcessor()

    while True:
        print(f"\n{MENU_HEADER} ({len(OPTIONS)} options)")
        for key, (label, _) in OPTIONS.items():
            if key == "Q":
                print("Q. Quit")
            else:
                print(f"{key}. {label}")

        choice = input("Select option: ").strip().upper()
        action = OPTIONS.get(choice)
        if not action:
            print("Invalid choice")
            continue
        label, func = action
        if func is None:
            break
        try:
            func(conn, processor)
        except Exception as exc:  # pragma: no cover - runtime safety
            print(f"Error running {label}: {exc}")


if __name__ == "__main__":
    main()
