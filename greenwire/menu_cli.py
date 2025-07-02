import argparse
from pathlib import Path
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


CONFIG = {
    "dump_blocks": 16,
    "fuzz_iterations": 1,
}

HELP_TEXT = """\
GREENWIRE interactive menu

Each option triggers a different smartcard test or NFC operation. Some
functions use values from the configurable settings (see option 24). The
current settings are:
  dump_blocks      Number of blocks read when dumping memory
  fuzz_iterations  Iterations for contactless fuzzing

"""

MENU = """\
GREENWIRE Menu (25 options)
1. Issue new card
2. Card count
3. List issued cards
4. Contactless EMV transaction
5. Scan NFC vulnerabilities
 6. Fuzz contactless card
 7. Read NFC block
 8. Write NFC block
 9. Show NFC tag UID
10. Dump ATR
11. Dump full card memory
12. Brute force PIN (simulated)
13. Fuzz APDU sequence
14. Fuzz contactless transaction
15. Scan for contactless cards
16. Dump card filesystem (simulated)
17. Export card data to JSON
18. Import card data from JSON
19. Reset card (simulated)
20. Detect card OS
21. Fuzz file parser
22. Show APDU log
23. Configure settings
24. Help
25. Quit
"""


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


def dump_memory(blocks: int | None = None) -> None:
    """Read and display a range of blocks from the card."""
    if blocks is None:
        blocks = CONFIG["dump_blocks"]
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


def fuzz_transaction(iterations: int | None = None) -> None:
    """Run a contactless fuzzing transaction using SmartcardFuzzer."""
    if iterations is None:
        iterations = CONFIG["fuzz_iterations"]
    fuzzer = SmartcardFuzzer({"dry_run": True})
    results = fuzzer.fuzz_contactless(
        ["A0000000031010"], iterations=iterations
    )
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


def show_apdu_log(conn) -> None:
    """Display recent APDU commands stored in the database."""
    query = (
        "SELECT timestamp, apdu, response, sw1, sw2 "
        "FROM commands ORDER BY id DESC LIMIT 10"
    )
    rows = conn.execute(query).fetchall()
    if not rows:
        print("No APDU log entries found")
        return
    print("Last 10 APDU exchanges:")
    for ts, apdu, resp, sw1, sw2 in rows:
        print(f"{ts}: APDU {apdu} -> {resp} ({sw1:02X}{sw2:02X})")


def configure_settings() -> None:
    """Allow user to modify global configuration values."""
    try:
        blocks_prompt = (
            f"Blocks to read when dumping memory [{CONFIG['dump_blocks']}]: "
        )
        blocks = int(input(blocks_prompt) or CONFIG["dump_blocks"])
        iters_prompt = (
            f"Fuzz iterations for transactions [{CONFIG['fuzz_iterations']}]: "
        )
        iters = int(input(iters_prompt) or CONFIG["fuzz_iterations"])
        CONFIG["dump_blocks"] = blocks
        CONFIG["fuzz_iterations"] = iters
    except ValueError:
        print("Invalid input; configuration unchanged")


def show_help() -> None:
    """Print detailed help information."""
    print(HELP_TEXT)
    for key, value in CONFIG.items():
        print(f"{key}: {value}")


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
# Main interactive loop
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="GREENWIRE interactive menu")
    parser.add_argument("--db", default="card_data.db", help="Database path")
    args = parser.parse_args()

    conn = init_backend(Path(args.db))
    processor = NFCEMVProcessor()

    while True:
        print(MENU)
        choice = input("Select option: ").strip()
        if choice == "1":
            card = issue_card(conn)
            print("Issued card:\n", card)
        elif choice == "2":
            count = conn.execute("SELECT COUNT(*) FROM cards").fetchone()[0]
            print(f"{count} cards stored")
        elif choice == "3":
            rows = conn.execute(
                "SELECT verification_code, pan_hash FROM cards"
            ).fetchall()
            for row in rows:
                print(row)
        elif choice == "4":
            terminal = ContactlessEMVTerminal(["A0000000031010"])
            results = terminal.run()
            for res in results:
                print(res)
        elif choice == "5":
            reader = ISO14443ReaderWriter()
            vulns = scan_nfc_vulnerabilities(reader)
            if vulns:
                for v in vulns:
                    print(v)
            else:
                print("No vulnerabilities detected")
        elif choice == "6":
            fuzz_transaction()
        elif choice == "7":
            reader = ISO14443ReaderWriter()
            blk = int(input("Block number: "))
            data = reader.read_block(blk)
            print(data.hex())
        elif choice == "8":
            reader = ISO14443ReaderWriter()
            blk = int(input("Block number: "))
            data = bytes.fromhex(input("Hex data: "))
            reader.write_block(blk, data)
            print("Wrote block")
        elif choice == "9":
            uid = processor.read_uid()
            print(f"UID: {uid}")
        elif choice == "10":
            dump_atr()
        elif choice == "11":
            dump_memory()
        elif choice == "12":
            brute_force_pin()
        elif choice == "13":
            fuzz_apdu()
        elif choice == "14":
            fuzz_transaction()
        elif choice == "15":
            scan_for_cards()
        elif choice == "16":
            dump_filesystem()
        elif choice == "17":
            export_data(conn)
        elif choice == "18":
            import_data()
        elif choice == "19":
            reset_card()
        elif choice == "20":
            detect_card_os()
        elif choice == "21":
            fuzz_file_menu()
        elif choice == "22":
            show_apdu_log(conn)
        elif choice == "23":
            configure_settings()
        elif choice == "24":
            show_help()
        elif choice == "25":
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
