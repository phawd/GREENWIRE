import argparse
import platform
from pathlib import Path
from datetime import datetime, timedelta
"""Simple interactive CLI exposing most GREENWIRE features."""

from greenwire.core.backend import init_backend, issue_card
from greenwire.core.nfc_emv import ContactlessEMVTerminal, NFCEMVProcessor
from greenwire.core.nfc_iso import ISO14443ReaderWriter
from greenwire.nfc_vuln import scan_nfc_vulnerabilities
from greenwire.core.fuzzer import SmartcardFuzzer
from greenwire.core import crypto_engine
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


MENU = """\
GREENWIRE Menu
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
21. Generate self-signed cert
22. Quit
"""

# ---------------------------------------------------------------------------
# Utility helper
# ---------------------------------------------------------------------------

def print_host_os() -> None:
    """Display the operating system running this script."""
    os_name = platform.system().lower()
    print(f"[*] Detected host OS: {os_name}")

# ---------------------------------------------------------------------------
# Helper functions for each menu option
# ---------------------------------------------------------------------------

def dump_atr() -> None:
    """Attempt to print the card ATR/ATS if available."""
    reader = ISO14443ReaderWriter()
    if reader.connect():
        atr = getattr(reader.tag, "ats", None) or getattr(reader.tag, "atr", None)
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
    """Attempt to identify the card OS based on known ATR patterns."""
    # Typical ATR prefixes associated with various JCOP revisions.  This list
    # is not exhaustive but serves as a reasonable heuristic for demo purposes.
    jcop_prefixes = [
        bytes.fromhex("3B8F"),
        bytes.fromhex("3B65"),
        bytes.fromhex("3B67"),
        bytes.fromhex("3B6A"),
        bytes.fromhex("3B6B"),
    ]

    reader = ISO14443ReaderWriter()
    if reader.connect():
        atr = getattr(reader.tag, "ats", None) or getattr(reader.tag, "atr", None)
        if atr:
            if any(atr.startswith(prefix) for prefix in jcop_prefixes):
                print(f"Detected card OS: JCOP (ATR {atr.hex()})")
            else:
                print(f"Unknown card OS (ATR {atr.hex()})")
        else:
            print("ATR/ATS not available; cannot detect OS")
        reader.disconnect()
    else:
        print("No reader or tag detected")


def generate_self_signed_cert() -> None:
    """Generate an RSA key and self-signed certificate."""
    key = crypto_engine.generate_rsa_key()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GREENWIRE"),
            x509.NameAttribute(NameOID.COMMON_NAME, "GREENWIRE Test Cert"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    pem_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    Path("test_key.pem").write_bytes(pem_key)
    Path("test_cert.pem").write_bytes(pem_cert)
    print("Generated test_key.pem and test_cert.pem")

# ---------------------------------------------------------------------------
# Main interactive loop
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="GREENWIRE interactive menu")
    parser.add_argument("--db", default="card_data.db", help="Database path")
    args = parser.parse_args()

    conn = init_backend(Path(args.db))
    processor = NFCEMVProcessor()

    # Inform the user about the host operating system
    print_host_os()

    while True:
        print(MENU)
        choice = input("Select option: ").strip()

        if choice == "1":
            # Issue a new sample card and persist details to the database
            card = issue_card(conn)
            print("Issued card:\n", card)

        elif choice == "2":
            # Display how many cards have been stored
            count = conn.execute("SELECT COUNT(*) FROM cards").fetchone()[0]
            print(f"{count} cards stored")

        elif choice == "3":
            # List verification codes and PAN hashes for all cards
            rows = conn.execute(
                "SELECT verification_code, pan_hash FROM cards"
            ).fetchall()
            for row in rows:
                print(row)

        elif choice == "4":
            # Run a basic contactless EMV transaction
            terminal = ContactlessEMVTerminal(["A0000000031010"])
            results = terminal.run()
            for res in results:
                print(res)

        elif choice == "5":
            # Probe for known NFC vulnerabilities using the current reader
            reader = ISO14443ReaderWriter()
            vulns = scan_nfc_vulnerabilities(reader)
            if vulns:
                for v in vulns:
                    print(v)
            else:
                print("No vulnerabilities detected")

        elif choice == "6":
            # Fuzz a contactless transaction sequence
            fuzz_transaction()

        elif choice == "7":
            # Read a single block from the card
            reader = ISO14443ReaderWriter()
            blk = int(input("Block number: "))
            data = reader.read_block(blk)
            print(data.hex())

        elif choice == "8":
            # Write raw hexadecimal data to a card block
            reader = ISO14443ReaderWriter()
            blk = int(input("Block number: "))
            data = bytes.fromhex(input("Hex data: "))
            reader.write_block(blk, data)
            print("Wrote block")

        elif choice == "9":
            # Display the UID of the current NFC tag
            uid = processor.read_uid()
            print(f"UID: {uid}")

        elif choice == "10":
            # Show the card ATR or ATS value
            dump_atr()

        elif choice == "11":
            # Dump the first few memory blocks from the card
            dump_memory()

        elif choice == "12":
            # Simulate a brute-force attempt on the PIN
            brute_force_pin()

        elif choice == "13":
            # Fuzz a sequence of APDUs
            fuzz_apdu()

        elif choice == "14":
            # Perform a contactless transaction fuzz
            fuzz_transaction()

        elif choice == "15":
            # Scan for nearby contactless cards
            scan_for_cards()

        elif choice == "16":
            # Dump the card's filesystem (simulation)
            dump_filesystem()

        elif choice == "17":
            # Export card metadata from the database to JSON
            export_data(conn)

        elif choice == "18":
            # Placeholder for importing card data back from JSON
            import_data()

        elif choice == "19":
            # Reset the card (simulation)
            reset_card()

        elif choice == "20":
            # Attempt to detect the card operating system
            detect_card_os()

        elif choice == "21":
            # Generate a test RSA key and self-signed certificate
            generate_self_signed_cert()

        elif choice == "22":
            # Option 22 simply exits the loop and quits
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
