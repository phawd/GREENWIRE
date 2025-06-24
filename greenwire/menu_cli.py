import argparse
from pathlib import Path
"""Simple interactive CLI exposing most GREENWIRE features."""

from greenwire.core.backend import init_backend, issue_card
from greenwire.core.nfc_emv import ContactlessEMVTerminal, NFCEMVProcessor
from greenwire.core.nfc_iso import ISO14443ReaderWriter
from greenwire.nfc_vuln import scan_nfc_vulnerabilities
from greenwire.core.fuzzer import SmartcardFuzzer


MENU = """
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
10. JCOP OS version
11. Fuzz JCOP
12. Quit
"""


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
            fuzzer = SmartcardFuzzer({"dry_run": True})
            results = fuzzer.fuzz_contactless(["A0000000031010"], iterations=1)
            for r in results:
                print(r)
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
            reader = ISO14443ReaderWriter()
            uid = processor.read_uid()
            print(f"UID: {uid}")
        elif choice == "10":
            from greenwire.core.jcop import JCOPManager
            mgr = JCOPManager()
            try:
                data, sw1, sw2 = mgr.get_os_version()
                print("JCOP OS version:", data, hex(sw1), hex(sw2))
            except Exception as exc:
                print("Error accessing JCOP card:", exc)
        elif choice == "11":
            from greenwire.core.jcop import JCOPManager
            mgr = JCOPManager()
            try:
                mgr.connect()
                fuzzer = SmartcardFuzzer({"dry_run": True})
                results = fuzzer.fuzz_contactless(["A0000000031010"], iterations=1)
                for r in results:
                    print(r)
            except Exception as exc:
                print("JCOP fuzzing failed:", exc)
        elif choice == "12":
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
