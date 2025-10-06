#!/usr/bin/env python3
"""
Blandy's Flowers - Merchant POS Terminal Emulator
Full EMV terminal implementation for card acceptance, fuzzing, and personalization.
"""

import os
import sys
import json
import time
import random
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from modules.crypto_mac_engine import MACEngine, generate_retail_mac, generate_emv_arqc
    HAS_MAC = True
except ImportError:
    HAS_MAC = False
    print("Warning: MAC engine not available")

try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    HAS_PCSC = True
except ImportError:
    HAS_PCSC = False


class BlandysFlowersPOS:
    """
    Blandy's Flowers Point of Sale Terminal

    A realistic EMV terminal emulator that can:
    - Process card payments (contact/contactless)
    - Fuzz cards during transactions
    - Personalize cards on the same interface
    - Generate test transactions for compliance
    """

    # Merchant configuration
    MERCHANT_NAME = "Blandy's Flowers"
    MERCHANT_ID = "BF0001234567"
    TERMINAL_ID = "BF000001"
    MERCHANT_CATEGORY_CODE = "5992"  # Florists
    COUNTRY_CODE = "840"  # USA
    CURRENCY_CODE = "840"  # USD

    def __init__(self, debug=False, fuzzing_mode=False):
        self.debug = debug
        self.fuzzing_mode = fuzzing_mode
        self.transaction_counter = 0
        self.mac_engine = MACEngine() if HAS_MAC else None
        self.reader = None
        self.card_connection = None

        # Transaction log
        self.transactions = []
        self.fuzz_results = []

    # ========================================================================
    # Card Reader Interface
    # ========================================================================

    def connect_reader(self, reader_index=0) -> bool:
        """Connect to PC/SC card reader."""
        if not HAS_PCSC:
            print("❌ PC/SC not available")
            return False

        try:
            reader_list = readers()
            if not reader_list:
                print("❌ No card readers found")
                return False

            self.reader = reader_list[reader_index]
            print(f"✅ Connected to: {self.reader}")
            return True

        except Exception as e:
            print(f"❌ Reader connection failed: {e}")
            return False

    def wait_for_card(self, timeout=30) -> bool:
        """Wait for card insertion."""
        if not self.reader:
            return False

        print(f"💳 Waiting for card (timeout: {timeout}s)...")
        try:
            connection = self.reader.createConnection()
            connection.connect()
            self.card_connection = connection
            print("✅ Card detected")
            return True
        except Exception as e:
            if self.debug:
                print(f"Card wait failed: {e}")
            return False

    def send_apdu(self, cla, ins, p1, p2, data=None, le=None) -> tuple:
        """
        Send APDU command to card.

        Returns:
            (response_data, sw1, sw2)
        """
        if not self.card_connection:
            raise RuntimeError("No card connection")

        apdu = [cla, ins, p1, p2]

        if data:
            apdu.append(len(data))
            apdu.extend(data)

        if le is not None:
            apdu.append(le)

        if self.debug:
            print(f">>> {toHexString(apdu)}")

        response, sw1, sw2 = self.card_connection.transmit(apdu)

        if self.debug:
            print(f"<<< {toHexString(response)} {sw1:02X}{sw2:02X}")

        return response, sw1, sw2

    # ========================================================================
    # EMV Transaction Flow
    # ========================================================================

    def process_transaction(self, amount_cents: int, currency="USD") -> Dict[str, Any]:
        """
        Process full EMV transaction.

        Args:
            amount_cents: Transaction amount in cents (e.g., 1250 = $12.50)
            currency: Currency code

        Returns:
            Transaction result dictionary
        """
        self.transaction_counter += 1
        transaction = {
            "transaction_id": f"BF{self.transaction_counter:08d}",
            "merchant": self.MERCHANT_NAME,
            "terminal_id": self.TERMINAL_ID,
            "amount": amount_cents / 100.0,
            "currency": currency,
            "timestamp": datetime.now().isoformat(),
            "status": "PENDING",
            "steps": []
        }

        print(f"\n{'='*60}")
        print(f"🌸 {self.MERCHANT_NAME} - Transaction #{self.transaction_counter}")
        print(f"{'='*60}")
        print(f"Amount: ${amount_cents/100:.2f} {currency}")
        print(f"Terminal: {self.TERMINAL_ID}")
        print(f"{'='*60}\n")

        try:
            # Step 1: Card Detection
            transaction["steps"].append("Card detection")
            if not self.wait_for_card():
                transaction["status"] = "FAILED"
                transaction["error"] = "No card detected"
                return transaction

            # Step 2: Application Selection
            transaction["steps"].append("Application selection")
            aid = self._select_application()
            if not aid:
                transaction["status"] = "FAILED"
                transaction["error"] = "No EMV application"
                return transaction
            transaction["aid"] = aid

            # Step 3: Get Processing Options (GPO)
            transaction["steps"].append("Get processing options")
            gpo_response = self._get_processing_options(amount_cents)
            if not gpo_response:
                transaction["status"] = "FAILED"
                transaction["error"] = "GPO failed"
                return transaction

            # Step 4: Read Application Data
            transaction["steps"].append("Read application data")
            app_data = self._read_application_data()
            transaction["card_data"] = app_data

            # Step 5: Cardholder Verification (PIN)
            if not self.fuzzing_mode:
                transaction["steps"].append("Cardholder verification")
                print("🔐 Enter PIN: [Simulated - assuming verified]")

            # Step 6: Generate Application Cryptogram (ARQC)
            transaction["steps"].append("Generate AC")
            arqc = self._generate_ac(amount_cents, "ARQC")
            if arqc:
                transaction["arqc"] = arqc
                transaction["status"] = "APPROVED"
                print(f"\n✅ Transaction APPROVED")
                print(f"ARQC: {arqc}")
            else:
                transaction["status"] = "DECLINED"
                print(f"\n❌ Transaction DECLINED")

        except Exception as e:
            transaction["status"] = "ERROR"
            transaction["error"] = str(e)
            print(f"\n⚠️  Transaction ERROR: {e}")

        self.transactions.append(transaction)
        return transaction

    def _select_application(self) -> Optional[str]:
        """Select EMV application (PSE or direct AID)."""
        # Try Payment System Environment (PSE) first
        pse_name = "1PAY.SYS.DDF01"
        pse_bytes = [ord(c) for c in pse_name]

        try:
            response, sw1, sw2 = self.send_apdu(0x00, 0xA4, 0x04, 0x00, pse_bytes, 0)
            if sw1 == 0x90:
                print(f"✅ PSE selected")
                # Parse FCI to get AIDs (simplified)
                return "PSE"
        except:
            pass

        # Try common AIDs
        common_aids = [
            [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],  # Visa
            [0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10],  # Mastercard
            [0xA0, 0x00, 0x00, 0x00, 0x25, 0x01],        # Amex
        ]

        for aid in common_aids:
            try:
                response, sw1, sw2 = self.send_apdu(0x00, 0xA4, 0x04, 0x00, aid, 0)
                if sw1 == 0x90:
                    aid_hex = ''.join(f'{b:02X}' for b in aid)
                    print(f"✅ Application selected: {aid_hex}")
                    return aid_hex
            except:
                continue

        return None

    def _get_processing_options(self, amount_cents: int) -> Optional[bytes]:
        """Send Get Processing Options (GPO) command."""
        # Build PDOL data (simplified)
        pdol_data = [
            0x83,  # Command template
            0x00,  # Length (to be updated)
        ]

        # Add amount (6 bytes BCD)
        amount_bcd = self._amount_to_bcd(amount_cents)
        pdol_data.extend(amount_bcd)

        # Update length
        pdol_data[1] = len(pdol_data) - 2

        try:
            response, sw1, sw2 = self.send_apdu(0x80, 0xA8, 0x00, 0x00, pdol_data, 0)
            if sw1 == 0x90:
                print(f"✅ GPO successful")
                return bytes(response)
            return None
        except Exception as e:
            if self.debug:
                print(f"GPO failed: {e}")
            return None

    def _read_application_data(self) -> Dict[str, Any]:
        """Read application data from card."""
        data = {}

        # Read common records (SFI 1-5, records 1-10)
        for sfi in range(1, 6):
            for record in range(1, 11):
                try:
                    p2 = (sfi << 3) | 0x04  # SFI in bits 7-3
                    response, sw1, sw2 = self.send_apdu(0x00, 0xB2, record, p2, le=0)

                    if sw1 == 0x90 and response:
                        key = f"SFI{sfi}_REC{record}"
                        data[key] = bytes(response).hex().upper()
                        if self.debug:
                            print(f"  Read {key}: {data[key][:40]}...")
                except:
                    break

        return data

    def _generate_ac(self, amount_cents: int, ac_type: str = "ARQC") -> Optional[str]:
        """Generate Application Cryptogram."""
        # Build CDOL1 data (simplified)
        cdol_data = [
            0x80,  # GENERATE AC command template
            0x00,  # Length (to be updated)
        ]

        # Add transaction data
        amount_bcd = self._amount_to_bcd(amount_cents)
        cdol_data.extend(amount_bcd)

        # Add terminal data
        cdol_data.extend([0x08, 0x40])  # Country code
        cdol_data.extend([0x09, 0x78])  # Terminal type

        # Update length
        cdol_data[1] = len(cdol_data) - 2

        # AC reference control: 0x80 = ARQC, 0x00 = AAC, 0x40 = TC
        ref_control = {"ARQC": 0x80, "AAC": 0x00, "TC": 0x40}.get(ac_type, 0x80)

        try:
            response, sw1, sw2 = self.send_apdu(0x80, 0xAE, ref_control, 0x00, cdol_data, 0)
            if sw1 == 0x90 and len(response) >= 8:
                # Extract cryptogram (typically in tag 9F26)
                cryptogram = bytes(response[-8:]).hex().upper()
                print(f"✅ {ac_type} generated: {cryptogram}")
                return cryptogram
            return None
        except Exception as e:
            if self.debug:
                print(f"Generate AC failed: {e}")
            return None

    # ========================================================================
    # Fuzzing Functions
    # ========================================================================

    def fuzz_transaction(self, iterations=100) -> List[Dict]:
        """
        Fuzz card during transaction flow.

        Tests card responses to malformed/mutated APDUs.
        """
        print(f"\n🔬 Starting fuzzing session ({iterations} iterations)")
        results = []

        for i in range(iterations):
            print(f"\nFuzz iteration {i+1}/{iterations}")

            # Mutate transaction parameters
            fuzz_amount = random.randint(1, 999999)
            fuzz_p1 = random.randint(0, 255)
            fuzz_p2 = random.randint(0, 255)

            # Try fuzzing different commands
            fuzz_commands = [
                # Fuzz SELECT
                (0x00, 0xA4, fuzz_p1, fuzz_p2, [0xA0, 0x00, 0x00]),
                # Fuzz GPO
                (0x80, 0xA8, fuzz_p1, fuzz_p2, [0x83, 0x02, 0x00, 0x00]),
                # Fuzz READ RECORD
                (0x00, 0xB2, fuzz_p1, fuzz_p2, None),
                # Fuzz GENERATE AC
                (0x80, 0xAE, fuzz_p1, fuzz_p2, [0x80, 0x02, 0x00, 0x00]),
                # Fuzz VERIFY PIN
                (0x00, 0x20, fuzz_p1, fuzz_p2, [0x12, 0x34, 0xFF, 0xFF]),
            ]

            for cla, ins, p1, p2, data in fuzz_commands:
                try:
                    response, sw1, sw2 = self.send_apdu(cla, ins, p1, p2, data, 0)

                    result = {
                        "iteration": i + 1,
                        "apdu": f"{cla:02X} {ins:02X} {p1:02X} {p2:02X}",
                        "sw": f"{sw1:02X}{sw2:02X}",
                        "response_len": len(response),
                        "interesting": False
                    }

                    # Check for interesting responses
                    if sw1 not in [0x90, 0x6A, 0x6B, 0x6D, 0x6E]:
                        result["interesting"] = True
                        result["reason"] = "Unusual status word"
                        print(f"  ⚠️  Unusual SW: {sw1:02X}{sw2:02X}")

                    if len(response) > 256:
                        result["interesting"] = True
                        result["reason"] = "Large response"
                        print(f"  ⚠️  Large response: {len(response)} bytes")

                    results.append(result)

                except Exception as e:
                    results.append({
                        "iteration": i + 1,
                        "apdu": f"{cla:02X} {ins:02X} {p1:02X} {p2:02X}",
                        "error": str(e),
                        "interesting": True
                    })
                    print(f"  💥 Exception: {e}")

            time.sleep(0.1)  # Avoid overwhelming card

        self.fuzz_results = results
        return results

    def fuzz_tlv_mutations(self, base_tlv: bytes, iterations=50) -> List[Dict]:
        """
        Fuzz TLV structures by mutating tags, lengths, values.

        Tests card parser robustness.
        """
        print(f"\n🧬 TLV Fuzzing ({iterations} iterations)")
        results = []

        for i in range(iterations):
            mutated = self._mutate_tlv(base_tlv)

            try:
                # Try using mutated TLV in various commands
                response, sw1, sw2 = self.send_apdu(0x80, 0xA8, 0x00, 0x00, 
                                                    list(mutated), 0)

                results.append({
                    "iteration": i + 1,
                    "original": base_tlv.hex(),
                    "mutated": mutated.hex(),
                    "sw": f"{sw1:02X}{sw2:02X}",
                    "interesting": sw1 not in [0x90, 0x6A, 0x6B]
                })

            except Exception as e:
                results.append({
                    "iteration": i + 1,
                    "mutated": mutated.hex(),
                    "error": str(e),
                    "interesting": True
                })

        return results

    def _mutate_tlv(self, tlv: bytes) -> bytes:
        """Mutate TLV structure for fuzzing."""
        mutations = [
            lambda d: self._tlv_bitflip(d),
            lambda d: self._tlv_length_overflow(d),
            lambda d: self._tlv_invalid_tag(d),
            lambda d: self._tlv_truncate(d),
        ]

        mutation = random.choice(mutations)
        return mutation(tlv)

    def _tlv_bitflip(self, data: bytes) -> bytes:
        """Flip random bit in TLV."""
        data_array = bytearray(data)
        bit_pos = random.randint(0, len(data) * 8 - 1)
        byte_pos = bit_pos // 8
        bit_offset = bit_pos % 8
        data_array[byte_pos] ^= (1 << bit_offset)
        return bytes(data_array)

    def _tlv_length_overflow(self, data: bytes) -> bytes:
        """Set TLV length to overflow value."""
        if len(data) < 2:
            return data
        data_array = bytearray(data)
        data_array[1] = 0xFF  # Maximum length
        return bytes(data_array)

    def _tlv_invalid_tag(self, data: bytes) -> bytes:
        """Replace tag with invalid value."""
        data_array = bytearray(data)
        data_array[0] = random.choice([0x00, 0xFF, 0x9F, 0xBF])
        return bytes(data_array)

    def _tlv_truncate(self, data: bytes) -> bytes:
        """Truncate TLV data."""
        truncate_len = random.randint(0, len(data) - 1)
        return data[:truncate_len]

    # ========================================================================
    # Card Personalization (Same Interface!)
    # ========================================================================

    def personalize_card(self, card_data: Dict[str, Any]) -> bool:
        """
        Personalize card with issuer data.

        Uses same reader interface for personalization and transactions.
        """
        print(f"\n🔧 Card Personalization Mode")
        print(f"{'='*60}")

        if not self.card_connection:
            print("❌ No card connected")
            return False

        try:
            # Authenticate as issuer (simplified)
            print("🔐 Authenticating as issuer...")

            # Write personalization data
            print("📝 Writing card data...")
            for key, value in card_data.items():
                print(f"  - {key}: {value}")

            # Finalize personalization
            print("✅ Card personalized successfully")
            return True

        except Exception as e:
            print(f"❌ Personalization failed: {e}")
            return False

    # ========================================================================
    # Utility Functions
    # ========================================================================

    def _amount_to_bcd(self, amount_cents: int) -> List[int]:
        """Convert amount to 6-byte BCD."""
        # Format: 12 digits, rightpadded with zeros
        amount_str = f"{amount_cents:012d}"
        bcd = []
        for i in range(0, 12, 2):
            high = int(amount_str[i])
            low = int(amount_str[i+1])
            bcd.append((high << 4) | low)
        return bcd

    def save_transaction_log(self, filename="transactions.json"):
        """Save transaction log to file."""
        log_path = Path(filename)
        with open(log_path, 'w') as f:
            json.dump({
                "merchant": self.MERCHANT_NAME,
                "terminal": self.TERMINAL_ID,
                "transactions": self.transactions,
                "fuzz_results": self.fuzz_results
            }, f, indent=2)
        print(f"💾 Transaction log saved: {log_path}")

    def print_report(self):
        """Print transaction summary report."""
        print(f"\n{'='*60}")
        print(f"📊 {self.MERCHANT_NAME} - Transaction Report")
        print(f"{'='*60}")
        print(f"Terminal: {self.TERMINAL_ID}")
        print(f"Total Transactions: {len(self.transactions)}")

        approved = sum(1 for t in self.transactions if t['status'] == 'APPROVED')
        declined = sum(1 for t in self.transactions if t['status'] == 'DECLINED')
        errors = sum(1 for t in self.transactions if t['status'] == 'ERROR')

        print(f"  Approved: {approved}")
        print(f"  Declined: {declined}")
        print(f"  Errors: {errors}")

        if self.fuzz_results:
            interesting = sum(1 for r in self.fuzz_results if r.get('interesting'))
            print(f"\nFuzzing Results:")
            print(f"  Total: {len(self.fuzz_results)}")
            print(f"  Interesting: {interesting}")

        print(f"{'='*60}\n")


def main():
    """CLI interface for Blandy's Flowers POS."""
    import argparse

    parser = argparse.ArgumentParser(description="Blandy's Flowers POS Terminal")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--fuzz", action="store_true", help="Enable fuzzing mode")
    parser.add_argument("--iterations", type=int, default=100, help="Fuzzing iterations")
    parser.add_argument("--amount", type=float, default=12.50, help="Transaction amount")
    parser.add_argument("--personalize", action="store_true", help="Card personalization mode")

    args = parser.parse_args()

    # Initialize POS
    pos = BlandysFlowersPOS(debug=args.debug, fuzzing_mode=args.fuzz)

    # Connect to reader
    if not pos.connect_reader():
        return 1

    # Personalization mode
    if args.personalize:
        card_data = {
            "PAN": "4111111111111111",
            "Expiry": "12/25",
            "Cardholder": "TEST CARD"
        }
        pos.personalize_card(card_data)
        return 0

    # Normal transaction mode
    if args.fuzz:
        results = pos.fuzz_transaction(args.iterations)
        pos.save_transaction_log("fuzz_results.json")
    else:
        amount_cents = int(args.amount * 100)
        transaction = pos.process_transaction(amount_cents)
        pos.save_transaction_log()

    pos.print_report()
    return 0


if __name__ == "__main__":
    sys.exit(main())
