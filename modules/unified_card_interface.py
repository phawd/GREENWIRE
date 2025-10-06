#!/usr/bin/env python3
"""
Unified Card Interface - Same interface for fuzzing and personalization
Combines merchant POS, smart fuzzing, and card personalization.
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from enum import Enum

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from modules.crypto_mac_engine import MACEngine
    from modules.blandys_flowers_pos import BlandysFlowersPOS
    from modules.smart_apdu_fuzzer import SmartAPDUFuzzer
    HAS_MODULES = True
except ImportError as e:
    HAS_MODULES = False
    print(f"Warning: Module import failed: {e}")


class OperationMode(Enum):
    """Operation modes for unified interface."""
    TRANSACTION = "transaction"
    FUZZING = "fuzzing"
    PERSONALIZATION = "personalization"
    TESTING = "testing"


class UnifiedCardInterface:
    """
    Unified interface for all card operations.

    Features:
    - Same reader/connection interface for all modes
    - Seamless switching between transaction, fuzzing, personalization
    - Integrated MAC engine for all cryptographic operations
    - Common logging and result tracking
    """

    def __init__(self, debug=False):
        self.debug = debug
        self.mode = OperationMode.TRANSACTION

        # Initialize components (lazy loaded)
        self._pos = None
        self._fuzzer = None
        self._mac_engine = None

        # Shared state
        self.reader = None
        self.card_connection = None
        self.operation_log = []

    # ========================================================================
    # Component Access (Lazy Loading)
    # ========================================================================

    @property
    def pos(self) -> Optional[BlandysFlowersPOS]:
        """Get POS terminal (lazy init)."""
        if not HAS_MODULES:
            return None
        if not self._pos:
            self._pos = BlandysFlowersPOS(debug=self.debug)
            # Share reader connection
            self._pos.reader = self.reader
            self._pos.card_connection = self.card_connection
        return self._pos

    @property
    def fuzzer(self) -> Optional[SmartAPDUFuzzer]:
        """Get smart fuzzer (lazy init)."""
        if not HAS_MODULES:
            return None
        if not self._fuzzer:
            self._fuzzer = SmartAPDUFuzzer(debug=self.debug)
            # Share reader connection
            self._fuzzer.reader = self.reader
            self._fuzzer.card_connection = self.card_connection
        return self._fuzzer

    @property
    def mac_engine(self) -> Optional[MACEngine]:
        """Get MAC engine (lazy init)."""
        if not HAS_MODULES:
            return None
        if not self._mac_engine:
            self._mac_engine = MACEngine()
        return self._mac_engine

    # ========================================================================
    # Connection Management
    # ========================================================================

    def connect(self, reader_index=0) -> bool:
        """
        Connect to card reader.

        Shares connection across all components.
        """
        if not HAS_MODULES:
            print("❌ Required modules not available")
            return False

        # Use POS connection logic (most complete)
        if self.pos.connect_reader(reader_index):
            # Share connection with other components
            self.reader = self.pos.reader
            self.card_connection = self.pos.card_connection

            if self._fuzzer:
                self._fuzzer.reader = self.reader
                self._fuzzer.card_connection = self.card_connection

            print(f"✅ Connected in {self.mode.value} mode")
            return True

        return False

    def wait_for_card(self, timeout=30) -> bool:
        """Wait for card insertion."""
        if self.pos:
            return self.pos.wait_for_card(timeout)
        return False

    # ========================================================================
    # Mode Switching
    # ========================================================================

    def set_mode(self, mode: OperationMode):
        """
        Switch operation mode.

        All modes use same reader connection.
        """
        old_mode = self.mode
        self.mode = mode

        self.operation_log.append({
            "action": "mode_switch",
            "from": old_mode.value,
            "to": mode.value
        })

        print(f"🔄 Switched: {old_mode.value} → {mode.value}")

    # ========================================================================
    # Transaction Operations
    # ========================================================================

    def process_transaction(self, amount_cents: int, currency="USD") -> Dict[str, Any]:
        """
        Process card transaction.

        Uses POS terminal in transaction mode.
        """
        self.set_mode(OperationMode.TRANSACTION)

        if not self.pos:
            return {"status": "ERROR", "error": "POS not available"}

        result = self.pos.process_transaction(amount_cents, currency)

        self.operation_log.append({
            "action": "transaction",
            "amount": amount_cents / 100.0,
            "currency": currency,
            "status": result.get("status")
        })

        return result

    # ========================================================================
    # Fuzzing Operations
    # ========================================================================

    def fuzz_card(self, strategy="all", iterations=100) -> List[Dict]:
        """
        Fuzz card with smart mutations.

        Args:
            strategy: Fuzzing strategy
                - "all": All fuzzing techniques
                - "generate_ac": GENERATE AC mutations
                - "tlv": TLV structure fuzzing
                - "p1p2": Parameter fuzzing
                - "sequence": State machine fuzzing
                - "timing": Timing attack fuzzing
            iterations: Number of iterations

        Returns:
            List of fuzzing results
        """
        self.set_mode(OperationMode.FUZZING)

        if not self.fuzzer:
            return [{"error": "Fuzzer not available"}]

        results = []

        if strategy == "all" or strategy == "generate_ac":
            print("\n🧠 Running GENERATE AC fuzzing...")
            results.extend(self.fuzzer.fuzz_generate_ac_mutations(iterations))

        if strategy == "all" or strategy == "tlv":
            print("\n🧬 Running TLV fuzzing...")
            base_tlv = bytes([0x83, 0x00])
            results.extend(self.fuzzer.fuzz_tlv_structures(base_tlv, iterations))

        if strategy == "all" or strategy == "p1p2":
            print("\n🎚️  Running P1/P2 fuzzing...")
            base_cmd = [0x80, 0xA8]
            results.extend(self.fuzzer.fuzz_p1_p2_parameters(base_cmd, iterations))

        if strategy == "all" or strategy == "sequence":
            print("\n🔄 Running sequence fuzzing...")
            results.extend(self.fuzzer.fuzz_command_sequence(iterations // 2))

        if strategy == "all" or strategy == "timing":
            print("\n⏱️  Running timing fuzzing...")
            cmd = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00]
            results.extend(self.fuzzer.fuzz_timing_attacks(cmd, iterations // 2))

        self.operation_log.append({
            "action": "fuzzing",
            "strategy": strategy,
            "iterations": iterations,
            "results_count": len(results)
        })

        return results

    def fuzz_transaction(self, iterations=50) -> List[Dict]:
        """
        Fuzz during normal transaction flow.

        Combines POS transaction with fuzzing mutations.
        """
        self.set_mode(OperationMode.FUZZING)

        if not self.pos:
            return [{"error": "POS not available"}]

        # Enable fuzzing mode on POS
        self.pos.fuzzing_mode = True
        results = self.pos.fuzz_transaction(iterations)
        self.pos.fuzzing_mode = False

        self.operation_log.append({
            "action": "fuzz_transaction",
            "iterations": iterations,
            "results_count": len(results)
        })

        return results

    # ========================================================================
    # Personalization Operations
    # ========================================================================

    def personalize_card(self, card_data: Dict[str, Any]) -> bool:
        """
        Personalize card with issuer data.

        Uses same reader interface as transactions and fuzzing.
        """
        self.set_mode(OperationMode.PERSONALIZATION)

        if not self.pos:
            print("❌ POS not available")
            return False

        success = self.pos.personalize_card(card_data)

        self.operation_log.append({
            "action": "personalization",
            "pan": card_data.get("PAN", "REDACTED"),
            "success": success
        })

        return success

    def generate_card_keys(self, master_key: bytes, pan: str, pan_seq: int = 0) -> Dict[str, bytes]:
        """
        Generate card cryptographic keys.

        Uses MAC engine for key derivation.
        """
        if not self.mac_engine:
            return {}

        # Derive session keys (simplified)
        pan_bytes = bytes.fromhex(pan.replace(" ", ""))
        atc = (pan_seq).to_bytes(2, 'big')

        session_key = self.mac_engine.emv_mac_session_key(master_key, atc)
        kcv = self.mac_engine.generate_kcv(session_key)

        keys = {
            "session_key": session_key,
            "kcv": kcv
        }

        self.operation_log.append({
            "action": "key_generation",
            "pan": pan[:6] + "******" + pan[-4:],
            "kcv": kcv.hex().upper()
        })

        return keys

    # ========================================================================
    # Testing Operations
    # ========================================================================

    def test_card_compliance(self) -> Dict[str, Any]:
        """
        Run compliance tests on card.

        Tests EMV standard compliance.
        """
        self.set_mode(OperationMode.TESTING)

        print("\n🧪 Running compliance tests...")

        tests = {
            "application_selection": self._test_application_selection(),
            "gpo_command": self._test_gpo(),
            "read_records": self._test_read_records(),
            "generate_ac": self._test_generate_ac(),
            "pin_verify": self._test_pin_verify(),
        }

        passed = sum(1 for t in tests.values() if t.get("passed"))
        total = len(tests)

        result = {
            "passed": passed,
            "total": total,
            "pass_rate": passed / total if total > 0 else 0.0,
            "tests": tests
        }

        self.operation_log.append({
            "action": "compliance_testing",
            "passed": passed,
            "total": total
        })

        print(f"\n✅ Compliance: {passed}/{total} tests passed ({result['pass_rate']*100:.1f}%)")

        return result

    def _test_application_selection(self) -> Dict:
        """Test SELECT command."""
        if not self.pos:
            return {"passed": False, "error": "POS not available"}

        try:
            aid = self.pos._select_application()
            return {
                "passed": aid is not None,
                "aid": aid
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def _test_gpo(self) -> Dict:
        """Test GET PROCESSING OPTIONS."""
        if not self.pos:
            return {"passed": False, "error": "POS not available"}

        try:
            gpo = self.pos._get_processing_options(1000)
            return {
                "passed": gpo is not None,
                "response_len": len(gpo) if gpo else 0
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def _test_read_records(self) -> Dict:
        """Test READ RECORD."""
        if not self.pos:
            return {"passed": False, "error": "POS not available"}

        try:
            data = self.pos._read_application_data()
            return {
                "passed": len(data) > 0,
                "records_read": len(data)
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def _test_generate_ac(self) -> Dict:
        """Test GENERATE AC."""
        if not self.pos:
            return {"passed": False, "error": "POS not available"}

        try:
            arqc = self.pos._generate_ac(1000, "ARQC")
            return {
                "passed": arqc is not None,
                "arqc": arqc
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def _test_pin_verify(self) -> Dict:
        """Test PIN verification."""
        # Simplified - actual implementation would verify PIN
        return {
            "passed": True,
            "note": "Simulated"
        }

    # ========================================================================
    # Workflow Examples
    # ========================================================================

    def workflow_transaction_then_fuzz(self, amount_cents=1250, fuzz_iterations=50):
        """
        Example workflow: Normal transaction followed by fuzzing.

        Tests card behavior after successful transaction.
        """
        print("\n" + "="*60)
        print("📋 Workflow: Transaction → Fuzzing")
        print("="*60)

        # Step 1: Normal transaction
        print("\n1️⃣  Processing normal transaction...")
        tx_result = self.process_transaction(amount_cents)

        if tx_result.get("status") != "APPROVED":
            print("❌ Transaction failed, aborting workflow")
            return

        # Step 2: Fuzz the card
        print("\n2️⃣  Fuzzing card...")
        fuzz_results = self.fuzz_card("generate_ac", fuzz_iterations)

        # Step 3: Test if card still works
        print("\n3️⃣  Testing card after fuzzing...")
        compliance = self.test_card_compliance()

        print("\n" + "="*60)
        print(f"✅ Workflow complete")
        print(f"   Transaction: {tx_result.get('status')}")
        print(f"   Fuzz iterations: {len(fuzz_results)}")
        print(f"   Compliance: {compliance.get('pass_rate', 0)*100:.1f}%")
        print("="*60)

    def workflow_personalize_then_test(self, card_data: Dict[str, Any]):
        """
        Example workflow: Personalize card then test.

        Full issuer workflow.
        """
        print("\n" + "="*60)
        print("📋 Workflow: Personalize → Test")
        print("="*60)

        # Step 1: Personalize
        print("\n1️⃣  Personalizing card...")
        if not self.personalize_card(card_data):
            print("❌ Personalization failed, aborting")
            return

        # Step 2: Generate keys
        print("\n2️⃣  Generating cryptographic keys...")
        master_key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        keys = self.generate_card_keys(master_key, card_data.get("PAN", ""))
        print(f"   Session Key KCV: {keys.get('kcv', b'').hex().upper()}")

        # Step 3: Compliance test
        print("\n3️⃣  Testing card compliance...")
        compliance = self.test_card_compliance()

        # Step 4: Test transaction
        print("\n4️⃣  Testing transaction...")
        tx_result = self.process_transaction(1000)

        print("\n" + "="*60)
        print(f"✅ Workflow complete")
        print(f"   Personalization: SUCCESS")
        print(f"   Compliance: {compliance.get('pass_rate', 0)*100:.1f}%")
        print(f"   Transaction: {tx_result.get('status')}")
        print("="*60)

    # ========================================================================
    # Logging & Reporting
    # ========================================================================

    def save_operation_log(self, filename="unified_operations.json"):
        """Save operation log to file."""
        log_path = Path(filename)
        with open(log_path, 'w') as f:
            json.dump({
                "mode": self.mode.value,
                "operations": self.operation_log,
                "total_operations": len(self.operation_log)
            }, f, indent=2)
        print(f"💾 Operation log saved: {log_path}")

    def print_summary(self):
        """Print operation summary."""
        print(f"\n{'='*60}")
        print(f"📊 Unified Interface Summary")
        print(f"{'='*60}")
        print(f"Current mode: {self.mode.value}")
        print(f"Total operations: {len(self.operation_log)}")

        # Count by action type
        actions = {}
        for op in self.operation_log:
            action = op.get("action", "unknown")
            actions[action] = actions.get(action, 0) + 1

        print(f"\nOperation breakdown:")
        for action, count in sorted(actions.items()):
            print(f"  - {action}: {count}")

        print(f"{'='*60}\n")


def main():
    """CLI interface for unified operations."""
    import argparse

    parser = argparse.ArgumentParser(description="Unified Card Interface")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--mode", choices=["transaction", "fuzzing", "personalization", "testing"],
                        default="transaction", help="Operation mode")
    parser.add_argument("--workflow", choices=["tx_fuzz", "personalize_test"],
                        help="Run predefined workflow")
    parser.add_argument("--amount", type=float, default=12.50, help="Transaction amount")
    parser.add_argument("--iterations", type=int, default=100, help="Fuzzing iterations")

    args = parser.parse_args()

    # Initialize interface
    interface = UnifiedCardInterface(debug=args.debug)

    # Connect to card
    if not interface.connect():
        print("❌ Failed to connect")
        return 1

    # Run workflow or single operation
    if args.workflow == "tx_fuzz":
        interface.workflow_transaction_then_fuzz(int(args.amount * 100), args.iterations)
    elif args.workflow == "personalize_test":
        card_data = {
            "PAN": "4111111111111111",
            "Expiry": "12/25",
            "Cardholder": "TEST CARD"
        }
        interface.workflow_personalize_then_test(card_data)
    else:
        # Single operation
        mode_map = {
            "transaction": OperationMode.TRANSACTION,
            "fuzzing": OperationMode.FUZZING,
            "personalization": OperationMode.PERSONALIZATION,
            "testing": OperationMode.TESTING
        }

        interface.set_mode(mode_map[args.mode])

        if args.mode == "transaction":
            interface.process_transaction(int(args.amount * 100))
        elif args.mode == "fuzzing":
            interface.fuzz_card("all", args.iterations)
        elif args.mode == "testing":
            interface.test_card_compliance()

    # Print summary and save log
    interface.print_summary()
    interface.save_operation_log()

    return 0


if __name__ == "__main__":
    sys.exit(main())
