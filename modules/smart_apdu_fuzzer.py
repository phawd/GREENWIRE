#!/usr/bin/env python3
"""
Smart APDU Fuzzer - Advanced fuzzing that causes unusual card reactions
Implements intelligent mutation strategies for EMV/JavaCard testing.
"""

import os
import sys
import random
import struct
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Callable

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from modules.crypto_mac_engine import MACEngine
    HAS_MAC = True
except ImportError:
    HAS_MAC = False

try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    HAS_PCSC = True
except ImportError:
    HAS_PCSC = False


class SmartAPDUFuzzer:
    """
    Advanced APDU fuzzer that uses encryption abilities and TLV manipulation
    to cause unusual card behavior (reboot, unlock, error states).
    """
    
    def __init__(self, debug=False):
        self.debug = debug
        self.mac_engine = MACEngine() if HAS_MAC else None
        self.reader = None
        self.card_connection = None
        self.fuzz_results = []
        
        # Track card state
        self.card_state = {
            "selected_aid": None,
            "authenticated": False,
            "pin_tries": 3,
            "last_sw": None
        }
    
    # ========================================================================
    # Card Connection
    # ========================================================================
    
    def connect(self, reader_index=0) -> bool:
        """Connect to card reader."""
        if not HAS_PCSC:
            if self.debug:
                print("PC/SC not available")
            return False
        
        try:
            reader_list = readers()
            if not reader_list:
                return False
            
            self.reader = reader_list[reader_index]
            connection = self.reader.createConnection()
            connection.connect()
            self.card_connection = connection
            return True
        except Exception as e:
            if self.debug:
                print(f"Connection failed: {e}")
            return False
    
    def send_apdu(self, apdu: List[int]) -> Tuple[List[int], int, int]:
        """Send APDU and return response."""
        if not self.card_connection:
            raise RuntimeError("No card connection")
        
        if self.debug:
            print(f">>> {toHexString(apdu)}")
        
        try:
            response, sw1, sw2 = self.card_connection.transmit(apdu)
            
            if self.debug:
                print(f"<<< {toHexString(response)} {sw1:02X}{sw2:02X}")
            
            self.card_state["last_sw"] = (sw1, sw2)
            return response, sw1, sw2
            
        except Exception as e:
            if self.debug:
                print(f"APDU failed: {e}")
            raise
    
    # ========================================================================
    # Smart Fuzzing Strategies
    # ========================================================================
    
    def fuzz_generate_ac_mutations(self, iterations=100) -> List[Dict]:
        """
        Fuzz GENERATE AC command with cryptographic mutations.
        
        Mix up ARQC/AC responses to cause unusual behavior:
        - Reboot card
        - Unlock security features
        - Trigger error states
        """
        print(f"\n🧠 Smart GENERATE AC Fuzzing ({iterations} iterations)")
        results = []
        
        for i in range(iterations):
            print(f"Iteration {i+1}/{iterations}", end="\r")
            
            # Mutation strategies
            strategies = [
                self._fuzz_ac_reference_control,
                self._fuzz_ac_cdol_data,
                self._fuzz_ac_cryptogram_version,
                self._fuzz_ac_amount_overflow,
                self._fuzz_ac_invalid_country,
                self._fuzz_ac_reserved_bits,
            ]
            
            strategy = random.choice(strategies)
            result = strategy()
            result["iteration"] = i + 1
            results.append(result)
            
            # Check for interesting responses
            if result.get("sw1", 0) not in [0x90, 0x6A, 0x6B, 0x6D, 0x6E]:
                print(f"\n⚠️  Unusual response: {result}")
            
            time.sleep(0.05)  # Avoid overwhelming card
        
        self.fuzz_results.extend(results)
        return results
    
    def _fuzz_ac_reference_control(self) -> Dict:
        """Fuzz AC reference control byte (P1)."""
        # Normal: 0x80=ARQC, 0x00=AAC, 0x40=TC
        # Try reserved/invalid values
        invalid_refs = [0x01, 0x10, 0x20, 0x30, 0x50, 0x60, 0x70, 0xC0, 0xFF]
        ref_control = random.choice(invalid_refs)
        
        cdol_data = [0x80, 0x08] + [0x00] * 8
        apdu = [0x80, 0xAE, ref_control, 0x00, len(cdol_data)] + cdol_data + [0x00]
        
        try:
            response, sw1, sw2 = self.send_apdu(apdu)
            return {
                "strategy": "ac_reference_control",
                "ref_control": f"{ref_control:02X}",
                "sw1": sw1,
                "sw2": sw2,
                "response_len": len(response),
                "interesting": sw1 not in [0x6A, 0x6B]
            }
        except Exception as e:
            return {
                "strategy": "ac_reference_control",
                "error": str(e),
                "interesting": True
            }
    
    def _fuzz_ac_cdol_data(self) -> Dict:
        """Fuzz CDOL data structure."""
        # Build malformed CDOL
        cdol_mutations = [
            [0x80, 0xFF] + [0x00] * 253,  # Maximum length
            [0x80, 0x00],  # Empty data
            [0x80, 0x08, 0xFF] * 3,  # Repeated data
            [0xFF, 0xFF, 0xFF, 0xFF],  # Invalid structure
            [0x80, 0x08] + [random.randint(0, 255) for _ in range(8)],  # Random
        ]
        
        cdol_data = random.choice(cdol_mutations)
        apdu = [0x80, 0xAE, 0x80, 0x00, len(cdol_data)] + cdol_data + [0x00]
        
        try:
            response, sw1, sw2 = self.send_apdu(apdu)
            return {
                "strategy": "ac_cdol_data",
                "cdol_hex": ''.join(f'{b:02X}' for b in cdol_data[:16]),
                "sw1": sw1,
                "sw2": sw2,
                "interesting": sw1 == 0x6F or len(response) > 100
            }
        except Exception as e:
            return {"strategy": "ac_cdol_data", "error": str(e), "interesting": True}
    
    def _fuzz_ac_cryptogram_version(self) -> Dict:
        """Fuzz cryptogram version number (CVN) in CDOL."""
        # Normal CVN: 0x0A, 0x12, 0x14, 0x18
        # Try invalid versions
        invalid_cvn = [0x00, 0x01, 0xFF, 0x99, random.randint(0x20, 0xFE)]
        cvn = random.choice(invalid_cvn)
        
        cdol_data = [0x80, 0x10]
        cdol_data.extend([0x00] * 6)  # Amount, etc.
        cdol_data.append(cvn)  # CVN
        cdol_data.extend([0x00] * 8)  # Rest of data
        
        apdu = [0x80, 0xAE, 0x80, 0x00, len(cdol_data)] + cdol_data + [0x00]
        
        try:
            response, sw1, sw2 = self.send_apdu(apdu)
            return {
                "strategy": "ac_cryptogram_version",
                "cvn": f"{cvn:02X}",
                "sw1": sw1,
                "sw2": sw2,
                "interesting": sw1 not in [0x6A, 0x90]
            }
        except Exception as e:
            return {"strategy": "ac_cryptogram_version", "error": str(e), "interesting": True}
    
    def _fuzz_ac_amount_overflow(self) -> Dict:
        """Fuzz with overflow amounts."""
        # Try extreme amounts
        overflow_amounts = [
            0xFFFFFFFFFFFF,  # Maximum
            0x000000000000,  # Zero
            0x999999999999,  # All 9s (invalid BCD)
            0xABCDEF123456,  # Invalid BCD
        ]
        
        amount = random.choice(overflow_amounts)
        amount_bytes = struct.pack('>Q', amount)[-6:]  # Last 6 bytes
        
        cdol_data = [0x80, 0x08]
        cdol_data.extend(amount_bytes)
        cdol_data.extend([0x08, 0x40])  # Country, terminal type
        
        apdu = [0x80, 0xAE, 0x80, 0x00, len(cdol_data)] + cdol_data + [0x00]
        
        try:
            response, sw1, sw2 = self.send_apdu(apdu)
            return {
                "strategy": "ac_amount_overflow",
                "amount": f"{amount:012X}",
                "sw1": sw1,
                "sw2": sw2,
                "interesting": sw1 not in [0x6A, 0x90]
            }
        except Exception as e:
            return {"strategy": "ac_amount_overflow", "error": str(e), "interesting": True}
    
    def _fuzz_ac_invalid_country(self) -> Dict:
        """Fuzz with invalid country codes."""
        # Try reserved/invalid country codes
        invalid_countries = [0x0000, 0xFFFF, 0x9999, 0x1234, random.randint(1000, 9999)]
        country = random.choice(invalid_countries)
        
        cdol_data = [0x80, 0x0A]
        cdol_data.extend([0x00] * 6)  # Amount
        cdol_data.extend(struct.pack('>H', country))  # Country code
        cdol_data.extend([0x09, 0x78])  # Terminal type
        
        apdu = [0x80, 0xAE, 0x80, 0x00, len(cdol_data)] + cdol_data + [0x00]
        
        try:
            response, sw1, sw2 = self.send_apdu(apdu)
            return {
                "strategy": "ac_invalid_country",
                "country": f"{country:04X}",
                "sw1": sw1,
                "sw2": sw2,
                "interesting": sw1 not in [0x6A, 0x90]
            }
        except Exception as e:
            return {"strategy": "ac_invalid_country", "error": str(e), "interesting": True}
    
    def _fuzz_ac_reserved_bits(self) -> Dict:
        """Set reserved bits in AC command."""
        # P2 byte has reserved bits
        reserved_p2 = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xFF]
        p2 = random.choice(reserved_p2)
        
        cdol_data = [0x80, 0x08] + [0x00] * 8
        apdu = [0x80, 0xAE, 0x80, p2, len(cdol_data)] + cdol_data + [0x00]
        
        try:
            response, sw1, sw2 = self.send_apdu(apdu)
            return {
                "strategy": "ac_reserved_bits",
                "p2": f"{p2:02X}",
                "sw1": sw1,
                "sw2": sw2,
                "interesting": sw1 != 0x6A
            }
        except Exception as e:
            return {"strategy": "ac_reserved_bits", "error": str(e), "interesting": True}
    
    # ========================================================================
    # TLV Fuzzing
    # ========================================================================
    
    def fuzz_tlv_structures(self, base_tlv: bytes, iterations=100) -> List[Dict]:
        """
        Advanced TLV fuzzing with intelligent mutations.
        
        Fuzzes:
        - Tag lengths (overflow, underflow)
        - Nested TLV structures
        - Invalid tag classes
        - Length encoding (short/long form)
        """
        print(f"\n🧬 Advanced TLV Fuzzing ({iterations} iterations)")
        results = []
        
        for i in range(iterations):
            print(f"Iteration {i+1}/{iterations}", end="\r")
            
            strategies = [
                self._tlv_length_overflow,
                self._tlv_length_underflow,
                self._tlv_nested_bomb,
                self._tlv_invalid_class,
                self._tlv_long_form_abuse,
                self._tlv_truncated_value,
            ]
            
            strategy = random.choice(strategies)
            mutated = strategy(base_tlv)
            
            # Try using mutated TLV in GPO
            apdu = [0x80, 0xA8, 0x00, 0x00, len(mutated)] + list(mutated) + [0x00]
            
            try:
                response, sw1, sw2 = self.send_apdu(apdu)
                results.append({
                    "iteration": i + 1,
                    "strategy": strategy.__name__,
                    "mutated_hex": mutated.hex()[:32],
                    "sw1": sw1,
                    "sw2": sw2,
                    "interesting": sw1 not in [0x90, 0x6A, 0x6B]
                })
            except Exception as e:
                results.append({
                    "iteration": i + 1,
                    "strategy": strategy.__name__,
                    "error": str(e),
                    "interesting": True
                })
        
        self.fuzz_results.extend(results)
        return results
    
    def _tlv_length_overflow(self, tlv: bytes) -> bytes:
        """Set TLV length to overflow value."""
        if len(tlv) < 2:
            return tlv
        data = bytearray(tlv)
        # Long form: 0x81 = 1 byte length, 0x82 = 2 byte length
        overflow_lengths = [0xFF, 0x81, 0xFF, 0x82, 0xFF, 0xFF]
        data[1:1+len(overflow_lengths)] = overflow_lengths
        return bytes(data)
    
    def _tlv_length_underflow(self, tlv: bytes) -> bytes:
        """Set TLV length smaller than actual data."""
        if len(tlv) < 3:
            return tlv
        data = bytearray(tlv)
        data[1] = 0x01  # Claim only 1 byte
        return bytes(data)
    
    def _tlv_nested_bomb(self, tlv: bytes) -> bytes:
        """Create deeply nested TLV (decompression bomb style)."""
        # Nest TLV 10 levels deep
        nested = bytearray(tlv)
        for _ in range(10):
            nested = bytearray([0x70, len(nested)]) + nested
        return bytes(nested)
    
    def _tlv_invalid_class(self, tlv: bytes) -> bytes:
        """Use invalid tag class bits."""
        data = bytearray(tlv)
        if data:
            # Tag class in bits 7-6: 00=universal, 01=application, 10=context, 11=private
            # Set to reserved/invalid combinations
            data[0] = (data[0] & 0x3F) | random.choice([0xC0, 0x80, 0x40])
        return bytes(data)
    
    def _tlv_long_form_abuse(self, tlv: bytes) -> bytes:
        """Abuse long-form length encoding."""
        if len(tlv) < 2:
            return tlv
        data = bytearray(tlv)
        # Use unnecessarily long length encoding
        # 0x84 = 4 bytes for length (way more than needed)
        data[1:2] = [0x84, 0x00, 0x00, 0x00, 0x08]
        return bytes(data)
    
    def _tlv_truncated_value(self, tlv: bytes) -> bytes:
        """Truncate TLV value (length claims more than available)."""
        if len(tlv) < 3:
            return tlv
        data = bytearray(tlv)
        data[1] = 0xFF  # Claim 255 bytes
        return bytes(data[:5])  # But only provide 5
    
    # ========================================================================
    # P1/P2 Parameter Fuzzing
    # ========================================================================
    
    def fuzz_p1_p2_parameters(self, base_command: List[int], iterations=100) -> List[Dict]:
        """
        Systematically fuzz P1/P2 parameters.
        
        Tests all combinations and reserved values.
        """
        print(f"\n🎚️  P1/P2 Parameter Fuzzing ({iterations} iterations)")
        results = []
        
        cla, ins = base_command[0], base_command[1]
        data = base_command[5:] if len(base_command) > 5 else []
        
        for i in range(iterations):
            print(f"Iteration {i+1}/{iterations}", end="\r")
            
            # Strategies for P1/P2
            strategies = [
                (0xFF, 0xFF),  # All bits set
                (0x00, 0x00),  # All bits clear
                (random.randint(0, 255), random.randint(0, 255)),  # Random
                (0xAA, 0x55),  # Alternating bits
                (0x80, 0x00),  # MSB only
                (0x00, 0x80),  # MSB only
            ]
            
            p1, p2 = random.choice(strategies)
            
            apdu = [cla, ins, p1, p2]
            if data:
                apdu.append(len(data))
                apdu.extend(data)
            apdu.append(0x00)  # Le
            
            try:
                response, sw1, sw2 = self.send_apdu(apdu)
                results.append({
                    "iteration": i + 1,
                    "p1": f"{p1:02X}",
                    "p2": f"{p2:02X}",
                    "sw1": sw1,
                    "sw2": sw2,
                    "response_len": len(response),
                    "interesting": sw1 not in [0x90, 0x6A, 0x6B, 0x6D]
                })
            except Exception as e:
                results.append({
                    "iteration": i + 1,
                    "p1": f"{p1:02X}",
                    "p2": f"{p2:02X}",
                    "error": str(e),
                    "interesting": True
                })
        
        self.fuzz_results.extend(results)
        return results
    
    # ========================================================================
    # State Machine Fuzzing
    # ========================================================================
    
    def fuzz_command_sequence(self, iterations=50) -> List[Dict]:
        """
        Fuzz by sending commands in unexpected order.
        
        Tests card state machine robustness.
        """
        print(f"\n🔄 State Machine Fuzzing ({iterations} iterations)")
        results = []
        
        # Common EMV commands
        commands = {
            "SELECT": [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00],
            "GPO": [0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00],
            "READ": [0x00, 0xB2, 0x01, 0x0C, 0x00],
            "GENERATE_AC": [0x80, 0xAE, 0x80, 0x00, 0x0A, 0x80, 0x08] + [0x00]*8 + [0x00],
            "VERIFY": [0x00, 0x20, 0x00, 0x80, 0x08, 0x12, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        }
        
        for i in range(iterations):
            print(f"Iteration {i+1}/{iterations}", end="\r")
            
            # Randomize command order
            cmd_sequence = random.sample(list(commands.keys()), k=random.randint(2, 4))
            
            sequence_results = []
            for cmd_name in cmd_sequence:
                apdu = commands[cmd_name]
                try:
                    response, sw1, sw2 = self.send_apdu(apdu)
                    sequence_results.append({
                        "command": cmd_name,
                        "sw": f"{sw1:02X}{sw2:02X}"
                    })
                except Exception as e:
                    sequence_results.append({
                        "command": cmd_name,
                        "error": str(e)
                    })
            
            results.append({
                "iteration": i + 1,
                "sequence": cmd_sequence,
                "results": sequence_results,
                "interesting": any(r.get("error") for r in sequence_results)
            })
        
        self.fuzz_results.extend(results)
        return results
    
    # ========================================================================
    # Timing Attack Fuzzing
    # ========================================================================
    
    def fuzz_timing_attacks(self, command: List[int], iterations=50) -> List[Dict]:
        """
        Test timing-based race conditions.
        
        Varies command delays to trigger race conditions.
        """
        print(f"\n⏱️  Timing Attack Fuzzing ({iterations} iterations)")
        results = []
        
        delays = [0.0, 0.001, 0.01, 0.1, 0.5, 1.0, 2.0]
        
        for i in range(iterations):
            print(f"Iteration {i+1}/{iterations}", end="\r")
            
            delay = random.choice(delays)
            
            # Send command rapidly with varying delays
            start = time.time()
            try:
                response, sw1, sw2 = self.send_apdu(command)
                elapsed = time.time() - start
                
                results.append({
                    "iteration": i + 1,
                    "delay_before": delay,
                    "elapsed": elapsed,
                    "sw1": sw1,
                    "sw2": sw2,
                    "interesting": elapsed > 1.0  # Suspiciously long
                })
            except Exception as e:
                results.append({
                    "iteration": i + 1,
                    "delay_before": delay,
                    "error": str(e),
                    "interesting": True
                })
            
            time.sleep(delay)
        
        self.fuzz_results.extend(results)
        return results
    
    # ========================================================================
    # Reporting
    # ========================================================================
    
    def save_results(self, filename="smart_fuzz_results.json"):
        """Save fuzzing results to file."""
        import json
        with open(filename, 'w') as f:
            json.dump({
                "total_iterations": len(self.fuzz_results),
                "interesting_count": sum(1 for r in self.fuzz_results if r.get("interesting")),
                "results": self.fuzz_results
            }, f, indent=2)
        print(f"\n💾 Results saved: {filename}")
    
    def print_summary(self):
        """Print fuzzing summary."""
        print(f"\n{'='*60}")
        print(f"🧠 Smart Fuzzing Summary")
        print(f"{'='*60}")
        print(f"Total iterations: {len(self.fuzz_results)}")
        
        interesting = [r for r in self.fuzz_results if r.get("interesting")]
        print(f"Interesting responses: {len(interesting)}")
        
        errors = [r for r in self.fuzz_results if "error" in r]
        print(f"Errors/Crashes: {len(errors)}")
        
        if interesting:
            print(f"\nTop interesting findings:")
            for r in interesting[:5]:
                strategy = r.get("strategy", "unknown")
                sw = f"{r.get('sw1', 0):02X}{r.get('sw2', 0):02X}"
                print(f"  - {strategy}: SW={sw}")
        
        print(f"{'='*60}\n")


def main():
    """CLI interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Smart APDU Fuzzer")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--iterations", type=int, default=100, help="Fuzzing iterations")
    parser.add_argument("--mode", choices=["generate_ac", "tlv", "p1p2", "sequence", "timing"],
                        default="generate_ac", help="Fuzzing mode")
    
    args = parser.parse_args()
    
    fuzzer = SmartAPDUFuzzer(debug=args.debug)
    
    if not fuzzer.connect():
        print("❌ Failed to connect to card")
        return 1
    
    print(f"✅ Connected to card")
    
    # Run selected fuzzing mode
    if args.mode == "generate_ac":
        fuzzer.fuzz_generate_ac_mutations(args.iterations)
    elif args.mode == "tlv":
        base_tlv = bytes([0x83, 0x00])
        fuzzer.fuzz_tlv_structures(base_tlv, args.iterations)
    elif args.mode == "p1p2":
        base_cmd = [0x80, 0xA8]
        fuzzer.fuzz_p1_p2_parameters(base_cmd, args.iterations)
    elif args.mode == "sequence":
        fuzzer.fuzz_command_sequence(args.iterations)
    elif args.mode == "timing":
        cmd = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00]
        fuzzer.fuzz_timing_attacks(cmd, args.iterations)
    
    fuzzer.print_summary()
    fuzzer.save_results()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
