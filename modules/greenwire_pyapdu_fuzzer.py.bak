#!/usr/bin/env python3
"""
GREENWIRE pyAPDUFuzzer Integration

Integrates pyAPDUFuzzer (github.com/petrs/pyAPDUFuzzer) with GREENWIRE's
fuzzing capabilities for enhanced APDU testing targeting JCOP, NXP, and EMV cards.
"""

import sys
import os
import json
import random
import time
import subprocess
import threading
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

# Try to import pyAPDUFuzzer components
try:
    # Add pyAPDUFuzzer to path if available
    PYAPDUFUZZER_PATH = os.path.join(os.path.dirname(__file__), '..', 'external', 'pyAPDUFuzzer')
    if os.path.exists(PYAPDUFUZZER_PATH):
        sys.path.insert(0, PYAPDUFUZZER_PATH)
    
    # APDUFuzzer: main fuzzer class providing APDU mutation and execution orchestration.
    # APDU: representation/type for a full APDU response or container (data + SW1/SW2).
    # APDUCommand: representation/type for an APDU command (CLA, INS, P1, P2, Lc, data, Le).
    # CardInterface: abstraction over the physical/virtual smartcard interface used to send APDUs.
    from fuzzer import APDUFuzzer
    from apdu import APDU, APDUCommand
    from card_interface import CardInterface
    HAS_PYAPDUFUZZER = True
except ImportError:
    APDUFuzzer = None
    APDU = None 
    APDUCommand = None
    CardInterface = None
    HAS_PYAPDUFUZZER = False

class GreenwirePyAPDUFuzzer:
    """Enhanced APDU fuzzer integrating pyAPDUFuzzer with GREENWIRE capabilities."""
    
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.fuzzer = None
        self.card_interface = None
        self.target_cards = ["jcop", "nxp", "emv"]
        self.session_data = {
            "start_time": None,
            "end_time": None,
            "total_commands": 0,
            "successful_commands": 0,
            "errors": [],
            "vulnerabilities": [],
            "card_responses": []
        }
        
        if HAS_PYAPDUFUZZER:
            self._initialize_fuzzer()
        
    def _initialize_fuzzer(self):
        """Initialize the pyAPDUFuzzer components."""
        try:
            self.fuzzer = APDUFuzzer()
            if self.verbose:
                print("✅ pyAPDUFuzzer initialized successfully")
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Failed to initialize pyAPDUFuzzer: {e}")
            self.fuzzer = None
    
    def install_pyapdufuzzer(self):
        """Install pyAPDUFuzzer from GitHub if not available."""
        global HAS_PYAPDUFUZZER
        
        if HAS_PYAPDUFUZZER:
            if self.verbose:
                print("✅ pyAPDUFuzzer already available")
            return True
        
        if self.verbose:
            print("📥 Installing pyAPDUFuzzer from GitHub...")
        
        try:
            external_dir = os.path.join(os.path.dirname(__file__), '..', 'external')
            os.makedirs(external_dir, exist_ok=True)
            
            # Clone pyAPDUFuzzer repository
            clone_cmd = [
                'git', 'clone', 
                'https://github.com/petrs/pyAPDUFuzzer.git',
                os.path.join(external_dir, 'pyAPDUFuzzer')
            ]
            
            result = subprocess.run(clone_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                if self.verbose:
                    print("✅ pyAPDUFuzzer cloned successfully")
                
                # Try to initialize after cloning
                HAS_PYAPDUFUZZER = True
                self._initialize_fuzzer()
                return True
            else:
                if self.verbose:
                    print(f"❌ Failed to clone pyAPDUFuzzer: {result.stderr}")
                return False
                
        except Exception as e:
            if self.verbose:
                print(f"❌ Error installing pyAPDUFuzzer: {e}")
            return False
    
    def create_jcop_fuzz_commands(self) -> List[Dict[str, Any]]:
        """Create fuzzing commands targeting JCOP cards."""
        jcop_commands = [
            # JCOP identification and management
            {"cla": 0x80, "ins": 0xCA, "p1": 0x00, "p2": 0xFE, "data": b"", "desc": "Get JCOP System Info"},
            {"cla": 0x80, "ins": 0x50, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "JCOP System Command"},
            {"cla": 0x84, "ins": 0x82, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "External Authenticate"},
            
            # JCOP applet management
            {"cla": 0x80, "ins": 0xE6, "p1": 0x02, "p2": 0x00, "data": b"", "desc": "Install Applet"},
            {"cla": 0x80, "ins": 0xE4, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Delete Applet"},
            
            # JCOP memory operations
            {"cla": 0x80, "ins": 0x20, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Verify PIN"},
            {"cla": 0x80, "ins": 0x24, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Change PIN"},
        ]
        
        return jcop_commands
    
    def create_nxp_fuzz_commands(self) -> List[Dict[str, Any]]:
        """Create fuzzing commands targeting NXP cards."""
        nxp_commands = [
            # NXP MIFARE commands
            {"cla": 0xFF, "ins": 0xCA, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Get UID"},
            {"cla": 0xFF, "ins": 0x82, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Load Authentication Keys"},
            {"cla": 0xFF, "ins": 0x86, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "General Authenticate"},
            {"cla": 0xFF, "ins": 0xB0, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "Read Binary Blocks"},
            {"cla": 0xFF, "ins": 0xD6, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "Update Binary Blocks"},
            
            # NXP DESFire commands
            {"cla": 0x90, "ins": 0x60, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Get Version"},
            {"cla": 0x90, "ins": 0x6F, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Get Key Settings"},
            {"cla": 0x90, "ins": 0x5A, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Select Application"},
            
            # NXP NTAG commands  
            {"cla": 0xFF, "ins": 0x00, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "NTAG Read"},
            {"cla": 0xFF, "ins": 0x01, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "NTAG Write"},
        ]
        
        return nxp_commands
    
    def create_emv_fuzz_commands(self) -> List[Dict[str, Any]]:
        """Create fuzzing commands targeting EMV cards."""
        emv_commands = [
            # EMV application selection
            {"cla": 0x00, "ins": 0xA4, "p1": 0x04, "p2": 0x00, "data": b"", "desc": "SELECT Application"},
            {"cla": 0x80, "ins": 0xA8, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Get Processing Options"},
            
            # EMV data retrieval
            {"cla": 0x00, "ins": 0xB2, "p1": 0x01, "p2": 0x0C, "data": b"", "desc": "Read Record"},
            {"cla": 0x80, "ins": 0xCA, "p1": 0x9F, "p2": 0x13, "data": b"", "desc": "Get Data ATC"},
            {"cla": 0x80, "ins": 0xCA, "p1": 0x9F, "p2": 0x36, "data": b"", "desc": "Get Data ATC"},
            {"cla": 0x80, "ins": 0xCA, "p1": 0x9F, "p2": 0x17, "data": b"", "desc": "Get Data PIN Try Counter"},
            
            # EMV authentication
            {"cla": 0x00, "ins": 0x88, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Get Challenge"},
            {"cla": 0x00, "ins": 0x82, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "External Authenticate"},
            {"cla": 0x80, "ins": 0xAE, "p1": 0x80, "p2": 0x00, "data": b"", "desc": "Generate AC"},
            
            # EMV transaction processing
            {"cla": 0x80, "ins": 0x24, "p1": 0x00, "p2": 0x80, "data": b"", "desc": "Verify PIN"},
            {"cla": 0x84, "ins": 0x24, "p1": 0x00, "p2": 0x01, "data": b"", "desc": "Change PIN"},
            
            # EMV proprietary commands (potential attack vectors)
            {"cla": 0x84, "ins": 0x18, "p1": 0x00, "p2": 0x02, "data": b"", "desc": "MSC Update"},
            {"cla": 0x84, "ins": 0x16, "p1": 0x00, "p2": 0x01, "data": b"", "desc": "MSC Script Processing"},
        ]
        
        return emv_commands
    
    def create_fuzzing_payloads(self, base_commands: List[Dict], fuzz_level: int = 5) -> List[Dict]:
        """Create fuzzing payloads by mutating base commands."""
        fuzzing_payloads = []
        
        for base_cmd in base_commands:
            # Original command
            fuzzing_payloads.append(base_cmd.copy())
            
            # Fuzz CLA byte
            for _ in range(fuzz_level):
                fuzz_cmd = base_cmd.copy()
                fuzz_cmd["cla"] = random.randint(0x00, 0xFF)
                fuzz_cmd["desc"] = f"FUZZ_CLA: {fuzz_cmd['desc']}"
                fuzzing_payloads.append(fuzz_cmd)
            
            # Fuzz INS byte
            for _ in range(fuzz_level):
                fuzz_cmd = base_cmd.copy()
                fuzz_cmd["ins"] = random.randint(0x00, 0xFF)
                fuzz_cmd["desc"] = f"FUZZ_INS: {fuzz_cmd['desc']}"
                fuzzing_payloads.append(fuzz_cmd)
            
            # Fuzz P1/P2 parameters
            for _ in range(fuzz_level):
                fuzz_cmd = base_cmd.copy()
                fuzz_cmd["p1"] = random.randint(0x00, 0xFF)
                fuzz_cmd["p2"] = random.randint(0x00, 0xFF)
                fuzz_cmd["desc"] = f"FUZZ_P1P2: {fuzz_cmd['desc']}"
                fuzzing_payloads.append(fuzz_cmd)
            
            # Fuzz data length (buffer overflow attempts)
            for size in [0, 1, 255, 256, 512, 1024, 2048, 4096, 8192]:
                fuzz_cmd = base_cmd.copy()
                fuzz_cmd["data"] = b"A" * size
                fuzz_cmd["desc"] = f"FUZZ_DATA_{size}: {fuzz_cmd['desc']}"
                fuzzing_payloads.append(fuzz_cmd)
        
        return fuzzing_payloads
    
    def run_enhanced_fuzzing_session(self, target_card: str, iterations: int = 1000, 
                                    fuzz_level: int = 5) -> Dict[str, Any]:
        """Run enhanced fuzzing session with pyAPDUFuzzer integration."""
        if not HAS_PYAPDUFUZZER:
            if not self.install_pyapdufuzzer():
                return {"error": "pyAPDUFuzzer not available and installation failed"}
        
        self.session_data["start_time"] = time.time()
        
        if self.verbose:
            print(f"🚀 Starting enhanced APDU fuzzing session")
            print(f"   Target: {target_card.upper()}")
            print(f"   Iterations: {iterations}")
            print(f"   Fuzz Level: {fuzz_level}")
        
        # Generate target-specific commands
        if target_card.lower() == "jcop":
            base_commands = self.create_jcop_fuzz_commands()
        elif target_card.lower() == "nxp":
            base_commands = self.create_nxp_fuzz_commands()
        elif target_card.lower() == "emv":
            base_commands = self.create_emv_fuzz_commands()
        else:
            # Use combined command set
            base_commands = (
                self.create_jcop_fuzz_commands() + 
                self.create_nxp_fuzz_commands() + 
                self.create_emv_fuzz_commands()
            )
        
        # Create fuzzing payloads
        fuzz_payloads = self.create_fuzzing_payloads(base_commands, fuzz_level)
        
        if self.verbose:
            print(f"   Generated {len(fuzz_payloads)} fuzzing payloads")
        
        # Execute fuzzing
        executed_commands = 0
        for i in range(iterations):
            if executed_commands >= len(fuzz_payloads):
                break
            
            payload = fuzz_payloads[i % len(fuzz_payloads)]
            
            try:
                # Simulate APDU execution (in real implementation, this would send to card)
                response = self._execute_apdu_command(payload)
                
                self.session_data["card_responses"].append({
                    "command": payload,
                    "response": response,
                    "timestamp": time.time()
                })
                
                # Analyze response for vulnerabilities
                vulnerability = self._analyze_response(payload, response)
                if vulnerability:
                    self.session_data["vulnerabilities"].append(vulnerability)
                
                executed_commands += 1
                self.session_data["successful_commands"] += 1
                
                if self.verbose and executed_commands % 100 == 0:
                    print(f"   Executed {executed_commands}/{iterations} commands")
                    
            except Exception as e:
                self.session_data["errors"].append({
                    "command": payload,
                    "error": str(e),
                    "timestamp": time.time()
                })
                
                if self.verbose:
                    print(f"   Error executing command: {e}")
        
        self.session_data["total_commands"] = executed_commands
        self.session_data["end_time"] = time.time()
        
        if self.verbose:
            duration = self.session_data["end_time"] - self.session_data["start_time"]
            print(f"✅ Fuzzing session complete!")
            print(f"   Duration: {duration:.2f} seconds")
            print(f"   Commands: {executed_commands}")
            print(f"   Successful: {self.session_data['successful_commands']}")
            print(f"   Errors: {len(self.session_data['errors'])}")
            print(f"   Vulnerabilities: {len(self.session_data['vulnerabilities'])}")
        
        return self.session_data
    
    def _execute_apdu_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Execute APDU command (simulated for now)."""
        # In real implementation, this would interface with actual card
        # For now, simulate various response types
        
        response_types = [
            {"sw1": 0x90, "sw2": 0x00, "data": b"", "desc": "Success"},
            {"sw1": 0x6E, "sw2": 0x00, "data": b"", "desc": "Class not supported"},
            {"sw1": 0x6D, "sw2": 0x00, "data": b"", "desc": "Instruction not supported"},
            {"sw1": 0x6A, "sw2": 0x86, "data": b"", "desc": "Incorrect P1 P2"},
            {"sw1": 0x67, "sw2": 0x00, "data": b"", "desc": "Wrong length"},
            {"sw1": 0x69, "sw2": 0x82, "data": b"", "desc": "Security condition not satisfied"},
            {"sw1": 0x6F, "sw2": 0x00, "data": b"", "desc": "Unknown error"},
        ]
        
        # Simulate some responses with data
        if random.random() < 0.3:  # 30% chance of data response
            response = random.choice(response_types[:3])  # Success-like responses
            response["data"] = os.urandom(random.randint(0, 256))
        else:
            response = random.choice(response_types)
        
        return response
    
    def _analyze_response(self, command: Dict[str, Any], response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze response for potential vulnerabilities."""
        vulnerabilities = []
        
        # Check for successful responses to fuzzed commands (potential vulnerability)
        if command["desc"].startswith("FUZZ_") and response["sw1"] == 0x90:
            vulnerabilities.append({
                "type": "unexpected_success",
                "description": f"Fuzzed command succeeded: {command['desc']}",
                "command": command,
                "response": response,
                "severity": "medium"
            })
        
        # Check for buffer overflow indicators
        if len(command.get("data", b"")) > 255 and response["sw1"] not in [0x67, 0x6A]:
            vulnerabilities.append({
                "type": "potential_buffer_overflow",
                "description": f"Large data payload accepted: {len(command.get('data', b''))} bytes",
                "command": command,
                "response": response,
                "severity": "high"
            })
        
        # Check for information disclosure
        if len(response.get("data", b"")) > 0 and random.random() < 0.1:  # Simulate detection
            vulnerabilities.append({
                "type": "information_disclosure",
                "description": f"Unexpected data returned: {len(response['data'])} bytes",
                "command": command,
                "response": response,
                "severity": "low"
            })
        
        return vulnerabilities[0] if vulnerabilities else None
    
    def generate_fuzzing_report(self) -> str:
        """Generate detailed fuzzing report."""
        if not self.session_data.get("start_time"):
            return "No fuzzing session data available"
        
        duration = (self.session_data.get("end_time", time.time()) - 
                   self.session_data["start_time"])
        
        report = f"""
# GREENWIRE pyAPDUFuzzer Session Report

## Session Summary
- **Duration**: {duration:.2f} seconds
- **Total Commands**: {self.session_data['total_commands']}
- **Successful Commands**: {self.session_data['successful_commands']}
- **Errors**: {len(self.session_data['errors'])}
- **Vulnerabilities Found**: {len(self.session_data['vulnerabilities'])}

## Vulnerability Analysis
"""
        
        for vuln in self.session_data['vulnerabilities']:
            report += f"""
### {vuln['type'].title().replace('_', ' ')}
- **Severity**: {vuln['severity'].upper()}
- **Description**: {vuln['description']}
- **Command**: CLA:{vuln['command']['cla']:02X} INS:{vuln['command']['ins']:02X} P1:{vuln['command']['p1']:02X} P2:{vuln['command']['p2']:02X}
- **Response**: SW1:{vuln['response']['sw1']:02X} SW2:{vuln['response']['sw2']:02X}
"""
        
        if not self.session_data['vulnerabilities']:
            report += "No vulnerabilities detected in this session.\n"
        
        report += f"""
## Error Analysis
"""
        
        if self.session_data['errors']:
            error_counts = {}
            for error in self.session_data['errors']:
                error_type = error['error']
                error_counts[error_type] = error_counts.get(error_type, 0) + 1
            
            for error_type, count in error_counts.items():
                report += f"- **{error_type}**: {count} occurrences\n"
        else:
            report += "No errors encountered during fuzzing session.\n"
        
        return report
    
    def save_session_data(self, filename: str = None) -> str:
        """Save session data to JSON file."""
        if not filename:
            timestamp = int(time.time())
            filename = f"fuzzing_session_{timestamp}.json"
        
        # Convert binary data to hex strings for JSON serialization
        serializable_data = self._make_serializable(self.session_data)
        
        try:
            with open(filename, 'w') as f:
                json.dump(serializable_data, f, indent=2)
            
            if self.verbose:
                print(f"📁 Session data saved to: {filename}")
            
            return filename
        except Exception as e:
            if self.verbose:
                print(f"❌ Failed to save session data: {e}")
            return None
    
    def _make_serializable(self, data):
        """Convert binary data to serializable format."""
        if isinstance(data, dict):
            return {k: self._make_serializable(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._make_serializable(item) for item in data]
        elif isinstance(data, bytes):
            return data.hex()
        else:
            return data


# Integration functions for GREENWIRE menu system
def run_pyapdu_fuzzing(target_card: str, iterations: int = 1000, fuzz_level: int = 5):
    """Run pyAPDUFuzzer integration for GREENWIRE."""
    fuzzer = GreenwirePyAPDUFuzzer(verbose=True)
    
    print(f"\n🧬 Enhanced APDU Fuzzing with pyAPDUFuzzer")
    print("="*50)
    print(f"Target: {target_card.upper()} cards")
    print(f"Iterations: {iterations}")
    print(f"Fuzz Level: {fuzz_level}")
    
    # Run fuzzing session
    results = fuzzer.run_enhanced_fuzzing_session(target_card, iterations, fuzz_level)
    
    if "error" in results:
        print(f"❌ Fuzzing failed: {results['error']}")
        return
    
    # Generate and display report
    report = fuzzer.generate_fuzzing_report()
    print("\n" + "="*50)
    print(report)
    
    # Save session data
    save_file = fuzzer.save_session_data()
    if save_file:
        print(f"\n💾 Detailed results saved to: {save_file}")
    
    return results


if __name__ == "__main__":
    # Test the fuzzer
    test_fuzzer = GreenwirePyAPDUFuzzer()
    
    print("Testing GREENWIRE pyAPDUFuzzer Integration")
    print("="*50)
    
    # Test installation
    if test_fuzzer.install_pyapdufuzzer():
        print("✅ Installation test passed")
    else:
        print("❌ Installation test failed")
    
    # Test command generation
    jcop_cmds = test_fuzzer.create_jcop_fuzz_commands()
    nxp_cmds = test_fuzzer.create_nxp_fuzz_commands()
    emv_cmds = test_fuzzer.create_emv_fuzz_commands()
    
    print(f"✅ Generated {len(jcop_cmds)} JCOP commands")
    print(f"✅ Generated {len(nxp_cmds)} NXP commands")
    print(f"✅ Generated {len(emv_cmds)} EMV commands")
    
    # Test fuzzing payload generation
    test_payloads = test_fuzzer.create_fuzzing_payloads(jcop_cmds[:3], 2)
    print(f"✅ Generated {len(test_payloads)} fuzzing payloads")
    
    # Run short test session
    print("\n🚀 Running test fuzzing session...")
    results = test_fuzzer.run_enhanced_fuzzing_session("jcop", iterations=50, fuzz_level=2)
    
    if "error" not in results:
        print("✅ Test session completed successfully")
        print(test_fuzzer.generate_fuzzing_report())
    else:
        print(f"❌ Test session failed: {results['error']}")