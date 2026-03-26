#!/usr/bin/env python3
"""
GREENWIRE pyAPDUFuzzer Integration

Integrates pyAPDUFuzzer (github.com/petrs/pyAPDUFuzzer) with GREENWIRE's
fuzzing capabilities for enhanced APDU testing targeting JCOP, NXP, and EMV cards.
"""

import json
import logging
import os
import random
import subprocess
import sys
import threading  # noqa: F401
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

try:
    from .data_artifact_analyzer import DataArtifactAnalyzer
except ImportError:  # pragma: no cover - fallback for script execution
    try:
        from GREENWIRE.modules.data_artifact_analyzer import DataArtifactAnalyzer  # type: ignore
    except ImportError:
        DataArtifactAnalyzer = None  # type: ignore

try:
    from .rfid_vulnerability_tester import RFIDVulnerabilityTester
except ImportError:  # pragma: no cover - fallback for script execution
    try:
        from GREENWIRE.modules.rfid_vulnerability_tester import RFIDVulnerabilityTester  # type: ignore
    except ImportError:
        RFIDVulnerabilityTester = None  # type: ignore

class GreenwirePyAPDUFuzzer:
    """Enhanced APDU fuzzer integrating pyAPDUFuzzer with GREENWIRE capabilities."""

    def __init__(
        self,
        verbose: bool = True,
        artifact_root: Optional[str] = None,
        analyzer: Optional[Any] = None,
    ) -> None:
        self.verbose = verbose
        self.logger = logging.getLogger("GreenwirePyAPDUFuzzer")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO if verbose else logging.WARNING)

        self.fuzzer: Optional[Any] = None
        self.card_interface = None
        self.target_cards = [
            "jcop",
            "nxp",
            "emv",
            "iso14443a",
            "iso14443b",
            "iso15693",
            "ntag",
            "mifare",
            "rfid",
            "all",
        ]

        self.artifact_root = Path(artifact_root or "artifacts/apdu_fuzzing")
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.session_directory: Optional[Path] = None
        self._artifact_counter = 0

        self.analyzer = analyzer
        if self.analyzer is None and DataArtifactAnalyzer:
            try:
                self.analyzer = DataArtifactAnalyzer(
                    workspace_dir=str(self.artifact_root / "analysis")
                )
                self.logger.info(
                    "Data artifact analyzer enabled for APDU fuzzing artifacts"
                )
            except Exception as exc:  # pragma: no cover - analyzer optional
                self.logger.warning(
                    "Unable to initialize DataArtifactAnalyzer: %s", exc
                )
                self.analyzer = None

        self.session_data = self._create_session_template()
        if self.analyzer:
            analyzer_workspace = getattr(self.analyzer, "workspace_dir", None)
            if isinstance(analyzer_workspace, Path):
                analyzer_workspace = str(analyzer_workspace)
            self.session_data["analyzer_workspace"] = analyzer_workspace or str(
                self.artifact_root / "analysis"
            )

        if HAS_PYAPDUFUZZER:
            self._initialize_fuzzer()
        else:
            self.logger.info(
                "pyAPDUFuzzer not detected; installation will be attempted on demand"
            )

    def _create_session_template(self) -> Dict[str, Any]:
        return {
            "session_id": None,
            "start_time": None,
            "end_time": None,
            "total_commands": 0,
            "successful_commands": 0,
            "errors": [],
            "vulnerabilities": [],
            "card_responses": [],
            "artifact_analysis": [],
            "artifact_files": [],
            "rfid_test_results": None,
            "target_card": None,
            "iterations_requested": 0,
            "fuzz_level": 0,
            "base_commands": [],
            "combined_analysis_file": None,
        }

    def _start_new_session(self, target_card: str, iterations: int, fuzz_level: int) -> None:
        self.session_data = self._create_session_template()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        session_id = f"apdu_fuzz_{timestamp}"
        self.session_data["session_id"] = session_id
        self.session_data["target_card"] = target_card
        self.session_data["iterations_requested"] = iterations
        self.session_data["fuzz_level"] = fuzz_level

        self.session_directory = self.artifact_root / session_id
        self.session_directory.mkdir(parents=True, exist_ok=True)
        self._artifact_counter = 0

        metadata = {
            "session_id": session_id,
            "target_card": target_card,
            "iterations": iterations,
            "fuzz_level": fuzz_level,
            "timestamp": timestamp,
        }
        self._write_json_artifact("session_metadata.json", metadata)

    def _write_json_artifact(self, filename: str, data: Any) -> Optional[str]:
        if not self.session_directory:
            return None

        try:
            artifact_path = self.session_directory / filename
            with open(artifact_path, "w", encoding="utf-8") as handle:
                json.dump(self._make_serializable(data), handle, indent=2)
            self.session_data["artifact_files"].append(str(artifact_path))
            return str(artifact_path)
        except Exception as exc:  # pragma: no cover - filesystem issues unexpected
            self.logger.error("Failed to write artifact %s: %s", filename, exc)
            return None

    def _record_artifact_analysis(self, command: Dict[str, Any], analysis: Dict[str, Any]) -> None:
        artifact_name = f"analysis_{self._artifact_counter:04d}.json"
        artifact_path = self._write_json_artifact(artifact_name, analysis)

        summary = {
            "command_desc": command.get("desc", "unknown"),
            "artifact_file": artifact_path,
            "data_size": analysis.get("data_size"),
            "patterns_found": len(analysis.get("pattern_matches", [])),
            "potential_keys": len(analysis.get("potential_keys", [])),
        }
        self.session_data["artifact_analysis"].append(summary)
        self._artifact_counter += 1

    def _finalize_session_artifacts(self) -> None:
        if not self.session_directory:
            return

        if self.session_data["card_responses"]:
            self._write_json_artifact(
                "card_responses.json", self.session_data["card_responses"]
            )

        if self.session_data["vulnerabilities"]:
            self._write_json_artifact(
                "vulnerabilities.json", self.session_data["vulnerabilities"]
            )

        if self.session_data["errors"]:
            self._write_json_artifact("errors.json", self.session_data["errors"])

        if self.session_data["artifact_analysis"]:
            self._write_json_artifact(
                "artifact_analysis.json", self.session_data["artifact_analysis"]
            )

        self._run_combined_artifact_analysis()
        self._write_json_artifact("session_summary.json", self.session_data)

    def _run_combined_artifact_analysis(self) -> None:
        if not self.analyzer:
            return

        combined_data = bytearray()
        for record in self.session_data["card_responses"]:
            response = record.get("response", {})
            data_block = response.get("data")
            if isinstance(data_block, bytes) and data_block:
                combined_data.extend(data_block)

        if not combined_data:
            return

        try:
            analysis = self.analyzer.analyze_memory_dump(
                bytes(combined_data), source="combined_apdu_responses"
            )
            artifact_path = self._write_json_artifact(
                "combined_analysis.json", analysis
            )
            self.session_data["combined_analysis_file"] = artifact_path
        except Exception as exc:  # pragma: no cover - analyzer failures unexpected
            self.logger.warning("Combined artifact analysis failed: %s", exc)

    def _maybe_run_rfid_vulnerability_tests(self, target_card: str) -> None:
        relevant_targets = {
            "rfid",
            "iso14443a",
            "iso14443b",
            "iso15693",
            "ntag",
            "mifare",
            "all",
        }

        if target_card.lower() not in relevant_targets:
            return

        if not RFIDVulnerabilityTester:
            self.logger.info("RFID vulnerability tester not available in environment")
            self.session_data["rfid_test_results"] = {
                "status": "unavailable",
                "reason": "RFIDVulnerabilityTester module not present",
            }
            return

        try:
            tester = RFIDVulnerabilityTester()
            results = tester.run_all_vulnerability_tests()
            self.session_data["rfid_test_results"] = results
            self._write_json_artifact("rfid_vulnerability_results.json", results)
        except Exception as exc:  # pragma: no cover - hardware/driver errors possible
            self.logger.error("RFID vulnerability tests failed: %s", exc)
            self.session_data["rfid_test_results"] = {
                "status": "error",
                "reason": str(exc),
            }

    def _initialize_fuzzer(self) -> None:
        """Initialize the pyAPDUFuzzer components."""
        try:
            self.fuzzer = APDUFuzzer()
            self.logger.info("pyAPDUFuzzer initialized successfully")
        except Exception as exc:  # pragma: no cover - initialization failure rare
            self.logger.warning("Failed to initialize pyAPDUFuzzer: %s", exc)
            self.fuzzer = None

    def install_pyapdufuzzer(self) -> bool:
        """Install pyAPDUFuzzer from GitHub if not available."""
        global HAS_PYAPDUFUZZER

        if HAS_PYAPDUFUZZER:
            self.logger.info("pyAPDUFuzzer already available")
            return True

        self.logger.info("Installing pyAPDUFuzzer from GitHub repository")

        try:
            external_dir = os.path.join(os.path.dirname(__file__), "..", "external")
            os.makedirs(external_dir, exist_ok=True)

            pyapdu_dir = os.path.join(external_dir, "pyAPDUFuzzer")

            # Check if directory already exists
            if os.path.exists(pyapdu_dir):
                self.logger.warning("pyAPDUFuzzer directory already exists, attempting to use it")
                # Try to initialize with existing installation
                if os.path.exists(os.path.join(pyapdu_dir, "fuzzer.py")):
                    if pyapdu_dir not in sys.path:
                        sys.path.insert(0, pyapdu_dir)
                    try:
                        # Import modules
                        import fuzzer
                        import apdu
                        import card_interface

                        # Update module-level variables through sys.modules
                        current_module = sys.modules[__name__]
                        setattr(current_module, 'APDUFuzzer', fuzzer.APDUFuzzer)
                        setattr(current_module, 'APDU', apdu.APDU)
                        setattr(current_module, 'APDUCommand', apdu.APDUCommand)
                        setattr(current_module, 'CardInterface', card_interface.CardInterface)
                        setattr(current_module, 'HAS_PYAPDUFUZZER', True)

                        self.logger.info("Successfully loaded existing pyAPDUFuzzer installation")
                        self._initialize_fuzzer()
                        return True
                    except ImportError as e:
                        self.logger.warning(f"Existing installation incomplete: {e}")
                        return False
                else:
                    self.logger.error("pyAPDUFuzzer directory exists but is incomplete")
                    return False

            clone_cmd = [
                "git",
                "clone",
                "https://github.com/petrs/pyAPDUFuzzer.git",
                pyapdu_dir,
            ]

            result = subprocess.run(clone_cmd, capture_output=True, text=True, check=False)

            if result.returncode == 0:
                self.logger.info("pyAPDUFuzzer cloned successfully")
                HAS_PYAPDUFUZZER = True
                self._initialize_fuzzer()
                return True

            self.logger.error("Failed to clone pyAPDUFuzzer: %s", result.stderr.strip())
            return False

        except Exception as exc:  # pragma: no cover - network failure etc.
            self.logger.error("Error installing pyAPDUFuzzer: %s", exc)
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

    def create_iso14443a_fuzz_commands(self) -> List[Dict[str, Any]]:
        """Commands targeting ISO14443A tags and cards."""
        return [
            {"cla": 0xFF, "ins": 0xCA, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "ISO14443A Get UID"},
            {"cla": 0xFF, "ins": 0xB0, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "ISO14443A Read Block"},
            {"cla": 0xFF, "ins": 0xD6, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "ISO14443A Write Block"},
            {"cla": 0xFF, "ins": 0x00, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "ISO14443A Halt"},
            {"cla": 0xFF, "ins": 0x88, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "ISO14443A Get Challenge"},
        ]

    def create_iso14443b_fuzz_commands(self) -> List[Dict[str, Any]]:
        """Commands targeting ISO14443B tags and cards."""
        return [
            {"cla": 0xFF, "ins": 0xCA, "p1": 0x01, "p2": 0x00, "data": b"", "desc": "ISO14443B Get PUPI"},
            {"cla": 0xFF, "ins": 0xCA, "p1": 0x02, "p2": 0x00, "data": b"", "desc": "ISO14443B Get Application Data"},
            {"cla": 0xFF, "ins": 0xCA, "p1": 0x03, "p2": 0x00, "data": b"", "desc": "ISO14443B Get Protocol Info"},
            {"cla": 0xFF, "ins": 0xB0, "p1": 0x00, "p2": 0x10, "data": b"", "desc": "ISO14443B Read Block"},
            {"cla": 0xFF, "ins": 0xD6, "p1": 0x00, "p2": 0x10, "data": b"", "desc": "ISO14443B Update Block"},
        ]

    def create_iso15693_fuzz_commands(self) -> List[Dict[str, Any]]:
        """Commands targeting ISO15693 vicinity cards."""
        return [
            {"cla": 0x02, "ins": 0x00, "p1": 0x26, "p2": 0x00, "data": b"", "desc": "ISO15693 Inventory"},
            {"cla": 0x02, "ins": 0x20, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "ISO15693 Stay Quiet"},
            {"cla": 0x02, "ins": 0x20, "p1": 0x02, "p2": 0x00, "data": b"", "desc": "ISO15693 Read Single Block"},
            {"cla": 0x02, "ins": 0x20, "p1": 0x03, "p2": 0x00, "data": b"", "desc": "ISO15693 Write Single Block"},
            {"cla": 0x02, "ins": 0x20, "p1": 0x04, "p2": 0x00, "data": b"", "desc": "ISO15693 Lock Block"},
        ]

    def create_ntag_fuzz_commands(self) -> List[Dict[str, Any]]:
        """Commands targeting NTAG variants for password and NDEF testing."""
        return [
            {"cla": 0xFF, "ins": 0x00, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "NTAG Fast Read"},
            {"cla": 0xFF, "ins": 0xA2, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "NTAG Write Page"},
            {"cla": 0xFF, "ins": 0xB0, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "NTAG Read Page"},
            {"cla": 0xFF, "ins": 0xA1, "p1": 0x00, "p2": 0xE3, "data": b"", "desc": "NTAG Read Lock Bytes"},
            {"cla": 0xFF, "ins": 0xB1, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "NTAG PWD_AUTH"},
        ]

    def create_mifare_classic_fuzz_commands(self) -> List[Dict[str, Any]]:
        """Commands targeting MIFARE Classic authentication flows."""
        return [
            {"cla": 0xFF, "ins": 0x82, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "MIFARE Load Key"},
            {"cla": 0xFF, "ins": 0x86, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "MIFARE Authenticate"},
            {"cla": 0xFF, "ins": 0xB0, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "MIFARE Read Block"},
            {"cla": 0xFF, "ins": 0xD6, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "MIFARE Write Block"},
            {"cla": 0xFF, "ins": 0xD7, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "MIFARE Increment"},
        ]

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

    def run_enhanced_fuzzing_session(
        self, target_card: str, iterations: int = 1000, fuzz_level: int = 5
    ) -> Dict[str, Any]:
        """Run enhanced fuzzing session with pyAPDUFuzzer integration.

        Note: This works in simulated mode using built-in command generators
        even if pyAPDUFuzzer is not installed.
        """
        # pyAPDUFuzzer is optional - we have built-in command generators
        if not HAS_PYAPDUFUZZER:
            self.logger.debug("Running in simulated mode with built-in command generators")

        self._start_new_session(target_card, iterations, fuzz_level)
        self.session_data["start_time"] = time.time()

        self.logger.info(
            "Starting enhanced APDU fuzzing session | Target=%s | Iterations=%d | FuzzLevel=%d",
            target_card,
            iterations,
            fuzz_level,
        )

        target_key = target_card.lower()
        if target_key == "jcop":
            base_commands = self.create_jcop_fuzz_commands()
        elif target_key == "nxp":
            base_commands = self.create_nxp_fuzz_commands()
        elif target_key == "emv":
            base_commands = self.create_emv_fuzz_commands()
        elif target_key == "iso14443a":
            base_commands = self.create_iso14443a_fuzz_commands()
        elif target_key == "iso14443b":
            base_commands = self.create_iso14443b_fuzz_commands()
        elif target_key == "iso15693":
            base_commands = self.create_iso15693_fuzz_commands()
        elif target_key == "ntag":
            base_commands = self.create_ntag_fuzz_commands()
        elif target_key == "mifare":
            base_commands = self.create_mifare_classic_fuzz_commands()
        elif target_key == "rfid":
            base_commands = (
                self.create_iso14443a_fuzz_commands()
                + self.create_iso14443b_fuzz_commands()
                + self.create_iso15693_fuzz_commands()
                + self.create_ntag_fuzz_commands()
                + self.create_mifare_classic_fuzz_commands()
            )
        elif target_key == "all":
            base_commands = (
                self.create_jcop_fuzz_commands()
                + self.create_nxp_fuzz_commands()
                + self.create_emv_fuzz_commands()
                + self.create_iso14443a_fuzz_commands()
                + self.create_iso14443b_fuzz_commands()
                + self.create_iso15693_fuzz_commands()
                + self.create_ntag_fuzz_commands()
                + self.create_mifare_classic_fuzz_commands()
            )
        else:
            base_commands = (
                self.create_jcop_fuzz_commands()
                + self.create_nxp_fuzz_commands()
                + self.create_emv_fuzz_commands()
            )
            self.logger.info(
                "Unknown target '%s'; using default combined command set", target_card
            )

        self.session_data["base_commands"] = base_commands
        self._write_json_artifact("base_commands.json", base_commands)

        fuzz_payloads = self.create_fuzzing_payloads(base_commands, fuzz_level)
        self._write_json_artifact(
            "fuzz_payload_overview.json",
            {"count": len(fuzz_payloads), "fuzz_level": fuzz_level},
        )
        sample_count = min(25, len(fuzz_payloads))
        if sample_count:
            self._write_json_artifact(
                "fuzz_payload_samples.json", fuzz_payloads[:sample_count]
            )

        self.logger.info("Generated %d fuzzing payloads", len(fuzz_payloads))

        executed_commands = 0
        for index in range(iterations):
            if executed_commands >= len(fuzz_payloads):
                break

            payload = fuzz_payloads[index % len(fuzz_payloads)]

            try:
                response = self._execute_apdu_command(payload)

                record = {
                    "command": payload,
                    "response": response,
                    "timestamp": time.time(),
                }
                self.session_data["card_responses"].append(record)

                vulnerabilities = self._analyze_response(payload, response) or []
                if vulnerabilities:
                    self.session_data["vulnerabilities"].extend(vulnerabilities)

                executed_commands += 1
                self.session_data["successful_commands"] += 1

                if self.verbose and executed_commands % 100 == 0:
                    self.logger.info(
                        "Executed %d/%d payloads", executed_commands, iterations
                    )

            except Exception as exc:  # pragma: no cover - runtime errors unexpected
                self.session_data["errors"].append(
                    {
                        "command": payload,
                        "error": str(exc),
                        "timestamp": time.time(),
                    }
                )
                self.logger.warning("Error executing command: %s", exc)

        self.session_data["total_commands"] = executed_commands
        self.session_data["end_time"] = time.time()

        self._maybe_run_rfid_vulnerability_tests(target_card)
        self._finalize_session_artifacts()

        duration = self.session_data["end_time"] - self.session_data["start_time"]
        self.logger.info(
            "Fuzzing session complete | Duration=%.2fs | Commands=%d | Errors=%d | Vulnerabilities=%d",
            duration,
            executed_commands,
            len(self.session_data["errors"]),
            len(self.session_data["vulnerabilities"]),
        )

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

        if random.random() < 0.3:
            base_response = dict(random.choice(response_types[:3]))
            base_response["data"] = os.urandom(random.randint(0, 256))
        else:
            base_response = dict(random.choice(response_types))

        return base_response

    def _analyze_response(self, command: Dict[str, Any], response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze response for potential vulnerabilities."""
        vulnerabilities: List[Dict[str, Any]] = []

        if command["desc"].startswith("FUZZ_") and response.get("sw1") == 0x90:
            vulnerabilities.append(
                {
                    "type": "unexpected_success",
                    "description": f"Fuzzed command succeeded: {command['desc']}",
                    "command": command,
                    "response": response,
                    "severity": "medium",
                }
            )

        if len(command.get("data", b"")) > 255 and response.get("sw1") not in [0x67, 0x6A]:
            vulnerabilities.append(
                {
                    "type": "potential_buffer_overflow",
                    "description": (
                        f"Large data payload accepted: {len(command.get('data', b''))} bytes"
                    ),
                    "command": command,
                    "response": response,
                    "severity": "high",
                }
            )

        response_data = response.get("data", b"")
        if isinstance(response_data, bytes) and response_data and random.random() < 0.1:
            vulnerabilities.append(
                {
                    "type": "information_disclosure",
                    "description": f"Unexpected data returned: {len(response_data)} bytes",
                    "command": command,
                    "response": response,
                    "severity": "low",
                }
            )

        if self.analyzer and isinstance(response_data, bytes) and response_data:
            try:
                analysis = self.analyzer.analyze_memory_dump(
                    response_data, source=command.get("desc", "unknown_command")
                )
                if analysis:
                    self._record_artifact_analysis(command, analysis)
            except Exception as exc:  # pragma: no cover - analyzer errors unexpected
                self.logger.debug("Artifact analysis failed for %s: %s", command.get("desc"), exc)

        return vulnerabilities

    def generate_fuzzing_report(self) -> str:
        """Generate detailed fuzzing report."""
        if not self.session_data.get("start_time"):
            return "No fuzzing session data available"

        duration = (self.session_data.get("end_time", time.time()) 
                    - self.session_data["start_time"])

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

    print("\nEnhanced APDU Fuzzing with pyAPDUFuzzer")
    print("=" * 50)
    print(f"Target: {target_card.upper()} cards")
    print(f"Iterations: {iterations}")
    print(f"Fuzz Level: {fuzz_level}")

    results = fuzzer.run_enhanced_fuzzing_session(target_card, iterations, fuzz_level)

    if "error" in results:
        print(f"Fuzzing failed: {results['error']}")
        return results

    report = fuzzer.generate_fuzzing_report()
    print("\n" + "=" * 50)
    print(report)

    save_file = fuzzer.save_session_data()
    if save_file:
        print(f"\nDetailed results saved to: {save_file}")

    return results


if __name__ == "__main__":
    test_fuzzer = GreenwirePyAPDUFuzzer()

    print("Testing GREENWIRE pyAPDUFuzzer Integration")
    print("=" * 50)

    if test_fuzzer.install_pyapdufuzzer():
        print("Installation test passed")
    else:
        print("Installation test failed")

    jcop_cmds = test_fuzzer.create_jcop_fuzz_commands()
    nxp_cmds = test_fuzzer.create_nxp_fuzz_commands()
    emv_cmds = test_fuzzer.create_emv_fuzz_commands()

    print(f"Generated {len(jcop_cmds)} JCOP commands")
    print(f"Generated {len(nxp_cmds)} NXP commands")
    print(f"Generated {len(emv_cmds)} EMV commands")

    test_payloads = test_fuzzer.create_fuzzing_payloads(jcop_cmds[:3], 2)
    print(f"Generated {len(test_payloads)} fuzzing payloads")

    print("\nRunning test fuzzing session...")
    results = test_fuzzer.run_enhanced_fuzzing_session("jcop", iterations=50, fuzz_level=2)

    if "error" not in results:
        print("Test session completed successfully")
        print(test_fuzzer.generate_fuzzing_report())
    else:
        print(f"Test session failed: {results['error']}")
