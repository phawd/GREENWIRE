#!/usr/bin/env python3
"""Native APDU Fuzzer (modularized).

Provides simulation-based and (optional) real smartcard fuzzing of APDU
commands for JCOP, NXP and EMV cards. Extracted from the monolithic
`greenwire.py` so other modules (menus/tests) can import without creating
heavy CLI side‑effects.

Key design goals:
 - Minimal external deps (only uses pyscard if available and requested)
 - Deterministic structure but randomized mutations
 - Simple contract: run_native_apdu_fuzz(...) returns (session_data, report_path)
 - Safe hardware mode (skips oversize payloads, catches all transmit errors)
"""

from __future__ import annotations

import os
import random
import time
from pathlib import Path
from typing import Dict, Any, List, Optional


class NativeAPDUFuzzer:
    """Core APDU fuzzing engine.

    If a `send_apdu_callable` is supplied it will be used to transmit real
    APDUs (hex string). Otherwise responses are simulated.
    """

    def __init__(self, verbose: bool = True, send_apdu_callable=None, hw_max_payload: int = 220):
        self.verbose = verbose
        self.send_apdu = send_apdu_callable  # function(hex_str)-> (data_hex, sw1, sw2) or raises
        self.hw_max_payload = hw_max_payload
        self.session_data: Dict[str, Any] = {
            "commands_sent": 0,
            "responses_received": 0,
            "vulnerabilities": [],
            "errors": [],
            "start_time": None,
            "end_time": None,
            "response_times_ms": [],  # flat list
            "hardware_mode": bool(send_apdu_callable),
        }
        self.card_commands = {
            "jcop": self._get_jcop_commands(),
            "nxp": self._get_nxp_commands(),
            "emv": self._get_emv_commands(),
        }

    # --- Base command sets -------------------------------------------------
    def _get_jcop_commands(self):
        return [
            {"cla": 0x80, "ins": 0xCA, "p1": 0x00, "p2": 0xFE, "data": b"", "desc": "Get JCOP System Info"},
            {"cla": 0x80, "ins": 0x50, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "JCOP System Command"},
            {"cla": 0x84, "ins": 0x82, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "External Authenticate"},
            {"cla": 0x80, "ins": 0xE6, "p1": 0x02, "p2": 0x00, "data": b"", "desc": "Install Applet"},
            {"cla": 0x80, "ins": 0xE4, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Delete Applet"},
            {"cla": 0x80, "ins": 0x20, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Verify PIN"},
            {"cla": 0x80, "ins": 0x24, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Change PIN"},
        ]

    def _get_nxp_commands(self):
        return [
            {"cla": 0xFF, "ins": 0xCA, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Get UID"},
            {"cla": 0xFF, "ins": 0x82, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Load Authentication Keys"},
            {"cla": 0xFF, "ins": 0x86, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "General Authenticate"},
            {"cla": 0xFF, "ins": 0xB0, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "Read Binary Blocks"},
            {"cla": 0xFF, "ins": 0xD6, "p1": 0x00, "p2": 0x04, "data": b"", "desc": "Update Binary Blocks"},
            {"cla": 0x90, "ins": 0x60, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "DESFire Get Version"},
            {"cla": 0x90, "ins": 0x6F, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Get Key Settings"},
            {"cla": 0x90, "ins": 0x5A, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Select Application"},
        ]

    def _get_emv_commands(self):
        return [
            {"cla": 0x00, "ins": 0xA4, "p1": 0x04, "p2": 0x00, "data": b"", "desc": "SELECT Application"},
            {"cla": 0x80, "ins": 0xA8, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Get Processing Options"},
            {"cla": 0x00, "ins": 0xB2, "p1": 0x01, "p2": 0x0C, "data": b"", "desc": "Read Record"},
            {"cla": 0x80, "ins": 0xCA, "p1": 0x9F, "p2": 0x13, "data": b"", "desc": "Get Data ATC"},
            {"cla": 0x80, "ins": 0xCA, "p1": 0x9F, "p2": 0x36, "data": b"", "desc": "Get Data ATC"},
            {"cla": 0x80, "ins": 0xCA, "p1": 0x9F, "p2": 0x17, "data": b"", "desc": "Get PIN Try Counter"},
            {"cla": 0x00, "ins": 0x88, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "Get Challenge"},
            {"cla": 0x00, "ins": 0x82, "p1": 0x00, "p2": 0x00, "data": b"", "desc": "External Authenticate"},
            {"cla": 0x80, "ins": 0xAE, "p1": 0x80, "p2": 0x00, "data": b"", "desc": "Generate AC"},
            {"cla": 0x80, "ins": 0x24, "p1": 0x00, "p2": 0x80, "data": b"", "desc": "Verify PIN"},
            {"cla": 0x84, "ins": 0x24, "p1": 0x00, "p2": 0x01, "data": b"", "desc": "Change PIN"},
        ]

    # --- Mutation & execution ---------------------------------------------
    def create_fuzz_mutations(self, base_cmd: Dict[str, Any], mutation_level: int = 5) -> List[Dict[str, Any]]:
        mutations = [base_cmd.copy()]  # Include original
        for _ in range(mutation_level):
            # Randomize each field separately
            mut = base_cmd.copy(); mut["cla"] = random.randint(0, 0xFF); mut["desc"] = f"FUZZ_CLA: {mut['desc']}"; mutations.append(mut)
            mut = base_cmd.copy(); mut["ins"] = random.randint(0, 0xFF); mut["desc"] = f"FUZZ_INS: {mut['desc']}"; mutations.append(mut)
            mut = base_cmd.copy(); mut["p1"] = random.randint(0, 0xFF); mut["p2"] = random.randint(0, 0xFF); mut["desc"] = f"FUZZ_P1P2: {mut['desc']}"; mutations.append(mut)

        # Payload sizes including stress cases
        for size in [0, 1, 15, 255, 256, 512, 1024, 2048]:
            mut = base_cmd.copy()
            mut["data"] = os.urandom(size) if size else b""
            mut["desc"] = f"FUZZ_DATA_{size}: {mut['desc']}"
            mutations.append(mut)

        return mutations

    def _build_apdu_hex(self, cmd: Dict[str, Any]) -> Optional[str]:
        """Build APDU hex string.

        Supports short APDU and a basic extended APDU form when data length > 255
        by using 0x00 Lc + 2-byte length. Only used in simulation unless a
        caller explicitly allows via send_apdu (hardware short-circuits large data).
        """
        data: bytes = cmd.get("data", b"") or b""
        header = [cmd["cla"], cmd["ins"], cmd["p1"], cmd["p2"]]
        if not data:
            return ''.join(f'{b:02X}' for b in (header + [0x00]))
        if len(data) <= 0xFF:
            apdu = header + [len(data)] + list(data) + [0x00]
            return ''.join(f'{b:02X}' for b in apdu)
        # Extended APDU (Lc=0x00, two-byte length, then data, no Le for now)
        if len(data) <= 0xFFFF:
            lc_hi = (len(data) >> 8) & 0xFF
            lc_lo = len(data) & 0xFF
            apdu = header + [0x00, lc_hi, lc_lo] + list(data)  # Omit Le to simplify
            return ''.join(f'{b:02X}' for b in apdu)
        # Too large
        return None

    def _simulate_response(self, cmd: Dict[str, Any]):
        # Basic simulated SW results & occasional data
        response_types = [
            {"sw1": 0x90, "sw2": 0x00, "data": b"", "status": "Success"},
            {"sw1": 0x6E, "sw2": 0x00, "data": b"", "status": "Class not supported"},
            {"sw1": 0x6D, "sw2": 0x00, "data": b"", "status": "Instruction not supported"},
            {"sw1": 0x6A, "sw2": 0x86, "data": b"", "status": "Incorrect P1 P2"},
            {"sw1": 0x67, "sw2": 0x00, "data": b"", "status": "Wrong length"},
            {"sw1": 0x69, "sw2": 0x82, "data": b"", "status": "Security condition not satisfied"},
            {"sw1": 0x6F, "sw2": 0x00, "data": b"", "status": "Unknown error"},
        ]
        resp = random.choice(response_types)
        if random.random() < 0.25:
            resp["data"] = os.urandom(random.randint(0, 64))
        return resp

    def _analyze(self, cmd: Dict[str, Any], response: Dict[str, Any]):
        vulns = []
        # Unexpected success of mutated command
        if cmd["desc"].startswith("FUZZ_") and response.get("sw1") == 0x90:
            vulns.append({
                "type": "unexpected_success",
                "severity": "medium",
                "description": f"Fuzzed command succeeded: {cmd['desc']}",
                "command": cmd,
            })
        # Large payload accepted
        data_len = len(cmd.get("data") or b"")
        if data_len > 255 and response.get("sw1") not in [0x67, 0x6A]:
            vulns.append({
                "type": "potential_buffer_overflow",
                "severity": "high",
                "description": f"Large payload accepted ({data_len} bytes)",
                "command": cmd,
            })
        if response.get("data"):
            vulns.append({
                "type": "information_disclosure",
                "severity": "low",
                "description": f"Data returned ({len(response['data'])} bytes)",
                "command": cmd,
            })
        self.session_data["vulnerabilities"].extend(vulns)

    def run_fuzzing_session(self, target_card: str, iterations: int = 1000, mutation_level: int = 5):
        self.session_data["start_time"] = time.time()
        if self.verbose:
            print("🎯 Native APDU Fuzzing")
            print(f"   Target: {target_card.upper()}")
            print(f"   Iterations: {iterations}")
            print(f"   Mutation level: {mutation_level}")
            print(f"   Mode: {'HARDWARE' if self.session_data['hardware_mode'] else 'SIMULATION'}")

        # Collect base commands
        if target_card.lower() in self.card_commands:
            base = self.card_commands[target_card.lower()]
        else:  # all
            base = []
            for v in self.card_commands.values():
                base.extend(v)

        # Generate mutations
        all_cmds: List[Dict[str, Any]] = []
        for b in base:
            all_cmds.extend(self.create_fuzz_mutations(b, mutation_level))
        if self.verbose:
            print(f"   Generated {len(all_cmds)} candidate commands")

        executed = 0
        for i, cmd in enumerate(all_cmds):
            if executed >= iterations:
                break
            try:
                if self.send_apdu:  # hardware
                    # Skip overly large payloads for hardware (short APDU only)
                    if len(cmd.get("data", b"") or b"") > self.hw_max_payload:
                        continue
                    apdu_hex = self._build_apdu_hex(cmd)
                    if not apdu_hex:
                        continue
                    try:
                        start_t = time.time()
                        data_list, sw1, sw2 = self.send_apdu(apdu_hex)  # expecting (list,int,int) like pyscard
                        end_t = time.time()
                        # Normalize
                        resp = {"sw1": sw1, "sw2": sw2, "data": bytes(data_list)}
                        resp["rt_ms"] = (end_t - start_t) * 1000.0
                        self.session_data["response_times_ms"].append(resp["rt_ms"]) 
                    except Exception as hw_err:
                        self.session_data["errors"].append({"command": cmd, "error": str(hw_err)})
                        continue
                else:  # simulation
                    start_t = time.time()
                    resp = self._simulate_response(cmd)
                    end_t = time.time()
                    resp["rt_ms"] = (end_t - start_t) * 1000.0
                    self.session_data["response_times_ms"].append(resp["rt_ms"]) 
                self.session_data["commands_sent"] += 1
                self.session_data["responses_received"] += 1
                self._analyze(cmd, resp)
                executed += 1
                if self.verbose and executed % 100 == 0:
                    print(f"   Progress: {executed}/{iterations}")
            except Exception as e:
                self.session_data["errors"].append({"command": cmd, "error": str(e)})

        self.session_data["end_time"] = time.time()
        duration = self.session_data["end_time"] - self.session_data["start_time"]
        if self.verbose:
            print("✅ Fuzzing complete")
            print(f"   Duration: {duration:.2f}s")
            print(f"   Executed: {self.session_data['commands_sent']}")
            print(f"   Vulns: {len(self.session_data['vulnerabilities'])}")
            print(f"   Errors: {len(self.session_data['errors'])}")
        return self.session_data

    def generate_report(self) -> str:
        if not self.session_data.get("start_time"):
            return "No session data"
        duration = (self.session_data.get("end_time") or time.time()) - self.session_data["start_time"]
        lines = [
            "# Native APDU Fuzzing Report",
            "",
            "## Session Summary",
            f"- Duration: {duration:.2f} seconds",
            f"- Commands Sent: {self.session_data['commands_sent']}",
            f"- Responses Received: {self.session_data['responses_received']}",
            f"- Vulnerabilities: {len(self.session_data['vulnerabilities'])}",
            f"- Errors: {len(self.session_data['errors'])}",
            f"- Mode: {'HARDWARE' if self.session_data['hardware_mode'] else 'SIMULATION'}",
            "",
            "## Vulnerabilities Found",
            "",
            "## Timing",
            f"- Avg Response Time: {self._avg_rt():.2f} ms" if self.session_data['responses_received'] else "- Avg Response Time: N/A",
            f"- P50: {self._percentile(50):.2f} ms" if self.session_data['response_times_ms'] else "- P50: N/A",
            f"- P95: {self._percentile(95):.2f} ms" if self.session_data['response_times_ms'] else "- P95: N/A",
        ]
        if self.session_data['vulnerabilities']:
            by_type = {}
            for v in self.session_data['vulnerabilities']:
                by_type[v['type']] = by_type.get(v['type'], 0) + 1
            for t, c in by_type.items():
                lines.append(f"- {t.replace('_', ' ').title()}: {c}")
        else:
            lines.append("No vulnerabilities detected.")
        return "\n".join(lines) + "\n"

    def _avg_rt(self) -> float:
        rts = self.session_data.get("response_times_ms", [])
        return sum(rts)/len(rts) if rts else 0.0

    def _percentile(self, p: int) -> float:
        rts = sorted(self.session_data.get("response_times_ms", []))
        if not rts:
            return 0.0
        k = (len(rts)-1) * (p/100)
        f = int(k)
        c = min(f+1, len(rts)-1)
        if f == c:
            return rts[f]
        return rts[f] + (rts[c]-rts[f]) * (k-f)


def run_native_apdu_fuzz(target_card: str = "all", iterations: int = 500, mutation_level: int = 5,
                          use_hardware: bool = False, send_apdu_callable=None, verbose: bool = True,
                          report_dir: str = "."):
    """Helper to execute a fuzzing session and write a report.

    Returns (session_data, report_path)
    """
    fuzzer = NativeAPDUFuzzer(verbose=verbose, send_apdu_callable=send_apdu_callable)
    session = fuzzer.run_fuzzing_session(target_card, iterations=iterations, mutation_level=mutation_level)
    report = fuzzer.generate_report()
    Path(report_dir).mkdir(parents=True, exist_ok=True)
    report_path = Path(report_dir) / f"native_apdu_fuzz_report_{int(time.time())}.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    return session, str(report_path)


__all__ = [
    "NativeAPDUFuzzer",
    "run_native_apdu_fuzz",
]
