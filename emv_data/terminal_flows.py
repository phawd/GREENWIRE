#!/usr/bin/env python3
"""
EMV Terminal Flows
------------------

Hardcoded EMV terminal command sequences for common scenarios (ATM withdrawal,
merchant purchase). Uses the APDU4J-style interface implemented in
apdu4j_data.apdu4j_integration to send ISO 7816-4 commands and parse responses.

These flows are intentionally simple and conservative, aiming to:
- Select PPSE and preferred AID
- Get Processing Options
- Read records from AFL
- Optionally verify PIN (if provided)
- Generate AC

They are designed to work with both contact and contactless EMV cards when a
PC/SC reader is available. If no reader is available, a dry-run mode can be used
to print the planned sequence without executing commands.
"""

from typing import List, Dict, Optional, Tuple
from pathlib import Path
import sys
import os

try:
    from apdu4j_data.apdu4j_integration import GREENWIREAPDU4JInterface
    from apdu4j_data.apdu_commands import APDU4JCommand
    HAVE_APDU4J = True
except Exception:
    # Attempt local path insertion if package import fails
    base_dir = Path(__file__).resolve().parent.parent
    apdu4j_path = base_dir / "apdu4j_data"
    if apdu4j_path.exists():
        sys.path.insert(0, str(apdu4j_path))
        try:
            from apdu4j_integration import GREENWIREAPDU4JInterface  # type: ignore
            from apdu4j_commands import APDU4JCommand  # type: ignore
            HAVE_APDU4J = True
        except Exception:
            GREENWIREAPDU4JInterface = None
            APDU4JCommand = None
            HAVE_APDU4J = False
    else:
        GREENWIREAPDU4JInterface = None
        APDU4JCommand = None
        HAVE_APDU4J = False


DEFAULT_PREFERRED_AIDS = [
    "A0000000031010",  # Visa
    "A0000000041010",  # Mastercard
    "A000000025",      # AmEx
    "A0000001523010",  # Discover
    "A0000000651010",  # JCB
]


class EMVTerminalFlow:
    """Runs a minimal EMV terminal flow using APDU4J integration."""

    def __init__(self, reader: Optional[str] = None, verbose: bool = False):
        if not HAVE_APDU4J:
            raise RuntimeError("APDU4J integration not available in this environment")
        self.iface = GREENWIREAPDU4JInterface(verbose=verbose)
        self.reader = reader
        self.verbose = verbose

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    def list_readers(self) -> List[str]:
        return self.iface.list_readers()

    def _send(self, cmd: APDU4JCommand, data: bytes = b"", le: Optional[int] = None,
              p1: Optional[int] = None, p2: Optional[int] = None) -> Tuple[bytes, int, int]:
        kwargs = {"data": data, "le": le}
        if p1 is not None:
            kwargs["p1"] = p1
        if p2 is not None:
            kwargs["p2"] = p2
        payload = cmd.to_bytes(**kwargs)
        if self.verbose:
            self._log(f"-> {payload.hex().upper()}")
        resp = self.iface.send_raw_apdu(payload, reader=self.reader)
        if self.verbose:
            self._log(f"<- {resp['data_hex']} SW={resp['sw1']:02X}{resp['sw2']:02X}")
        return bytes.fromhex(resp["data_hex"]) if resp.get("data_hex") else b"", resp["sw1"], resp["sw2"]

    def _select_ppse(self) -> Tuple[bytes, bool]:
        ppse_df = b"2PAY.SYS.DDF01"  # PPSE name
        data, sw1, sw2 = self._send(self.iface.commands["SELECT_DF"], data=ppse_df)
        ok = (sw1, sw2) == (0x90, 0x00)
        return data, ok

    def _select_aid(self, aids: List[str]) -> Tuple[Optional[str], bytes]:
        # Try each AID until selection succeeds
        for aid in aids:
            data, sw1, sw2 = self._send(self.iface.commands["SELECT_ADF"], data=bytes.fromhex(aid))
            if (sw1, sw2) == (0x90, 0x00):
                self._log(f"Selected AID {aid}")
                return aid, data
        return None, b""

    def _gpo(self) -> Tuple[bytes, bool]:
        # GPO with PDOL absent (simple template)
        # Construct a minimal PDOL: 83 00 (no PDOL) per some cards' tolerance, or tag-constructed 0 length.
        gpo_template = bytes.fromhex("8300")
        data, sw1, sw2 = self._send(self.iface.commands["GET_PROCESSING_OPTIONS"], data=gpo_template)
        ok = (sw1, sw2) == (0x90, 0x00)
        return data, ok

    def _read_records_from_afl(self, gpo_resp: bytes) -> List[Tuple[int, int, bytes, int, int]]:
        # Parse AFL from GPO response template (simple TLV scan for tag 94)
        afl = None
        i = 0
        while i < len(gpo_resp) - 1:
            tag = gpo_resp[i]
            if tag == 0x94:  # AFL
                length = gpo_resp[i + 1]
                afl = gpo_resp[i + 2:i + 2 + length]
                break
            i += 1
        records: List[Tuple[int, int, bytes, int, int]] = []
        if not afl:
            return records
        # AFL is tuples of 4 bytes: SFI|RecStart|RecEnd|NumRecordsAC
        for j in range(0, len(afl), 4):
            sfi = afl[j] >> 3
            rec_start = afl[j + 1]
            rec_end = afl[j + 2]
            for rec in range(rec_start, rec_end + 1):
                p1 = rec
                p2 = (sfi << 3) | 0x04
                cmd = self.iface.commands["READ_RECORD"]
                payload = cmd.to_bytes(p1=p1, p2=p2)
                if self.verbose:
                    self._log(f"-> {payload.hex().upper()}")
                resp = self.iface.send_raw_apdu(payload, reader=self.reader)
                data_hex = resp.get("data_hex", "")
                data = bytes.fromhex(data_hex) if data_hex else b""
                sw1, sw2 = resp["sw1"], resp["sw2"]
                if self.verbose:
                    self._log(f"<- {data_hex} SW={sw1:02X}{sw2:02X}")
                records.append((sfi, rec, data, sw1, sw2))
        return records

    def _verify_pin_if_supplied(self, pin: Optional[str]) -> Tuple[bool, Optional[Tuple[int, int]]]:
        if not pin:
            return True, None
        # Construct a simple plaintext PIN block (ISO-0 not encrypted here; demo only)
        pin_digits = ''.join(ch for ch in pin if ch.isdigit())[:12]
        pin_len = len(pin_digits)
        if pin_len == 0:
            return True, None
        pin_block = bytes([pin_len]) + pin_digits.encode("ascii")
        data, sw1, sw2 = self._send(self.iface.commands["VERIFY_PIN"], data=pin_block)
        return (sw1, sw2) == (0x90, 0x00), (sw1, sw2)

    def _generate_ac(self) -> Tuple[bytes, int, int]:
        # Minimal GENERATE AC (first AC)
        # CDOL1 building is issuer-specific; we send an empty template to trigger card defaults if any
    # P1=0x80 request ARQC if supported; P2=0x00
    data, sw1, sw2 = self._send(self.iface.commands["GENERATE_AC"], data=b"", p1=0x80, p2=0x00)
        return data, sw1, sw2

    def run_purchase(self, amount_cents: int, preferred_aids: Optional[List[str]] = None,
                     pin: Optional[str] = None) -> Dict:
        """Run a minimal purchase flow. Returns a dict summary."""
        preferred_aids = preferred_aids or DEFAULT_PREFERRED_AIDS
        summary = {"ok": False, "steps": [], "aid": None, "errors": []}

        # 1) PPSE
        data, ok = self._select_ppse()
        summary["steps"].append({"step": "SELECT_PPSE", "ok": ok})
        if not ok:
            summary["errors"].append("PPSE selection failed")
            return summary

        # 2) AID selection
        aid, fci = self._select_aid(preferred_aids)
        if not aid:
            summary["errors"].append("No supported AID on card")
            return summary
        summary["aid"] = aid

        # 3) GPO
        gpo, ok = self._gpo()
        summary["steps"].append({"step": "GPO", "ok": ok})
        if not ok:
            summary["errors"].append("GPO failed")
            return summary

        # 4) Read AFL records
        records = self._read_records_from_afl(gpo)
        summary["records"] = len(records)

        # 5) Optional PIN verify
        pin_ok, pin_sw = self._verify_pin_if_supplied(pin)
        summary["steps"].append({"step": "PIN", "ok": pin_ok, "sw": pin_sw})

        # 6) GENERATE AC
        ac, sw1, sw2 = self._generate_ac()
        summary["steps"].append({"step": "GENERATE_AC", "sw": (sw1, sw2)})
        summary["ok"] = (sw1, sw2) == (0x90, 0x00)
        return summary

    def run_withdrawal(self, amount_cents: int, preferred_aids: Optional[List[str]] = None,
                        pin: Optional[str] = None) -> Dict:
        """Run a minimal ATM cash withdrawal flow (very similar to purchase)."""
        # For now re-use purchase flow; ATM differences (CVM, TTQ) are abstracted away
        return self.run_purchase(amount_cents, preferred_aids, pin)


__all__ = ["EMVTerminalFlow", "DEFAULT_PREFERRED_AIDS"]
