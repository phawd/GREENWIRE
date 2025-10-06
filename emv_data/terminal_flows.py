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


from core.emv_processor import EMVProcessor
try:
    from static.lib.greenwire_emv_compliance import EMVCompliance
    HAVE_EMV_COMPLIANCE = True
except Exception:
    HAVE_EMV_COMPLIANCE = False

class EMVTerminalFlow:
    """Runs an advanced EMV terminal flow using APDU4J integration, with ATR reporting, PDOL/CDOL, and card type analysis."""

    def __init__(self, reader: Optional[str] = None, verbose: bool = False):
        if not HAVE_APDU4J:
            raise RuntimeError("APDU4J integration not available in this environment")
        self.iface = GREENWIREAPDU4JInterface(verbose=verbose)
        self.reader = reader
        self.verbose = verbose
        self.emv_processor = EMVProcessor()
        self.compliance = EMVCompliance(verbose=verbose) if HAVE_EMV_COMPLIANCE else None
        self.atr = None
        
    def get_atr(self) -> Optional[str]:
        """Get ATR from the card if available (pyscard or APDU4J)."""
        # Try pyscard if available
        try:
            from menu_implementations import SmartCardManager
            mgr = SmartCardManager()
            if mgr.get_readers():
                if mgr.connect_to_card(self.reader):
                    atr = mgr.get_atr()
                    mgr.disconnect()
                    self.atr = atr
                    return atr
        except Exception:
            pass
        # Fallback: try APDU4J interface if it exposes ATR
        try:
            if hasattr(self.iface, 'get_atr'):
                atr = self.iface.get_atr(reader=self.reader)
                self.atr = atr
                return atr
        except Exception:
            pass
        return None

    def report_card_type(self, fci_data: bytes = b"", aid: Optional[str] = None) -> dict:
        """Report card type and details using EMVCompliance if available."""
        card_data = {}
        # Parse FCI for AID, label, etc.
        tlvs = self.emv_processor.parse_tlv_data(fci_data)
        for tlv in tlvs:
            tag = tlv['tag']
            val = tlv['value']
            if tag == '4F':
                card_data['aid'] = val.hex().upper()
            elif tag == '50':
                try:
                    card_data['application_label'] = val.decode('ascii', errors='replace').strip()
                except Exception:
                    card_data['application_label'] = val.hex()
            elif tag == '5A':
                card_data['pan'] = val.hex().upper()
        if aid and 'aid' not in card_data:
            card_data['aid'] = aid
        if self.atr:
            card_data['atr'] = self.atr
        if self.compliance:
            return self.compliance.detect_card_type(card_data)
        return card_data

    def extract_pdol(self, fci_data: bytes) -> Optional[List[Tuple[str, int]]]:
        """Extract PDOL from FCI Template (tag 9F38) and return list of (tag, length)."""
        tlvs = self.emv_processor.parse_tlv_data(fci_data)
        for tlv in tlvs:
            if tlv['tag'] == '9F38':
                pdol_bytes = tlv['value']
                pdol = []
                i = 0
                while i < len(pdol_bytes):
                    # Tag: 1 or 2 bytes
                    tag = f"{pdol_bytes[i]:02X}"
                    i += 1
                    if (int(tag, 16) & 0x1F) == 0x1F and i < len(pdol_bytes):
                        tag += f"{pdol_bytes[i]:02X}"
                        i += 1
                    if i >= len(pdol_bytes):
                        break
                    length = pdol_bytes[i]
                    i += 1
                    pdol.append((tag, length))
                return pdol
        return None

    def build_pdol_data(self, pdol: Optional[List[Tuple[str, int]]], overrides: Optional[dict] = None) -> bytes:
        """Build PDOL data block for GPO from tag/length list and optional overrides."""
        if not pdol:
            return bytes.fromhex("8300")  # No PDOL present
        data = b''
        overrides = overrides or {}
        for tag, length in pdol:
            val = overrides.get(tag)
            if val is not None:
                v = bytes.fromhex(val) if isinstance(val, str) else val
                v = v[:length].ljust(length, b'\x00')
            else:
                v = b'\x00' * length
            data += v
        return bytes([0x83, len(data)]) + data

    def extract_cdol(self, records: List[Tuple[int, int, bytes, int, int]], cdol_tag: str = '8C') -> Optional[List[Tuple[str, int]]]:
        """Extract CDOL1 or CDOL2 from records (tag 8C or 8D)."""
        for sfi, rec, data, sw1, sw2 in records:
            tlvs = self.emv_processor.parse_tlv_data(data)
            for tlv in tlvs:
                if tlv['tag'] == cdol_tag:
                    cdol_bytes = tlv['value']
                    cdol = []
                    i = 0
                    while i < len(cdol_bytes):
                        tag = f"{cdol_bytes[i]:02X}"
                        i += 1
                        if (int(tag, 16) & 0x1F) == 0x1F and i < len(cdol_bytes):
                            tag += f"{cdol_bytes[i]:02X}"
                            i += 1
                        if i >= len(cdol_bytes):
                            break
                        length = cdol_bytes[i]
                        i += 1
                        cdol.append((tag, length))
                    return cdol
        return None

    def build_cdol_data(self, cdol: Optional[List[Tuple[str, int]]], overrides: Optional[dict] = None) -> bytes:
        """Build CDOL data block for GENERATE AC from tag/length list and optional overrides."""
        if not cdol:
            return b''
        data = b''
        overrides = overrides or {}
        for tag, length in cdol:
            val = overrides.get(tag)
            if val is not None:
                v = bytes.fromhex(val) if isinstance(val, str) else val
                v = v[:length].ljust(length, b'\x00')
            else:
                v = b'\x00' * length
            data += v
        return data

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    def list_readers(self) -> List[str]:
        return self.iface.list_readers()

    def _send(self, cmd: APDU4JCommand, data: bytes = b"", le: Optional[int] = None,
              p1: Optional[int] = None, p2: Optional[int] = None) -> Tuple[bytes, int, int]:
        # Use the command template's CLA/INS, but override P1/P2 and add data/le
        final_p1 = p1 if p1 is not None else cmd.p1
        final_p2 = p2 if p2 is not None else cmd.p2
        
        if self.verbose:
            self._log(f"-> CLA={cmd.cla:02X} INS={cmd.ins:02X} P1={final_p1:02X} P2={final_p2:02X} DATA={data.hex().upper() if data else ''} LE={le}")
        resp = self.iface.send_raw_apdu(cmd.cla, cmd.ins, final_p1, final_p2, data, le)
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
