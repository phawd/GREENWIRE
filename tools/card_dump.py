"""Card memory dump utility.

This provides a safe, dry-runable APDU dumper and a real PC/SC-backed dumper when pyscard is available.

Usage (dry-run):
  from tools.card_dump import dump_card
  dump_card(dry_run=True)

Usage (real):
  python -m tools.card_dump --reader "ACS ACR122" --out dumps/mydump.json
"""
from __future__ import annotations

import json
import os
import time
from typing import Dict, Optional

try:
    from smartcard.System import readers
    from smartcard.util import toHexString
    from smartcard.Exceptions import NoReadersAvailable
    HAS_PCSC = True
except Exception:
    HAS_PCSC = False


def _bytes_to_spaced_hex(b: bytes) -> str:
    return ' '.join(f"{x:02X}" for x in b)


def _parse_tlv(data: bytes) -> dict:
    """Minimal BER-TLV parser returning tag(hex)->value(bytes).

    Handles multi-byte tags and short/long lengths sufficiently for EMV FCI/GPO parsing.
    """
    out = {}
    i = 0
    L = len(data)
    while i < L:
        # parse tag
        tag_start = i
        first = data[i]
        i += 1
        if (first & 0x1F) == 0x1F:
            # multi-byte tag
            tag_bytes = bytes([first])
            while i < L:
                b = data[i]
                tag_bytes += bytes([b])
                i += 1
                if not (b & 0x80):
                    break
            tag = tag_bytes.hex().upper()
        else:
            tag = bytes([first]).hex().upper()

        # parse length
        if i >= L:
            break
        length_byte = data[i]
        i += 1
        if length_byte & 0x80:
            num_len_bytes = length_byte & 0x7F
            if num_len_bytes == 0 or i + num_len_bytes > L:
                break
            length = int.from_bytes(data[i:i+num_len_bytes], 'big')
            i += num_len_bytes
        else:
            length = length_byte

        if i + length > L:
            break
        value = data[i:i+length]
        i += length
        out[tag] = value
    return out


def list_readers() -> list[str]:
    if not HAS_PCSC:
        return []
    try:
        return [str(r) for r in readers()]
    except NoReadersAvailable:
        return []


def _read_record_connection(conn, sfi: int, record: int) -> Optional[Dict]:
    # READ RECORD: CLA=0x00 INS=0xB2 P1=record P2=(SFI<<3)|4 Le=0
    apdu = [0x00, 0xB2, record & 0xFF, ((sfi & 0x1F) << 3) | 4, 0x00]
    try:
        resp, sw1, sw2 = conn.transmit(apdu)
        sw = (sw1 << 8) | sw2
        return {"sfi": sfi, "record": record, "sw": hex(sw), "data": toHexString(resp)}
    except Exception:
        return None


def dump_card(reader_name: Optional[str] = None, out_path: Optional[str] = None, dry_run: bool = True,
              max_sfi: int = 10, max_records: int = 16, aid_hex: Optional[str] = None,
              use_ppse: bool = True) -> str:
    """Dump card records across SFI and record ranges.

    dry_run: if True, produce a small synthetic sample instead of talking to hardware.
    Returns path to JSON dump file.
    """
    os.makedirs("dumps", exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    out_file = out_path or os.path.join("dumps", f"card_dump_{timestamp}.json")

    if dry_run or not HAS_PCSC:
        sample = {
            "reader": reader_name or "DRY-RUN-READER",
            "generated_at": timestamp,
            "notes": "dry-run sample, enable pyscard and set dry_run=False to perform a real dump",
            "records": [
                {"sfi": 2, "record": 1, "sw": "0x9000", "data": "70 81 9F ... (truncated)"},
                {"sfi": 2, "record": 2, "sw": "0x9000", "data": "70 64 5A ... (truncated)"},
            ],
        }
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(sample, f, indent=2)
        return out_file

    # Real PC/SC-backed dump
    from smartcard.System import readers as _readers
    rlist = [r for r in _readers()]
    if not rlist:
        raise RuntimeError("No PC/SC readers available")

    # pick requested reader or first
    selected = None
    if reader_name:
        for r in rlist:
            if reader_name in str(r):
                selected = r
                break
    if selected is None:
        selected = rlist[0]

    conn = selected.createConnection()
    conn.connect()

    dump = {"reader": str(selected), "generated_at": timestamp, "records": []}

    # EMV-aware flow: SELECT PPSE (optionally), SELECT AID, GET PROCESSING OPTIONS, parse AFL, then READ RECORD per AFL
    def select_by_aid(aid_bytes: bytes) -> Optional[bytes]:
        apdu = [0x00, 0xA4, 0x04, 0x00, len(aid_bytes)] + list(aid_bytes) + [0x00]
        try:
            resp, sw1, sw2 = conn.transmit(apdu)
            sw = (sw1 << 8) | sw2
            if sw == 0x9000:
                return bytes(resp)
            return None
        except Exception:
            return None

    selected_aid = None
    fci_bytes = None

    # Try PPSE first if requested
    if use_ppse:
        try:
            ppse = bytes.fromhex('325041592E5359532E4444463031')  # '2PAY.SYS.DDF01'
            resp, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(ppse)] + list(ppse) + [0x00])
            sw = (sw1 << 8) | sw2
            if sw == 0x9000:
                fci_bytes = bytes(resp)
                # parse FCI for AIDs (tag 4F)
                tags = _parse_tlv(fci_bytes)
                if '4F' in tags:
                    # If multiple AIDs were present, this simplistic parser will pick the first
                    selected_aid = tags['4F']
        except Exception:
            selected_aid = None

    # If user supplied an AID, use that instead
    if aid_hex:
        try:
            selected_aid = bytes.fromhex(aid_hex)
        except Exception:
            pass

    # If we have an AID, SELECT it to get PDOL/FCI
    if selected_aid:
        sel = select_by_aid(selected_aid)
        if sel:
            fci_bytes = sel

    # If no AID found and no PPSE response, fall back to blind scan
    if not fci_bytes:
        # fallback to previous blind scan behaviour if we couldn't establish application
        for sfi in range(1, max_sfi + 1):
            for record in range(1, max_records + 1):
                entry = _read_record_connection(conn, sfi, record)
                if entry is None:
                    continue
                dump["records"].append(entry)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(dump, f, indent=2)
        return out_file

    # Parse PDOL (9F38) from FCI
    fci_tlvs = _parse_tlv(fci_bytes)
    pdol = fci_tlvs.get('9F38')

    # Build PDOL data (zeros for now) if present
    pdol_data = b''
    if pdol:
        # PDOL is a sequence of tags/lengths — parse sequentially
        i = 0
        while i < len(pdol):
            # parse tag
            t = pdol[i]
            i += 1
            if (t & 0x1F) == 0x1F:
                # multi-byte tag
                tag_bytes = bytes([t])
                while i < len(pdol):
                    b = pdol[i]
                    tag_bytes += bytes([b])
                    i += 1
                    if not (b & 0x80):
                        break
                # ignore tag value here
            # next byte is length
            if i >= len(pdol):
                break
            length = pdol[i]
            i += 1
            pdol_data += b'\x00' * length

    # Construct GPO command
    if pdol_data:
        gpo_data = bytes([0x83, len(pdol_data)]) + pdol_data
    else:
        gpo_data = bytes([0x83, 0x00])

    gpo_apdu = [0x80, 0xA8, 0x00, 0x00, len(gpo_data)] + list(gpo_data) + [0x00]
    try:
        resp, sw1, sw2 = conn.transmit(gpo_apdu)
        sw = (sw1 << 8) | sw2
        if sw != 0x9000:
            # fallback to blind scan
            for sfi in range(1, max_sfi + 1):
                for record in range(1, max_records + 1):
                    entry = _read_record_connection(conn, sfi, record)
                    if entry is None:
                        continue
                    dump["records"].append(entry)
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(dump, f, indent=2)
            return out_file
        gpo_resp = bytes(resp)
    except Exception:
        # on error fallback to blind scan
        for sfi in range(1, max_sfi + 1):
            for record in range(1, max_records + 1):
                entry = _read_record_connection(conn, sfi, record)
                if entry is None:
                    continue
                dump["records"].append(entry)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(dump, f, indent=2)
        return out_file

    # parse AFL: look for tag '94'
    gpo_tlvs = _parse_tlv(gpo_resp)
    afl = gpo_tlvs.get('94')
    if not afl:
        # sometimes response uses template '80' (AIP + AFL). Handle that simple case.
        if len(gpo_resp) >= 4 and gpo_resp[0] == 0x80:
            # skip tag and length: tag(1) + len(1)
            if len(gpo_resp) >= 4:
                # AIP is next two bytes, AFL follows
                afl = gpo_resp[2:]

    if not afl:
        # no AFL found -> fallback to blind scan
        for sfi in range(1, max_sfi + 1):
            for record in range(1, max_records + 1):
                entry = _read_record_connection(conn, sfi, record)
                if entry is None:
                    continue
                dump["records"].append(entry)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(dump, f, indent=2)
        return out_file

    # AFL is a sequence of 4-byte entries
    for i in range(0, len(afl), 4):
        if i + 4 > len(afl):
            break
        entry = afl[i:i+4]
        raw_sfi = entry[0]
        # Some cards encode SFI directly (1..31), others encode (SFI<<3). Try both.
        if 1 <= raw_sfi <= 31:
            sfi = raw_sfi
        else:
            sfi = raw_sfi >> 3
        first_rec = entry[1]
        last_rec = entry[2]
        # offline auth records count = entry[3] (not used here)
        for rec in range(first_rec, last_rec + 1):
            item = _read_record_connection(conn, sfi, rec)
            if item:
                dump["records"].append(item)

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(dump, f, indent=2)

    return out_file


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Dump card memory (records) to a JSON file")
    parser.add_argument("--reader", help="Reader name override", default=None)
    parser.add_argument("--out", help="Output file path (JSON)", default=None)
    parser.add_argument("--real", action="store_true", help="Use PC/SC and perform a real dump")
    args = parser.parse_args()

    path = dump_card(reader_name=args.reader, out_path=args.out, dry_run=not args.real)
    print(f"Dump written to: {path}")
