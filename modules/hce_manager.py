"""
HCE Manager — Android Host Card Emulation Orchestration.

Manages AID routing, APDU dispatch, ARQC generation, and transaction
state for both rooted and non-rooted Android devices connected via ADB.

Architecture:
    NFC Reader → HostApduService (APK on device)
                    ↕ TCP via adb forward
                GREENWIRE HCE Manager
                    ↕
                modules/crypto/emv_crypto.py  (ARQC)
                    ↕
                modules/tsp_integration.py    (DPAN / LUK)
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EMV AID Registry
# ---------------------------------------------------------------------------

PAYMENT_AIDS: Dict[str, str] = {
    "A0000000031010": "Visa Credit/Debit",
    "A0000000032010": "Visa Electron",
    "A0000000033010": "Visa V PAY",
    "A0000000041010": "Mastercard Credit",
    "A0000000043060": "Mastercard Maestro",
    "A0000000046000": "Mastercard Cirrus",
    "A000000025010801": "Amex",
    "A0000000651010": "JCB",
    "A0000001524010": "Discover",
    "325041592E5359532E4444463031": "PPSE (2PAY.SYS.DDF01)",
}

PPSE_AID = bytes.fromhex("325041592E5359532E4444463031")
PPSE_RESPONSE_TEMPLATE = (
    "6F{tlen:02X}"                         # FCI Template
    "84{alen:02X}{aid}"                    # DF Name
    "A5{blen:02X}"                         # FCI Prop
    "BF0C{flen:02X}"                       # FCI Issuer Discretionary Data
    "61{elen:02X}"                         # App Template
    "4F{klen:02X}{aid}"                    # ADF Name
    "500{nlen:01X}{name}"                  # App Label
    "9F2A01{priority:02X}"                 # App Priority
)

# PPSE FCI for a single Visa application — used when reader SELECT 2PAY.SYS
VISA_PPSE_FCI = bytes.fromhex(
    "6F23840E325041592E5359532E444446303100"
    "A511BF0C0E610C4F07A0000000031010500456495341"
)

# ---------------------------------------------------------------------------
# Transaction state
# ---------------------------------------------------------------------------

@dataclass
class TransactionContext:
    """Tracks state across the multi-step EMV flow."""
    aid: str = ""
    dpan: str = ""
    token_reference: str = ""
    expiry: str = ""
    scheme: str = ""
    atc: int = 0
    un: bytes = b""                 # Unpredictable Number from reader
    pdol_data: bytes = b""
    amount: int = 0                 # in minor currency unit
    currency: int = 978             # ISO 4217 EUR default
    cvr: bytes = b"\x03\x80\x00"   # Card Verification Results
    arqc: bytes = b""
    tc: bytes = b""
    aac: bytes = b""
    current_record: Dict[str, bytes] = field(default_factory=dict)
    started: float = field(default_factory=time.time)
    stage: str = "idle"             # idle→select→gpo→readrec→genac→done


# ---------------------------------------------------------------------------
# Core HCE Manager
# ---------------------------------------------------------------------------

class HCEManager:
    """
    Orchestrates an HCE session from PPSE SELECT through GENERATE AC.

    Works with both rooted and non-rooted devices via the APDU relay
    served by GreenwireHCEService.apk (see java/hce/).

    ADB port forward:  adb forward tcp:7816 localabstract:greenwire-hce
    """

    RELAY_PORT = 7816
    RELAY_HOST = "127.0.0.1"

    def __init__(
        self,
        device_id: Optional[str] = None,
        relay_port: int = RELAY_PORT,
        tsp_client=None,               # VTSSandboxClient | MDESSandboxClient
        scheme: str = "visa",
        verbose: bool = False,
    ) -> None:
        self.device_id = device_id
        self.relay_port = relay_port
        self.tsp = tsp_client
        self.scheme = scheme.lower()
        self.verbose = verbose

        self._ctx: TransactionContext = TransactionContext()
        self._tokens: Dict[str, object] = {}      # token_ref → TokenRecord
        self._active_aid: Optional[str] = None
        self._relay_sock: Optional[socket.socket] = None
        self._lock = threading.Lock()

        # APDU dispatch table: INS → handler
        self._handlers: Dict[int, Callable] = {
            0xA4: self._handle_select,
            0xB2: self._handle_read_record,
            0xA8: self._handle_gpo,
            0xAE: self._handle_generate_ac,
            0x82: self._handle_external_authenticate,
            0xCA: self._handle_get_data,
        }

    # ------------------------------------------------------------------
    # ADB relay lifecycle
    # ------------------------------------------------------------------

    def setup_adb_forward(self) -> bool:
        """Run adb forward to expose device relay socket on localhost."""
        cmd = f"adb{f' -s {self.device_id}' if self.device_id else ''} forward tcp:{self.relay_port} localabstract:greenwire-hce"
        ret = os.system(cmd)
        if ret != 0:
            logger.error("adb forward failed (rc=%d) — is USB debugging enabled?", ret)
            return False
        logger.info("adb forward: tcp:%d → device:greenwire-hce", self.relay_port)
        return True

    def connect_relay(self, timeout: float = 10.0) -> bool:
        """Connect to the HCE relay socket (after adb forward)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((self.RELAY_HOST, self.relay_port))
                self._relay_sock = s
                logger.info("Relay connected on port %d", self.relay_port)
                return True
            except (ConnectionRefusedError, OSError):
                time.sleep(0.5)
        logger.error("Could not connect to HCE relay after %.0fs", timeout)
        return False

    def disconnect_relay(self) -> None:
        if self._relay_sock:
            try:
                self._relay_sock.close()
            except OSError:
                pass
            self._relay_sock = None

    # ------------------------------------------------------------------
    # Token loading
    # ------------------------------------------------------------------

    def load_token(self, token_record) -> None:
        """Load a provisioned TokenRecord into the HCE manager."""
        self._tokens[token_record.token_reference] = token_record
        self._active_aid = self._aid_for_scheme(token_record.scheme)
        self._ctx.dpan = token_record.dpan
        self._ctx.token_reference = token_record.token_reference
        self._ctx.expiry = token_record.expiry
        self._ctx.scheme = token_record.scheme
        self._ctx.atc = 1
        logger.info(
            "Token loaded: DPAN=%s scheme=%s AID=%s",
            token_record.dpan[:6] + "****" + token_record.dpan[-4:],
            token_record.scheme,
            self._active_aid,
        )

    def _aid_for_scheme(self, scheme: str) -> str:
        if scheme.upper() == "VISA":
            return "A0000000031010"
        elif scheme.upper() in ("MASTERCARD", "MC"):
            return "A0000000041010"
        return "A0000000031010"

    # ------------------------------------------------------------------
    # Relay loop
    # ------------------------------------------------------------------

    def run_relay_loop(self) -> None:
        """
        Listen on relay socket and process APDUs.
        Blocking — run in a thread for non-interactive use.
        """
        if not self._relay_sock:
            raise RuntimeError("Call connect_relay() first")

        logger.info("HCE relay loop started — waiting for APDUs")
        try:
            while True:
                apdu = self._recv_apdu()
                if apdu is None:
                    logger.info("Relay disconnected")
                    break
                if self.verbose:
                    logger.debug("APDU IN:  %s", apdu.hex().upper())
                response = self._process_apdu(apdu)
                if self.verbose:
                    logger.debug("APDU OUT: %s", response.hex().upper())
                self._send_response(response)
        finally:
            self.disconnect_relay()

    def _recv_apdu(self) -> Optional[bytes]:
        """Read length-prefixed APDU from relay (2-byte big-endian length)."""
        try:
            hdr = self._recv_exact(2)
            if not hdr:
                return None
            length = struct.unpack(">H", hdr)[0]
            return self._recv_exact(length)
        except OSError:
            return None

    def _recv_exact(self, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            chunk = self._relay_sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _send_response(self, data: bytes) -> None:
        framed = struct.pack(">H", len(data)) + data
        self._relay_sock.sendall(framed)

    # ------------------------------------------------------------------
    # APDU dispatch
    # ------------------------------------------------------------------

    def _process_apdu(self, apdu: bytes) -> bytes:
        if len(apdu) < 4:
            return bytes([0x67, 0x00])  # Wrong length
        ins = apdu[1]
        handler = self._handlers.get(ins)
        if handler:
            try:
                return handler(apdu)
            except Exception as e:
                logger.exception("Handler error for INS %02X: %s", ins, e)
                return bytes([0x6F, 0x00])
        logger.warning("Unsupported INS: %02X", ins)
        return bytes([0x6D, 0x00])  # INS not supported

    def _handle_select(self, apdu: bytes) -> bytes:
        """Handle SELECT AID (INS=A4)."""
        lc = apdu[4] if len(apdu) > 4 else 0
        aid_bytes = apdu[5:5 + lc] if lc else b""

        if aid_bytes == PPSE_AID:
            self._ctx.stage = "select"
            return VISA_PPSE_FCI + bytes([0x90, 0x00])

        aid_hex = aid_bytes.hex().upper()
        if self._active_aid and aid_hex == self._active_aid:
            self._ctx.aid = aid_hex
            self._ctx.stage = "select"
            return self._build_fci(aid_bytes) + bytes([0x90, 0x00])

        return bytes([0x6A, 0x82])  # File not found

    def _handle_gpo(self, apdu: bytes) -> bytes:
        """Handle GET PROCESSING OPTIONS (INS=A8)."""
        self._ctx.stage = "gpo"
        # Extract PDOL data from APDU
        if len(apdu) > 5:
            self._ctx.pdol_data = apdu[5:]
            self._ctx.un = apdu[5:9] if len(apdu) > 8 else secrets.token_bytes(4)
        else:
            import secrets
            self._ctx.un = secrets.token_bytes(4)

        # AIP: contact chip, offline DDA supported, CVM supported
        aip = bytes([0x40, 0x00])
        # AFL: SFI 1, record 1-1
        afl = bytes([0x08, 0x01, 0x01, 0x00])

        response = b"\x80" + bytes([2 + len(afl)]) + aip + afl
        return response + bytes([0x90, 0x00])

    def _handle_read_record(self, apdu: bytes) -> bytes:
        """Handle READ RECORD (INS=B2)."""
        self._ctx.stage = "readrec"
        record_num = apdu[2]
        sfi = (apdu[3] >> 3) & 0x1F

        if sfi == 1 and record_num == 1:
            record = self._build_card_record()
            tlv = b"\x70" + bytes([len(record)]) + record
            return tlv + bytes([0x90, 0x00])

        return bytes([0x6A, 0x83])  # Record not found

    def _handle_generate_ac(self, apdu: bytes) -> bytes:
        """Handle GENERATE AC (INS=AE) — computes ARQC/TC/AAC."""
        self._ctx.stage = "genac"
        ref_ctrl = apdu[2]
        crypto_type = (ref_ctrl >> 6) & 0x03
        # 0=AAC (decline), 1=TC (approve offline), 2=ARQC (go online)

        arqc = self._compute_arqc()
        self._ctx.arqc = arqc
        self._ctx.atc += 1

        # Response format 2
        response_data = (
            b"\x80"
            + bytes([len(arqc) + 4])
            + bytes([crypto_type << 6])    # CID
            + bytes([0x00])                 # ATC high
            + bytes([self._ctx.atc & 0xFF])# ATC low
            + arqc
        )
        return response_data + bytes([0x90, 0x00])

    def _handle_external_authenticate(self, apdu: bytes) -> bytes:
        """Handle EXTERNAL AUTHENTICATE (INS=82) — ARPC verification."""
        return bytes([0x90, 0x00])

    def _handle_get_data(self, apdu: bytes) -> bytes:
        """Handle GET DATA (INS=CA) — return ATC and PIN try counter."""
        tag = (apdu[2] << 8) | apdu[3]
        if tag == 0x9F36:  # ATC
            atc_val = self._ctx.atc.to_bytes(2, "big")
            return b"\x9F\x36\x02" + atc_val + bytes([0x90, 0x00])
        if tag == 0x9F17:  # PIN try counter
            return b"\x9F\x17\x01\x03" + bytes([0x90, 0x00])
        return bytes([0x6A, 0x88])

    # ------------------------------------------------------------------
    # Crypto: ARQC
    # ------------------------------------------------------------------

    def _compute_arqc(self) -> bytes:
        """Compute ARQC using EMV session key from TSP-provided LUK."""
        luk = self._get_luk()
        txn_data = self._build_txn_data()
        from modules.crypto.primitives import encrypt_tdes_ecb
        padded = _iso9797_pad(txn_data, block_size=8)
        mac = _des3_mac(luk, padded)
        return mac

    def _get_luk(self) -> bytes:
        """Fetch LUK for current ATC from TSP or derive locally."""
        if self.tsp:
            rec = self.tsp.get_current_luk(self._ctx.token_reference, self._ctx.atc)
            if rec:
                return bytes.fromhex(rec.luk_hex)
        # Fallback: derive from lab IMK
        from modules.crypto.emv_crypto import EMVKeyDerivation
        from modules.crypto.primitives import encrypt_tdes_ecb
        imk = bytes.fromhex("404142434445464748494A4B4C4D4E4F")
        icc_mk = EMVKeyDerivation.derive_icc_mk_a(imk, self._ctx.dpan or "4111111111111111", psn="00")
        atc_b = self._ctx.atc.to_bytes(2, "big")
        left  = encrypt_tdes_ecb(icc_mk, atc_b + b"\x00\x00" + atc_b + b"\x00\x00")[:8]
        right = encrypt_tdes_ecb(icc_mk, atc_b + b"\xFF\xFF" + atc_b + b"\xFF\xFF")[:8]
        return left + right

    def _build_txn_data(self) -> bytes:
        """Build EMV transaction data buffer for ARQC calculation."""
        amount   = self._ctx.amount.to_bytes(6, "big")
        currency = self._ctx.currency.to_bytes(2, "big")
        tvr      = b"\x00" * 5         # Terminal Verification Results (all pass)
        txn_date = b"\x24\x01\x01"     # YYMMDD
        txn_type = b"\x00"             # Purchase
        un       = self._ctx.un if len(self._ctx.un) == 4 else b"\xDE\xAD\xBE\xEF"
        atc      = self._ctx.atc.to_bytes(2, "big")
        iad      = b"\x06\x01\x0A\x03\x80\x00"  # Issuer App Data (stub)
        return amount + amount + currency + tvr + txn_date + txn_type + un + atc + iad

    # ------------------------------------------------------------------
    # TLV helpers
    # ------------------------------------------------------------------

    def _build_fci(self, aid: bytes) -> bytes:
        """Build minimal FCI for SELECT response."""
        inner = b"\x50\x04" + (b"VISA" if self.scheme == "visa" else b"MC  ")
        prop  = b"\xA5" + bytes([len(inner)]) + inner
        body  = b"\x84" + bytes([len(aid)]) + aid + prop
        return b"\x6F" + bytes([len(body)]) + body

    def _build_card_record(self) -> bytes:
        """Build SFI 1 Record 1 with DPAN, expiry, cardholder name."""
        dpan = self._ctx.dpan or "4111111111111111"
        expiry = self._ctx.expiry or "2512"
        pan_bytes = bytes.fromhex(dpan + ("F" if len(dpan) % 2 else ""))
        exp_bytes = bytes.fromhex(expiry)
        name = b"GREENWIRE/LAB"

        record  = b"\x5A" + bytes([len(pan_bytes)]) + pan_bytes
        record += b"\x5F\x24\x02" + exp_bytes
        record += b"\x5F\x20" + bytes([len(name)]) + name
        record += b"\x9F\x1F\x08" + b"\xFF" * 8   # Track 2 discretionary data
        return record

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> Dict:
        return {
            "relay_connected": self._relay_sock is not None,
            "active_aid": self._active_aid,
            "tokens_loaded": len(self._tokens),
            "stage": self._ctx.stage,
            "atc": self._ctx.atc,
            "scheme": self.scheme,
        }


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _iso9797_pad(data: bytes, block_size: int = 8) -> bytes:
    padded = data + b"\x80"
    while len(padded) % block_size:
        padded += b"\x00"
    return padded


def _des3_mac(key: bytes, data: bytes) -> bytes:
    """ISO 9797-1 MAC Algorithm 3 (3DES) — 8-byte output."""
    from Crypto.Cipher import DES, DES3
    if len(key) == 16:
        key3 = key + key[:8]
    else:
        key3 = key
    k1, k2 = key3[:8], key3[8:16]
    iv = b"\x00" * 8
    # Single-DES CBC over all blocks except the last
    if len(data) > 8:
        des_enc = DES.new(k1, DES.MODE_CBC, iv)
        iv = des_enc.encrypt(data[:-8])[-8:]
    # Final block: 3DES
    des3 = DES3.new(key3, DES3.MODE_CBC, iv)
    return des3.encrypt(data[-8:])


__all__ = ["HCEManager", "TransactionContext", "PAYMENT_AIDS"]
