#!/usr/bin/env python3
"""
================================================================================
GREENWIRE Enhanced ATM Emulator
================================================================================
Module:  modules/enhanced_atm_emulator.py
Purpose: Full-featured ATM emulator for EMV lab testing, education, and fuzzing
Author:  GREENWIRE Security Research Lab
Spec:    ISO 9564, EMV Book 3 (Contact) / Book D (Contactless), ISO 8583

────────────────────────────────────────────────────────────────────────────────
ATM ARCHITECTURE OVERVIEW
────────────────────────────────────────────────────────────────────────────────
A real ATM has several subsystems:

  [Card Reader / NFC] ──┐
  [PIN Pad / EPP]  ──────┼──► [ATM Application SW] ──► [XFS/CEN interface]
  [Cash Dispenser] ──────┘          │
  [Receipt Printer]                 │
                                    ▼
                           [HSM — Hardware Security Module]
                                    │
                                    ▼
                        [Network (TLS/NDC/X.25)] ──► [Acquiring Bank Host]
                                                             │
                                                             ▼
                                                     [Card Network (Visa/MC)]
                                                             │
                                                             ▼
                                                       [Issuing Bank]

This emulator simulates the ATM Application SW layer plus a software HSM stub.

────────────────────────────────────────────────────────────────────────────────
PIN BLOCK FORMATS (ISO 9564-1)
────────────────────────────────────────────────────────────────────────────────
Format 0 (most common — ATM/POS):
  PIN field  = 0 | len | PIN... | F-padding   (8 bytes)
  PAN field  = 0000 | rightmost-12-excl-check  (8 bytes)
  PIN block  = PIN_field XOR PAN_field

Format 1 (no PAN needed — used in DUKPT):
  PIN field  = 1 | len | PIN... | TXN-ID padding

Format 3 (PIN + random pad — stronger):
  PIN field  = 3 | len | PIN... | Random nibbles
  PAN field  = same as Format 0
  PIN block  = PIN_field XOR PAN_field

The PIN block is NEVER stored or logged. It is encrypted under the Zone
Encryption Key (ZEK/ZPK) before leaving the PIN pad (EPP) and can only be
decrypted by the HSM at the issuing bank.

────────────────────────────────────────────────────────────────────────────────
WHAT IS AN ARQC?
────────────────────────────────────────────────────────────────────────────────
ARQC = Authorization Request Cryptogram

During EMV transaction processing, after the card has performed risk analysis,
it generates a cryptogram using its issuer master key (derived session key) to
prove:
  (a) The card is genuine (cryptographic proof)
  (b) The transaction data has not been tampered with
  (c) The card is online and communicating with the terminal (freshness via ATC)

The ARQC is computed as:
  ARQC = MAC_k(ATC | amount | currency | date | tvr | terminal_country | ...)

where k is a session key derived from the card's master key and the ATC. The
issuing bank can re-derive the same session key and verify the ARQC. If the
ARQC verifies, the issuer sends back an ARPC (Authorization Response Cryptogram)
to confirm the approval to the card.

ARQC vs TC vs AAC (the three EMV cryptogram types):
  ARQC  — "I want to go online"  — card requests online authorization
  TC    — "I approve offline"    — card approves transaction without going online
  AAC   — "I decline"            — card refuses the transaction

────────────────────────────────────────────────────────────────────────────────
CONTACT vs CONTACTLESS ATM FLOW
────────────────────────────────────────────────────────────────────────────────
Contact (ISO 7816-3):
  ATR → SELECT PPSE → SELECT AID → GPO (Get Processing Options)
  → READ RECORD (each AFL entry) → VERIFY PIN (offline, optional)
  → GENERATE AC (ARQC for online, TC for offline)
  → external auth if ARQC → GENERATE AC 2nd (TC)

Contactless (ISO 14443-4 / EMV Book D):
  RATS → SELECT PPSE → SELECT AID → GPO with PDOL/UDOL data
  (no PIN VERIFY — CVM is always signature or no-CVM for low amounts)
  → GENERATE AC in a single round-trip
  Contactless ATM withdrawals are rare and usually capped at low limits.
  Most ATMs only support contact cards for cash dispensing because the PIN
  pad for contactless is not standard hardware.
================================================================================
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import string
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ── GREENWIRE logger integration ─────────────────────────────────────────────
# Try the project's structured logger first; fall back gracefully to stdlib.
try:
    from core.logging_system import get_logger
    logger = get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)
    if not logger.handlers:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# ── Card validation ───────────────────────────────────────────────────────────
# Provides Luhn check and BIN lookup without requiring live network access.
try:
    from core.card_validator import validate_pan, CardProfile
    _HAVE_VALIDATOR = True
except ImportError:
    _HAVE_VALIDATOR = False
    CardProfile = None

# ── HSM integration ───────────────────────────────────────────────────────────
# ThalesEmulator provides: generate_key, generate_mac, generate_arqc,
# generate_pin_block, derive_emv_session_key, verify_pin, generate_arpc
try:
    from hsm.thales_emulator import ThalesEmulator
    _HAVE_HSM = True
except ImportError:
    _HAVE_HSM = False
    ThalesEmulator = None  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ATMTransaction:
    """
    Immutable record of a single ATM transaction attempt.

    Fields mirror the fields in an ISO 8583 authorization request (bitmap fields),
    plus ATM-specific state captured during the EMV card interaction.

    Fields:
        txn_id        : Unique transaction identifier (UUID-like hex string)
        pan_masked    : PAN with middle digits replaced by asterisks (PCI-DSS rule)
        amount        : Transaction amount as a float (e.g. 100.00)
        currency      : 3-char ISO 4217 code (e.g. "USD")
        txn_type      : "withdrawal" | "balance_inquiry" | "deposit"
        timestamp     : ISO-8601 wall-clock time of the transaction attempt
        approval_code : 6-char alphanumeric code from the issuer (ISO 8583 F38)
        status        : "approved" | "declined" | "error" | "pending"
        atc           : Application Transaction Counter — 2-byte integer from card
        arqc          : 8-byte Authorization Request Cryptogram as uppercase hex
        arpc          : 8-byte Authorization Response Cryptogram (from issuer)
        error         : Human-readable error message if status == "error"
        scheme        : Card network (visa/mastercard/amex…)
    """
    txn_id: str = ""
    pan_masked: str = ""
    amount: float = 0.0
    currency: str = "USD"
    txn_type: str = "withdrawal"
    timestamp: str = ""
    approval_code: str = ""
    status: str = "pending"
    atc: int = 0
    arqc: str = ""
    arpc: str = ""
    error: str = ""
    scheme: str = ""


def _mask_pan(pan: str) -> str:
    """
    Mask PAN per PCI-DSS requirement: show only first 6 and last 4 digits.
    Example: "4111111111111111" → "411111******1111"
    """
    pan = pan.replace(" ", "").replace("-", "")
    if len(pan) < 10:
        return "****"
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]


def _generate_txn_id() -> str:
    """Generate a random 16-character hex transaction ID (mimics host-assigned ID)."""
    return os.urandom(8).hex().upper()


def _luhn_valid(pan: str) -> bool:
    """
    Validate PAN using the Luhn (mod-10) algorithm (ISO/IEC 7812-1 Annex B).

    The check digit is the last digit. Starting from the second-to-last digit
    and moving left, every other digit is doubled. Digits > 9 have 9 subtracted.
    The total of all digits must be divisible by 10.
    """
    digits = [int(c) for c in pan if c.isdigit()]
    if len(digits) < 13:
        return False
    # Reverse so index 0 is the check digit, index 1 is first digit to double
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:              # every second digit from the right
            d *= 2
            if d > 9:
                d -= 9              # same as summing the two digits
        total += d
    return total % 10 == 0


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class EnhancedATMEmulator:
    """
    Full-featured ATM emulator for GREENWIRE lab testing.

    Simulates the ATM application layer: card acceptance, PIN verification,
    EMV transaction processing (SELECT → GPO → READ RECORD → GENERATE AC),
    online authorization (mocked), and receipt printing.

    Typical session flow:
        atm = EnhancedATMEmulator("ATM001", "Lobby", "001")
        print(atm.display_welcome_screen())
        ok, msg, card = atm.insert_card(pan="4111111111111111")
        ok, msg = atm.verify_pin("1234")
        result = atm.process_withdrawal(100.00)
        print(atm.print_receipt(result))
        atm.eject_card()
    """

    # Simulated account store (pan → {balance, pin_hash, blocked, name})
    _SIMULATED_ACCOUNTS: Dict[str, Dict] = {
        "4111111111111111": {
            "balance": 2500.00,
            "pin_hash": hashlib.sha256(b"1234").hexdigest(),
            "blocked": False,
            "name": "TEST CARDHOLDER",
        },
        "5500005555555559": {
            "balance": 1000.00,
            "pin_hash": hashlib.sha256(b"9999").hexdigest(),
            "blocked": False,
            "name": "MC TEST USER",
        },
        "378282246310005": {
            "balance": 5000.00,
            "pin_hash": hashlib.sha256(b"7777").hexdigest(),
            "blocked": False,
            "name": "AMEX TEST",
        },
    }

    def __init__(
        self,
        atm_id: str,
        location: str,
        bank_code: str,
        reader: Optional[str] = None,
        verbose: bool = True,
    ) -> None:
        """
        Initialise the ATM emulator and connect to the (software) HSM.

        Args:
            atm_id    : Unique identifier for this ATM (e.g. "ATM_001").
                        This appears on receipts and in log lines.
            location  : Human-readable location string (e.g. "Main Branch – Lobby").
            bank_code : 3-digit acquiring bank code used in ISO 8583 messages.
            reader    : Optional PC/SC reader name for real card interaction.
                        When None the emulator uses its built-in card simulator.
            verbose   : When True, print() progress as well as logging it.
        """
        self.atm_id = atm_id
        self.location = location
        self.bank_code = bank_code
        self.reader = reader
        self.verbose = verbose

        # Current session card state
        self._current_pan: Optional[str] = None
        self._card_profile: Optional[object] = None   # CardProfile or dict
        self._card_inserted: bool = False
        self._pin_verified: bool = False
        self._pin_attempts: int = 0
        self._card_blocked: bool = False

        # Session transaction history
        self._transaction_log: List[ATMTransaction] = []

        # ATC simulates the card's internal counter (incremented each transaction)
        self._atc: int = random.randint(1, 500)

        # Initialise HSM (software Thales emulator)
        if _HAVE_HSM:
            self._hsm = ThalesEmulator()
            # Pre-load a test master key for ARQC / MAC operations
            self._master_key_label = f"MK_{atm_id}"
            self._hsm.import_key(
                self._master_key_label,
                bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),  # test key only
            )
            logger.info("HSM initialised with master key label '%s'", self._master_key_label)
        else:
            self._hsm = None
            self._master_key_label = ""
            logger.warning("HSM module not available — cryptographic operations will be mocked")

        logger.info("ATM %s initialised at '%s' (bank_code=%s, reader=%s)",
                    atm_id, location, bank_code, reader or "simulator")

    # ── Display ───────────────────────────────────────────────────────────────

    def display_welcome_screen(self) -> str:
        """
        Render the ATM welcome screen text.

        In a real ATM this drives the LCD/touchscreen via XFS WFS_INF_IDC_STATUS.
        Here we return an ASCII representation and log the display event.

        Returns:
            Multi-line string representing the ATM welcome screen.
        """
        screen = (
            f"\n{'═' * 50}\n"
            f"  GREENWIRE BANK ATM\n"
            f"  Location : {self.location}\n"
            f"  Terminal : {self.atm_id}\n"
            f"  {datetime.now().strftime('%a %d %b %Y  %H:%M:%S')}\n"
            f"{'═' * 50}\n"
            f"  Please insert or tap your card\n"
            f"{'─' * 50}\n"
        )
        logger.info("Welcome screen displayed on ATM %s", self.atm_id)
        if self.verbose:
            print(screen)
        return screen

    # ── Card Acceptance ───────────────────────────────────────────────────────

    def insert_card(
        self,
        pan: Optional[str] = None,
        track2: Optional[str] = None,
    ) -> Tuple[bool, str, dict]:
        """
        Accept a card (real or simulated) into the ATM.

        This method handles:
          1. PAN extraction from track2 data if PAN not provided directly
          2. Luhn check (ISO/IEC 7812-1 Annex B)
          3. BIN lookup to identify the card network and issuer
          4. Blocked-card check against the simulated account store
          5. Setting internal state for downstream operations

        In a real ATM the ICC (chip) would be powered on here and ATR (Answer
        to Reset) received via ISO 7816-3, but for simulation we skip straight
        to card validation.

        Args:
            pan    : 13–19 digit PAN string.  Provide either this or track2.
            track2 : Raw Track 2 data in the format "PAN=YYMM SC..." as read
                     by the magnetic stripe reader.  The PAN is extracted from
                     the left of the '=' separator.

        Returns:
            (success: bool, message: str, card_info: dict)
            card_info keys: pan_masked, scheme, bank, luhn_ok, bin_country
        """
        # ── Extract PAN from track2 if not given directly ──────────────────
        if pan is None and track2 is not None:
            # Track 2 format:  <PAN>=<YYMM><SC>[discretionary data]
            pan = track2.split("=")[0].strip(";").strip()
            logger.debug("Extracted PAN from Track 2: %s", _mask_pan(pan))

        # ── Default to known test PAN when nothing is provided ─────────────
        if pan is None:
            pan = "4111111111111111"
            logger.info("No card data provided — using default test PAN %s", _mask_pan(pan))

        pan = pan.replace(" ", "").replace("-", "")

        # ── Luhn validation ────────────────────────────────────────────────
        if not _luhn_valid(pan):
            msg = f"PAN {_mask_pan(pan)} failed Luhn check — card rejected"
            logger.warning(msg)
            return False, msg, {}

        # ── BIN lookup / full card profile ────────────────────────────────
        card_info: dict = {"pan_masked": _mask_pan(pan), "scheme": "unknown",
                           "bank": "Unknown", "luhn_ok": True, "bin_country": "?"}
        if _HAVE_VALIDATOR:
            try:
                profile = validate_pan(pan)
                card_info.update({
                    "scheme":      profile.scheme,
                    "bank":        getattr(profile, "bank_name", "Unknown"),
                    "bin_country": getattr(profile, "issuer_country", "?"),
                    "luhn_ok":     profile.luhn_ok,
                })
                self._card_profile = profile
                logger.debug("BIN lookup: scheme=%s bank=%s country=%s",
                             profile.scheme, getattr(profile, "bank_name", "?"),
                             getattr(profile, "issuer_country", "?"))
            except Exception as exc:
                logger.warning("Card profile lookup failed: %s", exc)
        else:
            # Fallback heuristic BIN detection without the validator module
            if pan.startswith("4"):
                card_info["scheme"] = "visa"
            elif pan[:2] in ("51","52","53","54","55") or (222100 <= int(pan[:6]) <= 272099):
                card_info["scheme"] = "mastercard"
            elif pan[:2] in ("34","37"):
                card_info["scheme"] = "amex"
            elif pan.startswith("6011") or pan.startswith("65"):
                card_info["scheme"] = "discover"

        # ── Blocked-card check ─────────────────────────────────────────────
        acct = self._SIMULATED_ACCOUNTS.get(pan, {})
        if acct.get("blocked", False):
            msg = f"Card {_mask_pan(pan)} is blocked — retained"
            logger.warning(msg)
            self._card_blocked = True
            return False, msg, card_info

        # ── Commit state ───────────────────────────────────────────────────
        self._current_pan = pan
        self._card_inserted = True
        self._pin_verified = False
        self._pin_attempts = 0
        self._card_blocked = False

        msg = f"Card accepted: {_mask_pan(pan)} ({card_info['scheme'].upper()})"
        logger.info(msg)
        if self.verbose:
            print(f"  ✔ {msg}")
        return True, msg, card_info

    # ── PIN Verification ─────────────────────────────────────────────────────

    def verify_pin(self, pin: str, pan: Optional[str] = None) -> Tuple[bool, str]:
        """
        Verify the cardholder's PIN via ISO 9564 Format 0 PIN block and HSM.

        ISO 9564-1 Format 0 PIN Block Construction:
          Step 1 — Build PIN field (8 bytes):
                   Nibble 0 : 0x0 (format indicator)
                   Nibble 1 : PIN length in hex (4-12)
                   Nibbles 2–(1+L) : PIN digits
                   Remaining nibbles : 0xF (fill)
                   Example: PIN "1234" → 04 12 34 FF FF FF FF FF

          Step 2 — Build PAN field (8 bytes):
                   Nibble 0-3 : 0x0000 (zero pad)
                   Nibbles 4-15: 12 rightmost PAN digits EXCLUDING the check digit
                   Example: PAN "4111111111111111" → 00 00 11 11 11 11 11 10

          Step 3 — PIN block = PIN_field XOR PAN_field (8 bytes)

        The resulting PIN block is encrypted under the Zone Encryption Key (ZEK)
        before transmission to the HSM/issuer. The plaintext PIN block is NEVER
        stored or logged.

        This emulator passes the PIN block to ThalesEmulator.verify_pin() which
        compares a SHA-256 hash of the entered PIN against the stored hash
        (simulating what the issuer HSM would do after decryption).

        3-tries lockout: three consecutive failures block the card per EMV spec
        (EMV Book 3, section 7.3).

        Args:
            pin : Numeric PIN string (4–12 digits).
            pan : PAN override; if None, uses the currently inserted card PAN.

        Returns:
            (success: bool, message: str)
        """
        if not self._card_inserted:
            return False, "No card inserted"

        if self._card_blocked:
            return False, "Card is blocked — please contact your bank"

        if self._pin_attempts >= 3:
            self._card_blocked = True
            # Mark account as blocked in simulated store
            if self._current_pan and self._current_pan in self._SIMULATED_ACCOUNTS:
                self._SIMULATED_ACCOUNTS[self._current_pan]["blocked"] = True
            msg = "Card blocked after 3 incorrect PIN attempts"
            logger.warning("ATM %s: %s (PAN=%s)", self.atm_id, msg,
                           _mask_pan(self._current_pan or ""))
            return False, msg

        effective_pan = pan or self._current_pan
        if not effective_pan:
            return False, "No PAN available for PIN block construction"

        # ── Build ISO 9564 Format 0 PIN block ─────────────────────────────
        # This is purely for educational logging; the HSM verify_pin call
        # below uses the raw PIN for hash comparison (simulating decryption).
        if self._hsm:
            try:
                pin_block = self._hsm.generate_pin_block(pin, effective_pan, format="ISO-0")
                logger.debug("ISO-9564 F0 PIN block: %s (never transmitted in plaintext)",
                             pin_block.hex().upper())
            except Exception as exc:
                logger.debug("PIN block construction error (non-fatal): %s", exc)

        # ── HSM verification ───────────────────────────────────────────────
        # In a real system: send encrypted PIN block to issuer HSM over network.
        # Here: compare SHA-256 hash of entered PIN to stored hash.
        acct = self._SIMULATED_ACCOUNTS.get(effective_pan, {})
        stored_hash = acct.get("pin_hash", "")

        if self._hsm and stored_hash:
            verified = self._hsm.verify_pin(pin, stored_hash)
        else:
            # Pure fallback when HSM is unavailable
            verified = hashlib.sha256(pin.encode()).hexdigest() == stored_hash

        if verified:
            self._pin_verified = True
            self._pin_attempts = 0
            msg = "PIN verified successfully"
            logger.info("ATM %s: PIN OK for PAN %s", self.atm_id, _mask_pan(effective_pan))
            if self.verbose:
                print("  ✔ PIN accepted")
            return True, msg
        else:
            self._pin_attempts += 1
            remaining = 3 - self._pin_attempts
            msg = f"Incorrect PIN — {remaining} attempt(s) remaining"
            logger.warning("ATM %s: PIN FAIL attempt %d/3 for PAN %s",
                           self.atm_id, self._pin_attempts, _mask_pan(effective_pan))
            if self.verbose:
                print(f"  ✘ {msg}")
            return False, msg

    # ── EMV Mock Internals ────────────────────────────────────────────────────

    def _run_emv_select(self, aid: str = "A0000000031010") -> dict:
        """
        Simulate the EMV SELECT command (ISO 7816-4 INS=A4, P1=04).

        SELECT by AID is the first step in every EMV transaction.  The card
        responds with a File Control Information (FCI) template (tag 6F) that
        contains the Application Label (50), Application Priority Indicator (87),
        PDOL (9F38), and other data.

        Args:
            aid : Application Identifier hex string.
                  A0000000031010 = Visa Credit/Debit
                  A0000000041010 = MasterCard Credit

        Returns:
            dict with 'sw', 'aid', 'app_label', 'pdol', 'fci_raw'
        """
        # Mock FCI response — in real hardware this would be the raw APDU response
        app_labels = {
            "A0000000031010": "VISA CREDIT",
            "A0000000032010": "VISA DEBIT",
            "A0000000041010": "MASTERCARD",
            "A0000000043060": "MASTERCARD MAESTRO",
        }
        label = app_labels.get(aid, "UNKNOWN APP")
        logger.debug("EMV SELECT AID=%s → %s SW=9000", aid, label)
        return {
            "sw": "9000",
            "aid": aid,
            "app_label": label,
            # PDOL: 9F02 (amount, 6B) | 9F03 (cashback, 6B) | 9F1A (country, 2B) |
            #        95   (TVR, 5B)   | 5F2A (currency, 2B) | 9A   (date, 3B)
            "pdol": "9F0206 9F0306 9F1A02 9502 5F2A02 9A03",
            "fci_raw": "6F1A840E" + aid + "A508500A" + label[:10].encode().hex().upper(),
        }

    def _run_gpo(self, amount_cents: int, currency_code: int = 840) -> dict:
        """
        Simulate GET PROCESSING OPTIONS (GPO) — EMV Book 3, section 6.5.8.

        GPO is the command that starts the EMV transaction.  The terminal
        provides PDOL-requested data (amount, country, date, TTQ for
        contactless) and the card responds with:
          - AIP (Application Interchange Profile, 2 bytes): which EMV features
            the card supports (ODA, CVM, issuer authentication…)
          - AFL (Application File Locator): list of which records to read

        AIP bit meanings (from EMV Book 3 Table 31):
          b8 of byte 1 : SDA supported
          b7 of byte 1 : DDA supported
          b6 of byte 1 : Cardholder verification supported
          b5 of byte 1 : Terminal risk management to be performed
          b4 of byte 1 : Issuer authentication supported
          b3 of byte 1 : Reserved
          b2 of byte 1 : CDA supported

        Returns:
            dict with 'sw', 'aip', 'afl', 'aip_decoded'
        """
        # AIP = 0x7900 → SDA + DDA + CVM + terminal risk + issuer auth + CDA
        aip = 0x7900
        # AFL: SFI 1 record 1–3 (application data), SFI 2 record 1 (issuer data)
        afl = [(1, 1, 3, True), (2, 1, 1, False)]  # (sfi, first, last, data_auth)

        aip_decoded = {
            "sda":            bool(aip & 0x4000),
            "dda":            bool(aip & 0x2000),
            "cvm":            bool(aip & 0x1000),
            "terminal_risk":  bool(aip & 0x0800),
            "issuer_auth":    bool(aip & 0x0400),
            "cda":            bool(aip & 0x0100),
        }
        logger.debug("GPO: AIP=%04X AFL=%s", aip, afl)
        logger.debug("GPO: AIP decoded: %s", aip_decoded)
        return {"sw": "9000", "aip": aip, "afl": afl, "aip_decoded": aip_decoded}

    def _run_read_records(self, afl: list) -> dict:
        """
        Simulate READ RECORD for each entry in the AFL (Application File Locator).

        Each AFL entry specifies a Short File Identifier (SFI) and a range of
        record numbers.  The terminal reads every record in the range.  Records
        may contain: PAN (tag 5A), expiry (5F24), cardholder name (5F20),
        ATC (9F36), issuer public key (90), CDOL (8C), CVM list (8E), etc.

        Returns:
            dict mapping (sfi, record) tuples to their TLV data
        """
        records: dict = {}
        pan = self._current_pan or "4111111111111111"
        pan_bytes = bytes.fromhex(pan.ljust(20, "F")[:20])  # BCD-like
        for sfi, first, last, _ in afl:
            for rec_num in range(first, last + 1):
                key = (sfi, rec_num)
                # Construct mock TLV record
                records[key] = {
                    "5A":   pan_bytes.hex().upper(),       # PAN
                    "5F24": "2712",                         # Expiry YYMM = Dec 2027
                    "5F20": "475245454E574952452F544553",   # Cardholder: GREENWIRE/TEST
                    "9F36": f"{self._atc:04X}",            # Application Transaction Counter
                    "8C":   "9F02069F03069F1A0295055F2A029A039F0306",  # CDOL1
                    "8E":   "000000000000000042031E031F00",            # CVM list
                    "90":   os.urandom(128).hex().upper(),             # Issuer public key cert
                }
                logger.debug("READ RECORD SFI=%d REC=%d → tags %s", sfi, rec_num,
                             list(records[key].keys()))
        return records

    def _compute_arqc_mock(
        self,
        amount_cents: int,
        currency_code: int,
        pan: str,
        atc: int,
    ) -> str:
        """
        Compute a mock ARQC (Authorization Request Cryptogram).

        In EMV the card computes:
          ARQC = MAC_session_key(amount | other_amount | country | currency |
                                 date | txn_type | unpredictable_number | AIP | ATC)

        The session key is derived from the card issuer master key and the ATC
        using the EMV Common Session Key Derivation method (EMV Book 2, Ann A1.3).

        For lab simulation we use ThalesEmulator.generate_arqc() which implements
        a test-only KDF (SHA-256 based) followed by a 3DES-MAC.  This is NOT
        production-compliant but produces deterministic, verifiable output for
        testing purposes.

        Args:
            amount_cents  : Transaction amount in smallest currency unit.
            currency_code : ISO 4217 numeric currency code (840 = USD).
            pan           : Card PAN digits.
            atc           : Application Transaction Counter.

        Returns:
            Uppercase hex string of 8-byte ARQC.
        """
        # Build the transaction data to be MACed (simplified CDOL1 data)
        # Real CDOL1 includes many more fields from the terminal and card.
        txn_data = struct.pack(
            ">IH3sHH",
            amount_cents,          # 4 bytes: authorised amount
            currency_code,         # 2 bytes: transaction currency code
            datetime.now().strftime("%y%m%d").encode(),  # 3 bytes: transaction date
            atc,                   # 2 bytes: ATC
            random.randint(0, 0xFFFF),  # 2 bytes: unpredictable number
        )

        if self._hsm and self._master_key_label:
            try:
                # Derive session key and MAC using the HSM emulator
                arqc = self._hsm.generate_arqc(
                    self._master_key_label, pan, atc, txn_data
                )
                logger.debug("ARQC generated via HSM: %s", arqc)
                return arqc
            except Exception as exc:
                logger.warning("HSM ARQC generation failed (%s) — using fallback", exc)

        # Pure Python fallback: HMAC-SHA256 truncated to 8 bytes
        key_material = b"GREENWIRE_TEST_KEY_DO_NOT_USE_IN_PROD"
        arqc_bytes = hashlib.sha256(key_material + pan.encode() + txn_data).digest()[:8]
        arqc = arqc_bytes.hex().upper()
        logger.debug("ARQC generated via fallback HMAC: %s", arqc)
        return arqc

    def _mock_online_authorization(
        self,
        pan: str,
        amount: float,
        arqc: str,
        currency: str,
    ) -> dict:
        """
        Simulate sending an ISO 8583 authorization request to the acquiring host.

        In a production ATM this is an encrypted TCP connection (TLS 1.2+) to
        the acquirer's host, which then forwards to the card network, which routes
        to the issuer.  The round-trip typically takes 200–800ms.

        The response includes:
          - Response code (F39 in ISO 8583): "00" = approved
          - Authorization code (F38): 6-char code (stored in txn record)
          - ARPC: Issuer response cryptogram — the card verifies this before
                  committing the transaction (prevents replay attacks)
          - Issuer scripts (optional): commands to execute on the card ICC

        Returns:
            dict with keys: approved, response_code, auth_code, arpc, scripts
        """
        acct = self._SIMULATED_ACCOUNTS.get(pan, {})
        balance = acct.get("balance", 0.0)

        # Check available funds
        if amount > balance:
            logger.info("Authorization declined: insufficient funds (%.2f requested, %.2f available)",
                        amount, balance)
            return {
                "approved": False,
                "response_code": "51",   # ISO 8583 resp code 51 = Insufficient funds
                "auth_code": "",
                "arpc": "",
                "scripts": [],
            }

        # Generate a random 6-character authorization code
        auth_code = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))

        # Deduct from simulated balance
        if pan in self._SIMULATED_ACCOUNTS:
            self._SIMULATED_ACCOUNTS[pan]["balance"] -= amount

        # Generate ARPC (issuer response cryptogram) — card verifies this
        arpc = ""
        if self._hsm:
            try:
                arpc = self._hsm.generate_arpc(
                    self._master_key_label, pan, self._atc,
                    bytes.fromhex(arqc), b"\x3c\x00"  # issuer response code
                )
            except Exception as exc:
                logger.debug("ARPC generation skipped: %s", exc)

        logger.info("Authorization APPROVED: auth_code=%s arpc=%s", auth_code, arpc)
        return {
            "approved": True,
            "response_code": "00",
            "auth_code": auth_code,
            "arpc": arpc,
            "scripts": [],  # no issuer scripts in this simulation
        }

    # ── Transactions ─────────────────────────────────────────────────────────

    def process_withdrawal(
        self,
        amount: float,
        currency: str = "USD",
    ) -> dict:
        """
        Execute a full EMV cash withdrawal flow.

        EMV Contact Withdrawal Sequence (EMV Books 1-4):
          1. SELECT PPSE                — discover applications on card
          2. SELECT AID                 — choose Visa/MC application
          3. GET PROCESSING OPTIONS     — start transaction, get AIP + AFL
          4. READ RECORD (each AFL)     — read cardholder/card data records
          5. OFFLINE DATA AUTH          — verify card authenticity (SDA/DDA)
          6. PROCESSING RESTRICTIONS    — expiry, version, AUC checks
          7. CARDHOLDER VERIFICATION    — PIN (online/offline) or signature
          8. TERMINAL RISK MANAGEMENT   — floor limit, velocity, random online
          9. TERMINAL ACTION ANALYSIS   — decide ARQC/TC/AAC
          10. GENERATE AC (1st)         — get ARQC from card
          11. ONLINE AUTHORIZATION      — send ARQC to issuer, receive ARPC
          12. ISSUER SCRIPT PROCESSING  — execute any scripts from issuer
          13. GENERATE AC (2nd)         — get TC (approved) or AAC (declined)
          14. DISPENSE CASH             — only if TC received

        This simulation compresses steps 1–10 into mock calls for lab use.

        Args:
            amount   : Amount to withdraw in major currency units (e.g. 100.00).
            currency : ISO 4217 currency code (e.g. "USD").

        Returns:
            ATMTransaction as a dict with all fields populated.
        """
        if not self._card_inserted:
            return {"status": "error", "error": "No card inserted"}
        if not self._pin_verified:
            return {"status": "error", "error": "PIN not verified"}
        if self._card_blocked:
            return {"status": "error", "error": "Card blocked"}

        currency_map = {"USD": 840, "EUR": 978, "GBP": 826, "JPY": 392}
        currency_code = currency_map.get(currency.upper(), 840)
        amount_cents = int(amount * 100)

        txn = ATMTransaction(
            txn_id=_generate_txn_id(),
            pan_masked=_mask_pan(self._current_pan or ""),
            amount=amount,
            currency=currency,
            txn_type="withdrawal",
            timestamp=datetime.now().isoformat(),
            atc=self._atc,
        )

        logger.info("Beginning withdrawal: txn_id=%s amount=%.2f %s ATC=%d",
                    txn.txn_id, amount, currency, self._atc)

        # ── Steps 1–2: SELECT ─────────────────────────────────────────────
        if self.verbose:
            print(f"  → SELECT AID (EMV application selection)...")
        fci = self._run_emv_select()

        # ── Steps 3–4: GPO + READ RECORD ──────────────────────────────────
        if self.verbose:
            print(f"  → GET PROCESSING OPTIONS (start transaction)...")
        gpo = self._run_gpo(amount_cents, currency_code)
        records = self._run_read_records(gpo["afl"])

        # ── Steps 5–9: Auth decisions (simplified) ────────────────────────
        # In full EMV: offline data auth, CVM list processing, risk management
        # all happen here.  For the ATM emulator we go online unconditionally.
        if self.verbose:
            print(f"  → Processing restrictions & terminal risk management...")

        # ── Step 10: GENERATE AC — request ARQC ───────────────────────────
        if self.verbose:
            print(f"  → GENERATE AC (requesting ARQC from card)...")
        self._atc += 1  # increment ATC (card does this internally)
        arqc = self._compute_arqc_mock(amount_cents, currency_code,
                                       self._current_pan or "", self._atc)
        txn.arqc = arqc
        txn.atc = self._atc

        # ── Step 11: Online authorization ─────────────────────────────────
        if self.verbose:
            print(f"  → Online authorization (sending ARQC to host)...")
        time.sleep(0.1)  # simulate network latency
        auth = self._mock_online_authorization(
            self._current_pan or "", amount, arqc, currency
        )
        txn.arpc = auth.get("arpc", "")

        # ── Steps 12–13: GENERATE AC 2nd (TC or AAC) ──────────────────────
        if auth["approved"]:
            txn.status = "approved"
            txn.approval_code = auth["auth_code"]
            txn.error = ""
            if self.verbose:
                print(f"  ✔ APPROVED — auth code: {txn.approval_code}")
            logger.info("Withdrawal approved: txn_id=%s auth=%s", txn.txn_id, txn.approval_code)
        else:
            txn.status = "declined"
            txn.error = f"Response code: {auth['response_code']}"
            if self.verbose:
                print(f"  ✘ DECLINED — response code: {auth['response_code']}")
            logger.warning("Withdrawal declined: txn_id=%s rc=%s", txn.txn_id, auth["response_code"])

        self._transaction_log.append(txn)
        return txn.__dict__

    def process_balance_inquiry(self) -> dict:
        """
        Query the cardholder's account balance.

        In a real ATM this involves an ISO 8583 message type 0100 (authorization
        request) with a balance inquiry processing code (320000).  The issuer
        responds with the available and ledger balances in fields F54/F54A.

        Returns:
            dict with: available_balance, ledger_balance, currency, txn_id, status
        """
        if not self._card_inserted:
            return {"status": "error", "error": "No card inserted"}
        if not self._pin_verified:
            return {"status": "error", "error": "PIN not verified"}

        pan = self._current_pan or ""
        acct = self._SIMULATED_ACCOUNTS.get(pan, {})
        balance = acct.get("balance", 0.0)

        txn = ATMTransaction(
            txn_id=_generate_txn_id(),
            pan_masked=_mask_pan(pan),
            amount=0.0,
            currency="USD",
            txn_type="balance_inquiry",
            timestamp=datetime.now().isoformat(),
            atc=self._atc,
            status="approved",
            approval_code="BAL" + _generate_txn_id()[:3],
        )
        self._transaction_log.append(txn)

        result = {
            "txn_id":            txn.txn_id,
            "available_balance": balance,
            "ledger_balance":    balance,
            "currency":          "USD",
            "status":            "approved",
        }
        logger.info("Balance inquiry: PAN=%s balance=%.2f", _mask_pan(pan), balance)
        if self.verbose:
            print(f"  ✔ Balance: ${balance:,.2f} USD")
        return result

    def process_deposit(self, amount: float) -> dict:
        """
        Accept a cash/cheque deposit (bill acceptor / cheque scanner simulation).

        Real ATMs validate deposited bills via a currency discrimination module
        and hold cheques for clearing.  This simulation simply credits the account
        immediately.

        Args:
            amount : Amount being deposited in major currency units.

        Returns:
            dict with: txn_id, new_balance, status, approval_code
        """
        if not self._card_inserted:
            return {"status": "error", "error": "No card inserted"}
        if not self._pin_verified:
            return {"status": "error", "error": "PIN not verified"}
        if amount <= 0:
            return {"status": "error", "error": "Deposit amount must be positive"}

        pan = self._current_pan or ""
        if pan in self._SIMULATED_ACCOUNTS:
            self._SIMULATED_ACCOUNTS[pan]["balance"] += amount

        new_balance = self._SIMULATED_ACCOUNTS.get(pan, {}).get("balance", amount)
        auth_code = "DEP" + _generate_txn_id()[:5]

        txn = ATMTransaction(
            txn_id=_generate_txn_id(),
            pan_masked=_mask_pan(pan),
            amount=amount,
            currency="USD",
            txn_type="deposit",
            timestamp=datetime.now().isoformat(),
            atc=self._atc,
            status="approved",
            approval_code=auth_code,
        )
        self._transaction_log.append(txn)
        logger.info("Deposit of %.2f accepted: PAN=%s new_balance=%.2f", amount, _mask_pan(pan), new_balance)
        if self.verbose:
            print(f"  ✔ Deposit accepted: ${amount:,.2f}.  New balance: ${new_balance:,.2f}")
        return {"txn_id": txn.txn_id, "new_balance": new_balance,
                "status": "approved", "approval_code": auth_code}

    # ── Card Ejection & Session Control ──────────────────────────────────────

    def eject_card(self) -> str:
        """
        Eject the card and clear sensitive session state.

        In a real ATM the card motor physically moves the card to the exit slot.
        Critically, all sensitive in-memory data (PAN, PIN state) must be zeroed.

        Returns:
            User-facing message string.
        """
        pan_masked = _mask_pan(self._current_pan or "")
        self.reset()
        msg = f"Card {pan_masked} ejected — please take your card"
        logger.info("ATM %s: %s", self.atm_id, msg)
        if self.verbose:
            print(f"\n  {msg}\n{'─' * 50}")
        return msg

    def reset(self) -> None:
        """
        Clear all card and PIN state without losing the transaction log.

        Called after card ejection or a session timeout.  Security note: in
        production ATMs, sensitive memory regions are zeroed using secure_zero().
        """
        self._current_pan = None
        self._card_profile = None
        self._card_inserted = False
        self._pin_verified = False
        self._pin_attempts = 0
        self._card_blocked = False
        logger.debug("ATM %s: session state cleared", self.atm_id)

    def get_transaction_log(self) -> List[dict]:
        """
        Return all transactions recorded during this ATM session.

        Returns:
            List of dicts (one per ATMTransaction) sorted by timestamp.
        """
        return [t.__dict__ for t in self._transaction_log]

    # ── Receipt Printing ─────────────────────────────────────────────────────

    def print_receipt(self, txn: dict) -> str:
        """
        Generate a formatted ASCII receipt for a transaction.

        Receipt format follows EMV Book 4 / scheme receipt requirements:
          - Merchant name and terminal ID
          - Masked PAN (first 6, last 4 per PCI-DSS)
          - Amount, currency, date/time
          - Authorization code and transaction reference
          - Status line
          - ATC and ARQC snippet (for lab debugging)

        Args:
            txn : Transaction dict as returned by process_withdrawal() etc.

        Returns:
            Multi-line ASCII receipt string.
        """
        sep = "─" * 38
        lines = [
            f"\n{'─' * 38}",
            f"  GREENWIRE BANK ATM — {self.atm_id}",
            f"  {self.location}",
            sep,
            f"  Date  : {txn.get('timestamp', '')[:19].replace('T', ' ')}",
            f"  Type  : {txn.get('txn_type', 'TRANSACTION').upper()}",
            sep,
            f"  Card  : {txn.get('pan_masked', 'N/A')}",
            f"  Amount: {txn.get('currency', 'USD')} {txn.get('amount', 0.0):>12.2f}",
            sep,
            f"  Status: {txn.get('status', '?').upper()}",
        ]
        if txn.get("approval_code"):
            lines.append(f"  Auth  : {txn['approval_code']}")
        if txn.get("txn_id"):
            lines.append(f"  Ref   : {txn['txn_id']}")
        # Lab-specific debug lines
        if txn.get("arqc"):
            lines.append(f"  ATC   : {txn.get('atc', 0):04X}")
            lines.append(f"  ARQC  : {txn['arqc'][:16]}…")
        lines.append(sep)
        lines.append("  Thank you for using GREENWIRE ATM")
        lines.append(f"{'─' * 38}\n")
        receipt = "\n".join(lines)
        if self.verbose:
            print(receipt)
        return receipt


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE DEMO
# ─────────────────────────────────────────────────────────────────────────────

def demo_atm() -> None:
    """
    Demonstrate the ATM emulator with a complete session: welcome → card →
    PIN → balance → withdrawal → deposit → receipt → eject.

    Run directly:  python -m modules.enhanced_atm_emulator
    """
    print("\n" + "=" * 60)
    print("  GREENWIRE Enhanced ATM Emulator — Demo Session")
    print("=" * 60)

    atm = EnhancedATMEmulator(
        atm_id="ATM_DEMO_01",
        location="GREENWIRE Lab — Demo Bench",
        bank_code="001",
        verbose=True,
    )

    # 1. Welcome
    atm.display_welcome_screen()

    # 2. Insert card
    ok, msg, card_info = atm.insert_card(pan="4111111111111111")
    print(f"\nCard info: scheme={card_info.get('scheme')}, "
          f"bank={card_info.get('bank')}, luhn={card_info.get('luhn_ok')}")

    if not ok:
        print(f"Card rejected: {msg}")
        return

    # 3. Verify PIN
    print("\n--- Testing wrong PIN ---")
    atm.verify_pin("0000")

    print("\n--- Testing correct PIN ---")
    ok, msg = atm.verify_pin("1234")
    if not ok:
        print(f"PIN failed: {msg}")
        return

    # 4. Balance inquiry
    print("\n--- Balance Inquiry ---")
    bal = atm.process_balance_inquiry()
    print(f"Available balance: ${bal.get('available_balance', 0):,.2f}")

    # 5. Withdrawal
    print("\n--- Withdrawal $100 ---")
    txn = atm.process_withdrawal(100.00, "USD")
    atm.print_receipt(txn)

    # 6. Deposit
    print("\n--- Deposit $50 ---")
    dep = atm.process_deposit(50.00)

    # 7. Full transaction log
    print("\n--- Transaction Log ---")
    for t in atm.get_transaction_log():
        print(f"  {t['txn_type']:18s}  {t['status']:8s}  ${t['amount']:8.2f}  ref={t['txn_id']}")

    # 8. Eject
    atm.eject_card()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    demo_atm()
