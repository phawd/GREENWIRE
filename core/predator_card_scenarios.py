"""
GREENWIRE Predator Card Scenarios
==================================
"Predator cards" (also called aggressor cards, stress cards, or test instruments)
are virtual cards loaded with specific behavioural profiles designed to exercise
every code path inside a merchant terminal, ATM, or payment gateway.

WHY "PREDATOR"?
───────────────
The name comes from the VISA/MC certification lab world.  A "predator card" is a
card that *hunts* for bugs in terminal software by presenting edge-case data.  It
is the standard industry tool used to certify terminals before deployment.

Think of it as a test harness shaped like a payment card:
  • The card "knows" what response to give for each transaction.
  • The tester controls which scenario is loaded.
  • The terminal under test never knows it isn't talking to a real card.

IN THIS FRAMEWORK
─────────────────
Each scenario is a `PredatorScenario` dataclass that describes:
  - What EMV data to present (PAN, AIP, AFL, records)
  - How to respond to GENERATE AC (ARQC / TC / AAC)
  - What status words to return for each APDU command
  - Any timing anomalies or retry logic to exercise

Scenarios are designed to test:

  CATEGORY A — NORMAL FLOWS
    A1  Standard contactless Visa credit (online approval)
    A2  Standard contactless Mastercard debit (online approval)
    A3  Standard contact chip (dip) credit
    A4  Offline approved — returns TC without going online
    A5  PIN-verified contactless (online PIN)

  CATEGORY B — DECLINE / ERROR FLOWS
    B1  Hard decline — card returns AAC immediately
    B2  Issuer authentication failure — bad ARQC signature
    B3  Card blocked — 6983 on any VERIFY or GENERATE AC
    B4  Expired card — expiry date in the past
    B5  Service code 007 — card issuer call required (referral)

  CATEGORY C — EDGE CASES (floor / velocity / limits)
    C1  Amount exactly at terminal floor limit
    C2  Amount one cent above floor limit (forces online)
    C3  Amount one cent below floor limit (offline OK)
    C4  High-value transaction ($9,999.00)
    C5  Zero-amount — often used for balance inquiry

  CATEGORY D — CVM (Cardholder Verification Method) stress
    D1  CVM list: No-CVM only — no PIN, no signature required
    D2  CVM list: Signature preferred
    D3  CVM list: Online PIN required — terminal must prompt
    D4  CVM list: Offline plain PIN — PIN sent unencrypted to card
    D5  CVM list: Consumer Device CVM (CDCVM — phone authenticates)

  CATEGORY E — AID / APPLICATION SELECTION stress
    E1  Multiple AID response — PPSE returns Visa + MC simultaneously
    E2  Partial AID match — terminal must handle AID length mismatch
    E3  No AID match — card returns 6A82 on every SELECT
    E4  AID priority conflict — two equal-priority applications

  CATEGORY F — CRYPTOGRAM / CRYPTO stress
    F1  ATC rollback — ATC lower than last seen (replay attack test)
    F2  ATC jump — ATC 1000 higher than expected
    F3  Weak unpredictable number — UN = 00000000
    F4  ARQC with wrong length (7 bytes instead of 8)
    F5  All-zeros cryptogram response

  CATEGORY G — FALLBACK / COMPATIBILITY
    G1  Mag-stripe fallback trigger (chip fail simulation)
    G2  Contactless ceiling exceeded — force contact
    G3  Offline data auth failure — SDA signature mismatch

USAGE
─────
    from core.predator_card_scenarios import load_scenario, list_scenarios

    # List all available scenarios
    for s in list_scenarios():
        print(s.id, s.name)

    # Load a scenario by ID
    card = load_scenario("B1")   # Hard decline

    # Use with HCEEmulator
    from core.hce_emulator import HCEEmulator
    emu = HCEEmulator(scenario=card)
    emu.start()                   # TCP server ready for terminal tap

    # Use with POS terminal tester
    from modules.merchant_card_tester import MerchantCardTester
    tester = MerchantCardTester()
    result = tester.run_scenario(card)
    print(result.outcome)

ENVIRONMENT NOTES
─────────────────
All PANs in this file are either:
  (a) EMVCo published test PANs, or
  (b) Synthetic PANs in ranges reserved by Visa/MC for testing
      (Visa: 4895370xxxxx, MC MDES: 5351100xxxxx)
No real cardholder data is used anywhere.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# ENUMERATIONS
# ──────────────────────────────────────────────────────────────────────────────

class CryptogramType(str, Enum):
    """What GENERATE AC should return.

    AAC  — Application Authentication Cryptogram.  Card refuses.  Terminal MUST
           decline.  Use when testing that a terminal correctly handles a card
           that has decided offline decline.

    TC   — Transaction Certificate.  Card approves offline.  Terminal SHOULD
           complete without going online (if floor limit allows).

    ARQC — Authorisation Request Cryptogram.  Card requests online auth.
           Terminal MUST send to the acquirer/issuer for approval.  This is the
           normal flow for contactless.
    """
    AAC  = "AAC"    # Decline
    TC   = "TC"     # Offline approve
    ARQC = "ARQC"   # Online request


class CVMPreference(str, Enum):
    """Which Cardholder Verification Method the scenario prefers.

    The CVM list is a prioritised list of methods encoded in the card record.
    The terminal walks the list top-to-bottom and picks the first method it
    can support.  Testing each value exercises different terminal code paths.
    """
    NO_CVM       = "NO_CVM"        # No verification required at all
    SIGNATURE    = "SIGNATURE"     # Paper receipt signature
    ONLINE_PIN   = "ONLINE_PIN"    # PIN sent online encrypted to issuer
    OFFLINE_PLAIN_PIN = "OFFLINE_PLAIN_PIN"  # PIN sent to card in plaintext
    CDCVM        = "CDCVM"         # Consumer Device CVM (phone auth)


class SchemeType(str, Enum):
    """Payment network for the predator card scenario."""
    VISA        = "visa"
    MASTERCARD  = "mastercard"
    AMEX        = "amex"
    DISCOVER    = "discover"


# ──────────────────────────────────────────────────────────────────────────────
# CORE DATA STRUCTURES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class APDUOverride:
    """
    Override the default response for a specific APDU command.

    Used to inject bad status words, wrong data lengths, or unusual
    responses that stress-test specific terminal code paths.

    The `match_ins` byte selects which APDU instruction to intercept:
      0xA4 = SELECT
      0xA8 = GET PROCESSING OPTIONS (GPO)
      0xB2 = READ RECORD
      0xAE = GENERATE AC
      0x20 = VERIFY (PIN)
      0xCA = GET DATA
    """
    match_ins: int                   # INS byte to intercept
    match_p1: Optional[int] = None   # Optional P1 filter
    response_sw: int = 0x9000        # Status word to return (e.g. 0x6983)
    response_data: Optional[bytes] = None  # Data to inject, or None for default
    note: str = ""                   # Human-readable explanation


@dataclass
class PredatorScenario:
    """
    A complete predator card scenario definition.

    This dataclass carries everything the HCE emulator needs to impersonate
    a card with specific behaviour — the PAN, the EMV data records, how to
    respond to GENERATE AC, and any APDU-level overrides.

    FIELDS
    ──────
    id          : Short code like "A1", "B2", etc.
    name        : Human-readable scenario name
    description : Longer explanation of what this scenario tests
    category    : Letter category (A=normal, B=decline, C=edge, ...)

    -- Card identity --
    scheme      : Payment network
    pan         : Test PAN (always synthetic or EMVCo-published)
    pan_seq     : PAN sequence number, usually "01"
    expiry_mmyy : Expiry in MMYY format, e.g. "1228"
    aid         : AID hex string for the selected application

    -- EMV behaviour flags --
    cryptogram_type  : What GENERATE AC should return (ARQC/TC/AAC)
    cvm_preference   : Which CVM method the card prefers
    aip_bytes        : 2-byte AIP as hex (controls terminal capabilities)
    go_online_force  : If True, AIP bit forces every transaction online
    offline_approved : If True, scenario returns TC without going online
    force_decline    : If True, scenario always returns AAC (decline)

    -- Advanced stress fields --
    atc_override       : Force a specific ATC value (for replay/rollback tests)
    cryptogram_override: Inject a fixed bad cryptogram (for crypto-fail tests)
    apdu_overrides     : List of APDU-level response overrides
    floor_limit_cents  : Floor limit to load into terminal data for this test
    timing_delay_ms    : Inject artificial delay before responding (timeout test)
    expected_outcome   : What a correctly-implemented terminal SHOULD do
    tags               : Free-form labels for filtering (e.g. ["visa", "decline"])
    """
    # Identification
    id: str
    name: str
    description: str
    category: str

    # Card identity
    scheme: SchemeType
    pan: str
    pan_seq: str = "01"
    expiry_mmyy: str = "1228"
    aid: str = "A0000000031010"       # Visa Credit default

    # EMV behaviour
    cryptogram_type: CryptogramType = CryptogramType.ARQC
    cvm_preference: CVMPreference = CVMPreference.NO_CVM
    aip_bytes: str = "5800"           # 0x5800 = SDA+CVM+TRMI+IA supported
    go_online_force: bool = True

    # Advanced
    atc_override: Optional[int] = None
    cryptogram_override: Optional[str] = None   # 16-char hex = 8 bytes
    apdu_overrides: List[APDUOverride] = field(default_factory=list)
    floor_limit_cents: int = 5000               # $50.00 default
    timing_delay_ms: int = 0
    expected_outcome: str = "Online approval"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Serialise to a plain dict (for JSON config files / ADB push)."""
        return {
            "id": self.id,
            "name": self.name,
            "scheme": self.scheme.value,
            "pan": self.pan,
            "pan_seq": self.pan_seq,
            "expiry_mmyy": self.expiry_mmyy,
            "aid": self.aid,
            "cryptogram_type": self.cryptogram_type.value,
            "cvm_preference": self.cvm_preference.value,
            "aip_bytes": self.aip_bytes,
            "go_online_force": self.go_online_force,
            "atc_override": self.atc_override,
            "cryptogram_override": self.cryptogram_override,
            "floor_limit_cents": self.floor_limit_cents,
            "timing_delay_ms": self.timing_delay_ms,
            "expected_outcome": self.expected_outcome,
            "tags": self.tags,
        }


# ──────────────────────────────────────────────────────────────────────────────
# SCENARIO LIBRARY
# ──────────────────────────────────────────────────────────────────────────────
# All PANs are either EMVCo test PANs or PANs in Visa/MC token ranges.
# None are real cardholder PANs.

_SCENARIOS: Dict[str, PredatorScenario] = {}


def _reg(s: PredatorScenario) -> PredatorScenario:
    """Register a scenario in the library and return it."""
    _SCENARIOS[s.id] = s
    logger.debug("Registered predator scenario: %s – %s", s.id, s.name)
    return s


# ─── CATEGORY A: NORMAL FLOWS ─────────────────────────────────────────────────

_reg(PredatorScenario(
    id="A1", category="A",
    name="Standard Visa Contactless — Online Approval",
    description=(
        "The most common scenario in the field.  Presents a Visa Credit card that "
        "requests online authorisation.  Tests the full happy path: PPSE → AID "
        "SELECT → GPO → READ RECORD → GENERATE AC (ARQC) → online auth → TC.  "
        "A correctly implemented terminal MUST send the ARQC to its host and return "
        "an approval to the cardholder."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000001",   # Visa VTS token test range
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",          # SDA + CVM list + TRMI + Issuer Auth
    go_online_force=True,
    expected_outcome="Online approval — 00 response code",
    tags=["visa", "contactless", "normal", "arqc"],
))

_reg(PredatorScenario(
    id="A2", category="A",
    name="Standard Mastercard Contactless — Online Approval",
    description=(
        "MC M/Chip Advance contactless transaction.  Exercises the Mastercard "
        "kernel (Kernel 2 / MChip) path.  AIP = 5E00 sets Mastercard-specific bits: "
        "SDA, cardholder verification, TRMI, issuer authentication, and CDA.  "
        "Terminal must handle MC-specific PDOL fields correctly."
    ),
    scheme=SchemeType.MASTERCARD,
    pan="5351100000000001",   # MC MDES token test range
    expiry_mmyy="1228",
    aid="A0000000041010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5E00",
    go_online_force=True,
    expected_outcome="Online approval — 00 response code",
    tags=["mastercard", "contactless", "normal", "arqc"],
))

_reg(PredatorScenario(
    id="A3", category="A",
    name="Contact Chip — Dip (ISO 7816)",
    description=(
        "Contact chip (dip) transaction.  No contactless interface active.  "
        "Tests EMV Book 3 flow at a terminal that requires physical insertion.  "
        "ARQC computed via contact interface.  CVM = no-CVM (card-not-present "
        "equivalent for lab testing without a physical reader)."
    ),
    scheme=SchemeType.VISA,
    pan="4111111111111111",   # Classic EMVCo Visa test PAN
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.SIGNATURE,
    aip_bytes="5800",
    go_online_force=True,
    expected_outcome="Online approval with signature CVM",
    tags=["visa", "contact", "normal", "signature"],
))

_reg(PredatorScenario(
    id="A4", category="A",
    name="Offline Approved — TC returned without online",
    description=(
        "Card returns Transaction Certificate (TC) directly from GENERATE AC.  "
        "This means the card has approved the transaction offline — no online auth "
        "needed.  This is legal when the terminal is operating below its floor limit "
        "and the card supports offline authorisation.  "
        "Test: terminal SHOULD complete without contacting the host."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000002",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.TC,    # ← TC = offline approved
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    go_online_force=False,
    floor_limit_cents=10000,              # $100 — keep test below this
    expected_outcome="Offline approval — TC — no host contact needed",
    tags=["visa", "offline", "tc", "floor-limit"],
))

_reg(PredatorScenario(
    id="A5", category="A",
    name="Online PIN Verified — Contactless PIN",
    description=(
        "CVM = Online PIN.  Terminal must prompt for PIN, encrypt it using a Zone "
        "PIN Key (ZPK) and send the PIN block to the issuer.  "
        "Tests: PIN prompt UI, ISO 9564 Format 0 PIN block construction, PIN block "
        "transmission in auth request, issuer response handling."
    ),
    scheme=SchemeType.MASTERCARD,
    pan="5351100000000002",
    expiry_mmyy="1228",
    aid="A0000000041010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.ONLINE_PIN,  # ← forces terminal PIN prompt
    aip_bytes="5E00",
    go_online_force=True,
    expected_outcome="Online approval with PIN verification",
    tags=["mastercard", "pin", "online-pin", "cvm"],
))

# ─── CATEGORY B: DECLINE / ERROR FLOWS ───────────────────────────────────────

_reg(PredatorScenario(
    id="B1", category="B",
    name="Hard Decline — Card returns AAC",
    description=(
        "Card returns Application Authentication Cryptogram (AAC) from GENERATE AC.  "
        "AAC means the card itself has decided to decline — the terminal MUST NOT "
        "send this to the host for authorisation; it MUST display 'Declined'.  "
        "Tests: terminal correctly distinguishes AAC from ARQC in the CID byte "
        "(bit 7-6 of first byte of response: 00=AAC, 01=TC, 10=ARQC)."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000010",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.AAC,   # ← hard decline
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    go_online_force=False,
    expected_outcome="Declined — terminal shows 'Card Declined'",
    tags=["visa", "decline", "aac"],
))

_reg(PredatorScenario(
    id="B2", category="B",
    name="Issuer Authentication Failure — Bad ARQC",
    description=(
        "Card returns ARQC but the cryptogram is deliberately wrong (all zeros).  "
        "After online auth, the issuer's EXTERNAL AUTHENTICATE will fail.  "
        "Tests: terminal/gateway correctly handles issuer auth failure response "
        "(auth response code = 'Z3' or similar).  Terminal MUST reverse/void."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000011",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    go_online_force=True,
    cryptogram_override="0000000000000000",   # ← bad ARQC — will fail issuer auth
    expected_outcome="Online decline due to ARQC verification failure",
    tags=["visa", "crypto-fail", "arqc-bad", "issuer-auth"],
))

_reg(PredatorScenario(
    id="B3", category="B",
    name="Card Blocked — 6983 on GENERATE AC",
    description=(
        "Card returns SW 6983 (Authentication Blocked) on GENERATE AC.  "
        "Status word 0x6983 means the card's retry counter is exhausted and the "
        "card has blocked itself.  Tests: terminal recognises 6983 and displays "
        "an appropriate 'Card Blocked — Contact Your Bank' message."
    ),
    scheme=SchemeType.MASTERCARD,
    pan="5351100000000010",
    expiry_mmyy="1228",
    aid="A0000000041010",
    cryptogram_type=CryptogramType.AAC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5E00",
    apdu_overrides=[
        APDUOverride(
            match_ins=0xAE,                  # GENERATE AC
            response_sw=0x6983,              # Authentication Blocked
            response_data=b"",
            note="Card blocked — simulates PIN retry exhaustion",
        )
    ],
    expected_outcome="Error — 'Card blocked, contact your bank'",
    tags=["mastercard", "blocked", "6983", "error"],
))

_reg(PredatorScenario(
    id="B4", category="B",
    name="Expired Card",
    description=(
        "Card presents an expiry date in the past (12/20).  "
        "A correct terminal MUST check expiry during Processing Restrictions and "
        "set TVR bit 3 of byte 1 (Expired application).  Terminal MUST decline "
        "without sending to the host — this is an offline decision."
    ),
    scheme=SchemeType.VISA,
    pan="4111111111111111",
    pan_seq="01",
    expiry_mmyy="1220",                  # ← January 2020 — clearly expired
    aid="A0000000031010",
    cryptogram_type=CryptogramType.AAC,   # Even if terminal asks, card declines
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    go_online_force=False,
    expected_outcome="Offline decline — expired card — TVR byte1 bit3 set",
    tags=["visa", "expired", "tvr", "processing-restrictions"],
))

_reg(PredatorScenario(
    id="B5", category="B",
    name="Referral — Issuer Call Required",
    description=(
        "Online auth returns response code '01' (Refer to Issuer).  "
        "Tests: terminal correctly handles referral — displays 'Call Bank for Auth', "
        "allows manual keyed override with authorisation code.  "
        "This is important for high-value transactions at counters."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000012",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.SIGNATURE,
    aip_bytes="5800",
    go_online_force=True,
    expected_outcome="Referral — terminal must call bank for voice auth",
    tags=["visa", "referral", "voice-auth"],
))

# ─── CATEGORY C: EDGE CASES — FLOOR / VELOCITY / LIMITS ──────────────────────

_reg(PredatorScenario(
    id="C1", category="C",
    name="Amount exactly at floor limit ($50.00)",
    description=(
        "Transaction amount equals the terminal floor limit exactly.  "
        "The floor limit check is '>' not '>=' in EMV Book 3.  Amount AT the "
        "floor limit should trigger offline processing.  Tests the boundary "
        "condition in the terminal's Terminal Risk Management code."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000003",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.TC,    # offline OK at floor limit
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    go_online_force=False,
    floor_limit_cents=5000,              # $50.00
    expected_outcome="Offline approval — amount == floor limit (boundary condition)",
    tags=["visa", "floor-limit", "boundary", "offline"],
))

_reg(PredatorScenario(
    id="C2", category="C",
    name="One cent above floor limit — forces online",
    description=(
        "Amount = floor limit + 1 cent ($50.01 with $50.00 floor).  "
        "Terminal MUST go online.  Tests: floor limit comparison is strict > "
        "and not >=.  Terminal MUST send ARQC to host even if card would approve offline."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000003",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC, # card requests online
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    go_online_force=True,
    floor_limit_cents=5000,
    expected_outcome="Online — amount exceeds floor limit — ARQC to host",
    tags=["visa", "floor-limit", "boundary", "online", "arqc"],
))

_reg(PredatorScenario(
    id="C3", category="C",
    name="One cent below floor limit — offline approved",
    description=(
        "Amount = floor limit - 1 cent ($49.99 with $50.00 floor).  "
        "Terminal SHOULD allow offline processing.  Card returns TC.  "
        "Tests: terminal does not escalate to online unnecessarily — "
        "important for performance testing of contactless terminals."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000003",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.TC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    go_online_force=False,
    floor_limit_cents=5000,
    expected_outcome="Offline approval — amount below floor limit",
    tags=["visa", "floor-limit", "offline", "tc"],
))

_reg(PredatorScenario(
    id="C4", category="C",
    name="High value — $9,999.00",
    description=(
        "Large transaction amount.  Tests amount field overflow handling in "
        "terminal software (amount is encoded as 6-byte BCD in CDOL1).  "
        "Also tests that terminal applies correct CVM (usually PIN above certain "
        "thresholds) and that the host auth system handles large amounts."
    ),
    scheme=SchemeType.MASTERCARD,
    pan="5351100000000003",
    expiry_mmyy="1228",
    aid="A0000000041010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.ONLINE_PIN,  # high value → PIN
    aip_bytes="5E00",
    go_online_force=True,
    floor_limit_cents=5000,
    expected_outcome="Online approval with PIN for high-value transaction",
    tags=["mastercard", "high-value", "pin", "amount-encoding"],
))

_reg(PredatorScenario(
    id="C5", category="C",
    name="Zero Amount — Balance Inquiry",
    description=(
        "Amount = $0.00.  Used to simulate a balance inquiry tap.  "
        "Some terminals reject zero-amount transactions entirely; others handle "
        "them as a special flow.  Tests: terminal correctly handles zero in "
        "6-byte BCD amount field (000000000000) and does not divide by zero."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000004",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    go_online_force=True,
    floor_limit_cents=0,
    expected_outcome="Terminal handles zero-amount gracefully",
    tags=["visa", "zero-amount", "balance-inquiry", "edge-case"],
))

# ─── CATEGORY D: CVM STRESS ───────────────────────────────────────────────────

_reg(PredatorScenario(
    id="D1", category="D",
    name="No-CVM Only — No cardholder verification",
    description=(
        "CVM list contains only 'No CVM Required'.  Terminal must NOT prompt for "
        "PIN or signature.  Tests: terminal respects card's CVM list and does not "
        "add its own PIN requirement.  This is the standard flow for low-value "
        "contactless (e.g. transit, coffee shops)."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000005",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    expected_outcome="Approved — no PIN or signature prompted",
    tags=["visa", "no-cvm", "contactless", "low-value"],
))

_reg(PredatorScenario(
    id="D2", category="D",
    name="Signature Preferred CVM",
    description=(
        "CVM list: signature preferred.  Terminal must print receipt and wait for "
        "signature.  Tests: terminal signature workflow, receipt printer, and "
        "that the transaction is held open until staff confirms signature match."
    ),
    scheme=SchemeType.VISA,
    pan="4111111111111111",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.SIGNATURE,
    aip_bytes="5800",
    expected_outcome="Approved with signature — receipt printed",
    tags=["visa", "signature", "cvm", "receipt"],
))

_reg(PredatorScenario(
    id="D3", category="D",
    name="Online PIN Required",
    description=(
        "CVM = Online PIN only.  Terminal MUST encrypt PIN and include it in the "
        "auth request.  No fallback to signature.  Tests: PIN pad integration, "
        "ISO 9564 Format 0 PIN block, ZPK key injection, pin block in DE52."
    ),
    scheme=SchemeType.MASTERCARD,
    pan="5351100000000004",
    expiry_mmyy="1228",
    aid="A0000000041010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.ONLINE_PIN,
    aip_bytes="5E00",
    expected_outcome="Approved with online PIN verification",
    tags=["mastercard", "online-pin", "pin-block", "iso9564"],
))

_reg(PredatorScenario(
    id="D4", category="D",
    name="Offline Plain PIN (Unencrypted PIN to Card)",
    description=(
        "CVM = Offline Plain PIN.  Terminal sends PIN directly to the card "
        "via VERIFY command without encryption.  The card checks it internally.  "
        "IMPORTANT: This method is deprecated in modern deployments because the "
        "PIN travels in plaintext on the ISO 7816 bus.  Still used in some EU "
        "transit/access scenarios.  Tests: VERIFY APDU construction."
    ),
    scheme=SchemeType.VISA,
    pan="4111111111111111",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.OFFLINE_PLAIN_PIN,
    aip_bytes="5800",
    expected_outcome="Approved — offline PIN verified by card",
    tags=["visa", "offline-pin", "verify-apdu", "deprecated"],
))

_reg(PredatorScenario(
    id="D5", category="D",
    name="Consumer Device CVM (CDCVM — Mobile Phone Auth)",
    description=(
        "CVM = CDCVM.  The cardholder authenticated ON the phone (biometric/PIN) "
        "before presenting.  The card signals this via AIP bit and CVM result.  "
        "Terminal MUST NOT prompt for PIN.  Tests: terminal correctly reads CDCVM "
        "indicator and skips its own CVM step.  Standard for Apple Pay / Google Pay."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000006",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.CDCVM,
    aip_bytes="5800",
    expected_outcome="Approved — phone-authenticated, no terminal PIN prompt",
    tags=["visa", "cdcvm", "mobile", "apple-pay", "google-pay"],
))

# ─── CATEGORY E: AID / APPLICATION SELECTION STRESS ──────────────────────────

_reg(PredatorScenario(
    id="E1", category="E",
    name="Multiple AID — PPSE returns Visa + Mastercard",
    description=(
        "PPSE (2PAY.SYS.DDF01) response contains both a Visa AID and a "
        "Mastercard AID with equal priority.  Tests: terminal candidate list "
        "processing, application selection UI (does it ask the cardholder?), "
        "and correct selection of highest-priority mutual AID."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000007",
    expiry_mmyy="1228",
    aid="A0000000031010",      # terminal should select this (first in list)
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    expected_outcome="Visa selected — correct priority resolution",
    tags=["visa", "multi-aid", "ppse", "application-selection"],
))

_reg(PredatorScenario(
    id="E3", category="E",
    name="No AID match — 6A82 on every SELECT",
    description=(
        "Card returns 0x6A82 (File Not Found) for every AID the terminal tries.  "
        "Tests: terminal gracefully handles the case where no mutual application "
        "exists.  MUST display 'This card cannot be used here' — not hang or crash."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000099",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.AAC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="0000",
    apdu_overrides=[
        APDUOverride(
            match_ins=0xA4,             # SELECT
            response_sw=0x6A82,         # File not found
            response_data=b"",
            note="No AID match — card rejects all SELECTs",
        )
    ],
    expected_outcome="Card rejected — 'Card not compatible with this terminal'",
    tags=["error", "no-aid", "6a82", "application-selection"],
))

# ─── CATEGORY F: CRYPTOGRAM / CRYPTO STRESS ───────────────────────────────────

_reg(PredatorScenario(
    id="F1", category="F",
    name="ATC Rollback — Replay Attack Detection",
    description=(
        "ATC (Application Transaction Counter) is set lower than what was last "
        "seen for this card.  A correctly implemented terminal or issuer MUST "
        "detect this as a potential replay attack and decline.  "
        "ATC monotonically increases by 1 on every transaction — any decrease "
        "means the card has been cloned or rolled back."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000020",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    atc_override=1,        # Force ATC to 0x0001 — clearly a rollback
    expected_outcome="Decline — ATC rollback detected by issuer",
    tags=["visa", "atc", "replay", "security", "fraud-detection"],
))

_reg(PredatorScenario(
    id="F2", category="F",
    name="ATC Jump — 1000 Higher Than Expected",
    description=(
        "ATC jumps by 1000 in a single transaction.  This may indicate the card "
        "is being used somewhere else in parallel (card sharing) or that counter "
        "manipulation has occurred.  Issuers often set a maximum ATC delta policy.  "
        "Tests: host-side ATC gap detection and risk scoring."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000020",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    atc_override=5000,     # Suspiciously high ATC jump
    expected_outcome="Risk flagged — unusual ATC delta — may trigger fraud review",
    tags=["visa", "atc", "fraud", "risk-scoring"],
))

_reg(PredatorScenario(
    id="F3", category="F",
    name="Weak Unpredictable Number — UN = 00000000",
    description=(
        "Unpredictable Number (UN) from the terminal is forced to 0x00000000.  "
        "The UN is supposed to prevent pre-computed ARQC attacks — a zero UN "
        "means any pre-computed ARQC for that card+ATC will be valid.  "
        "Tests: terminal's UN generation is truly random and not predictable.  "
        "NOTE: This scenario tests TERMINAL behaviour, not card behaviour."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000021",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    expected_outcome="Security risk — terminal using weak UN (test for compliance)",
    tags=["visa", "un", "unpredictable-number", "security", "pre-play"],
))

_reg(PredatorScenario(
    id="F5", category="F",
    name="All-zeros Cryptogram Response",
    description=(
        "GENERATE AC returns a cryptogram of 0x0000000000000000.  This is "
        "trivially distinguishable from a real ARQC and should be rejected by "
        "any issuer implementing ARQC verification.  Tests: issuer host correctly "
        "rejects degenerate cryptograms without crashing."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000022",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.ARQC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    cryptogram_override="0000000000000000",
    expected_outcome="Issuer decline — degenerate all-zeros ARQC rejected",
    tags=["visa", "crypto", "degenerate", "security"],
))

# ─── CATEGORY G: FALLBACK / COMPATIBILITY ─────────────────────────────────────

_reg(PredatorScenario(
    id="G1", category="G",
    name="Chip Fail → Magnetic Stripe Fallback",
    description=(
        "Card returns 0x6F00 (No Precise Diagnosis) on the first SELECT.  "
        "Terminal should detect chip failure and offer mag-stripe fallback if "
        "configured.  Many modern terminals and issuers DECLINE fallback as a "
        "fraud-prevention measure.  Tests: terminal's fallback policy handling "
        "and that it logs the event correctly."
    ),
    scheme=SchemeType.VISA,
    pan="4895370000000030",
    expiry_mmyy="1228",
    aid="A0000000031010",
    cryptogram_type=CryptogramType.AAC,
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5800",
    apdu_overrides=[
        APDUOverride(
            match_ins=0xA4,
            response_sw=0x6F00,         # No precise diagnosis — chip error
            response_data=b"",
            note="Simulate chip failure — trigger fallback path",
        )
    ],
    expected_outcome="Fallback declined or mag-stripe fallback attempted",
    tags=["visa", "fallback", "chip-fail", "mag-stripe", "6f00"],
))

_reg(PredatorScenario(
    id="G2", category="G",
    name="Contactless Ceiling Exceeded — Force Contact",
    description=(
        "Transaction amount exceeds the contactless ceiling (typically $200 in "
        "most markets).  Terminal MUST decline the contactless tap and instruct "
        "the cardholder to insert the card instead.  "
        "Tests: terminal contactless limit enforcement — critical for compliance."
    ),
    scheme=SchemeType.MASTERCARD,
    pan="5351100000000005",
    expiry_mmyy="1228",
    aid="A0000000041010",
    cryptogram_type=CryptogramType.AAC,   # Card also declines contactless
    cvm_preference=CVMPreference.NO_CVM,
    aip_bytes="5E00",
    floor_limit_cents=20000,              # $200 ceiling
    expected_outcome="Declined contactless — 'Please insert card'",
    tags=["mastercard", "contactless-ceiling", "compliance", "limit"],
))


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def load_scenario(scenario_id: str) -> PredatorScenario:
    """
    Load a predator card scenario by its ID.

    Args:
        scenario_id: Case-insensitive scenario ID, e.g. "A1", "b2", "F5".

    Returns:
        PredatorScenario dataclass.

    Raises:
        KeyError: If the ID is not found.

    Example:
        card = load_scenario("A1")   # Standard Visa contactless
        card = load_scenario("B1")   # Hard decline
    """
    key = scenario_id.upper()
    if key not in _SCENARIOS:
        available = ", ".join(sorted(_SCENARIOS.keys()))
        raise KeyError(f"Scenario {scenario_id!r} not found. Available: {available}")
    scenario = _SCENARIOS[key]
    logger.info("Loaded predator scenario: [%s] %s", scenario.id, scenario.name)
    return scenario


def list_scenarios(category: Optional[str] = None) -> List[PredatorScenario]:
    """
    Return all registered scenarios, optionally filtered by category letter.

    Args:
        category: Optional single letter e.g. "A", "B", "C". Case-insensitive.
                  If None, all scenarios are returned.

    Returns:
        Sorted list of PredatorScenario objects.

    Example:
        all_cards = list_scenarios()
        decline_cards = list_scenarios("B")
    """
    scenarios = list(_SCENARIOS.values())
    if category is not None:
        cat = category.upper()
        scenarios = [s for s in scenarios if s.category == cat]
    return sorted(scenarios, key=lambda s: s.id)


def list_by_tag(tag: str) -> List[PredatorScenario]:
    """
    Return all scenarios that have the given tag.

    Args:
        tag: Tag string to filter by, e.g. "arqc", "decline", "pin".

    Returns:
        List of matching PredatorScenario objects.

    Example:
        pin_cards = list_by_tag("pin")
        fraud_tests = list_by_tag("fraud-detection")
    """
    tag_lower = tag.lower()
    return [s for s in _SCENARIOS.values() if tag_lower in s.tags]


def scenario_summary() -> str:
    """
    Return a formatted text summary table of all loaded scenarios.

    Returns:
        Multi-line string suitable for printing to a terminal.
    """
    lines = [
        "",
        "╔══════════════════════════════════════════════════════════════════════╗",
        "║           GREENWIRE Predator Card Scenario Library                   ║",
        "╠═══════╦═══════════════════════════════════════════════╦══════════════╣",
        "║  ID   ║ Name                                          ║ Cryptogram   ║",
        "╠═══════╬═══════════════════════════════════════════════╬══════════════╣",
    ]
    for s in sorted(_SCENARIOS.values(), key=lambda x: x.id):
        ctype = s.cryptogram_type.value
        lines.append(f"║  {s.id:<4} ║ {s.name[:45]:<45} ║ {ctype:<12} ║")
    lines += [
        "╚═══════╩═══════════════════════════════════════════════╩══════════════╝",
        f"  Total: {len(_SCENARIOS)} scenarios across categories A–G",
        "",
    ]
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# CLI DEMO
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(message)s")

    print(scenario_summary())

    if len(sys.argv) > 1:
        sid = sys.argv[1]
        try:
            s = load_scenario(sid)
            print(f"\nScenario [{s.id}]: {s.name}")
            print(f"  Category    : {s.category}")
            print(f"  PAN         : {s.pan[:6]}xxxxxx{s.pan[-4:]}")
            print(f"  Scheme      : {s.scheme.value}")
            print(f"  AID         : {s.aid}")
            print(f"  Cryptogram  : {s.cryptogram_type.value}")
            print(f"  CVM         : {s.cvm_preference.value}")
            print(f"  Expected    : {s.expected_outcome}")
            print(f"\n  Description:")
            print(f"    {s.description}")
            if s.apdu_overrides:
                print(f"\n  APDU Overrides:")
                for o in s.apdu_overrides:
                    print(f"    INS=0x{o.match_ins:02X} → SW=0x{o.response_sw:04X}  ({o.note})")
            print(f"\n  JSON payload:")
            print("  " + json.dumps(s.to_dict(), indent=4).replace("\n", "\n  "))
        except KeyError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        print("Usage: python core/predator_card_scenarios.py [scenario_id]")
        print("       e.g.  python core/predator_card_scenarios.py A1")
