"""
GREENWIRE Card Validator
========================
Comprehensive payment card validation suite covering:

  • Luhn (mod-10) checksum — the primary integrity check on any PAN
  • BIN / IIN database — maps the first 6–8 digits to issuer, country, scheme
  • PAN structural rules per scheme (length, digit ranges)
  • Expiry date validation
  • CVV/CVC digit-count rules per scheme
  • Service code meaning decoder (track-2 3-digit field)
  • Country and bank-of-issue identification with ISO codes
  • Full card profile report

THEORY OF OPERATION
───────────────────
Every payment card starts with an IIN (Issuer Identification Number), formerly
called a BIN (Bank Identification Number). The IIN occupies the first 6 digits
of the PAN (expanded to 8 digits under ISO 7812-1:2017). The network uses the
IIN to route the transaction to the correct issuer.

Luhn Algorithm (ISO/IEC 7812-1 Annex B):
  1. Starting from the RIGHT-most digit (the check digit), double every second
     digit moving left.
  2. If doubling produces a value > 9, subtract 9.
  3. Sum all digits. If total mod 10 == 0 → valid.

Usage:
    from core.card_validator import validate_pan, CardProfile

    profile = validate_pan("4111111111111111")
    print(profile.scheme)          # "visa"
    print(profile.issuer_country)  # "US"
    print(profile.bank_name)       # "Test / Generic Visa"
    print(profile.luhn_ok)         # True
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# BIN DATABASE
# ──────────────────────────────────────────────────────────────────────────────
# Structure:  prefix_string → (scheme, bank_name, country_iso2, country_name, pan_length)
#
# Prefixes are tested longest-first so an 8-digit match beats a 4-digit match.
# Sources: public ISO 7812 documentation, open BIN lists, EMVCo test vectors,
#          Visa/MC developer documentation, and academic EMV research.
#
# TEST/RANGE indicators:
#   (T) = well-known test number (EMVCo, scheme dev portals)
#   (R) = real issuer range (anonymised to bank class, not individual card)

_BIN_DB: Dict[str, Tuple[str, str, str, str, int]] = {
    # ── VISA ─────────────────────────────────────────────────────────────────
    # scheme, bank_name, iso2, country_name, pan_len

    # Well-known EMVCo / Visa test PANs
    "41111111": ("visa",       "Test / Generic Visa (T)",          "US", "United States",    16),
    "40000001": ("visa",       "Test / Visa Debit (T)",             "US", "United States",    16),
    "40000002": ("visa",       "Test / Visa Prepaid (T)",           "US", "United States",    16),
    "45717360": ("visa",       "Test / Visa 3-D Secure (T)",        "US", "United States",    16),
    "48953700": ("visa",       "Visa Token / VTS DPAN (T)",         "US", "United States",    16),
    "48953701": ("visa",       "Visa Token / VTS DPAN (T)",         "US", "United States",    16),

    # UK Visa issuers
    "453978":   ("visa",       "Barclays Visa UK",                  "GB", "United Kingdom",   16),
    "454313":   ("visa",       "Lloyds Bank Visa UK",               "GB", "United Kingdom",   16),
    "491182":   ("visa",       "HSBC Visa UK",                      "GB", "United Kingdom",   16),
    "476173":   ("visa",       "NatWest Visa UK",                   "GB", "United Kingdom",   16),
    "405060":   ("visa",       "Santander UK Visa",                 "GB", "United Kingdom",   16),

    # US Visa issuers
    "414720":   ("visa",       "Chase Visa US",                     "US", "United States",    16),
    "426684":   ("visa",       "Bank of America Visa",              "US", "United States",    16),
    "431274":   ("visa",       "Wells Fargo Visa",                  "US", "United States",    16),
    "440393":   ("visa",       "Citibank Visa US",                  "US", "United States",    16),
    "403766":   ("visa",       "Capital One Visa",                  "US", "United States",    16),

    # EU Visa issuers
    "461046":   ("visa",       "Deutsche Bank Visa DE",             "DE", "Germany",          16),
    "435516":   ("visa",       "BNP Paribas Visa FR",               "FR", "France",           16),
    "432415":   ("visa",       "ING Bank Visa NL",                  "NL", "Netherlands",      16),
    "405516":   ("visa",       "Intesa Sanpaolo Visa IT",           "IT", "Italy",            16),

    # AU / NZ
    "452263":   ("visa",       "Commonwealth Bank AU",              "AU", "Australia",        16),
    "413720":   ("visa",       "ANZ Visa AU",                       "AU", "Australia",        16),

    # Wildcard Visa ranges (prefix-only, lower priority)
    "4":        ("visa",       "Visa (generic range)",              "ZZ", "Unknown",          16),

    # ── MASTERCARD ───────────────────────────────────────────────────────────
    # 2-series BINs (ISO 7812 update, 2017)
    "22214567": ("mastercard", "Test / MC 2-series (T)",            "US", "United States",    16),
    "23190018": ("mastercard", "Test / MC 2-series Alt (T)",        "US", "United States",    16),

    # MDES Token BINs
    "53511000": ("mastercard", "MC Token / MDES DPAN (T)",          "US", "United States",    16),
    "53511001": ("mastercard", "MC Token / MDES DPAN (T)",          "US", "United States",    16),

    # Well-known test PANs (5-series)
    "51071234": ("mastercard", "Test / MC Debit (T)",               "US", "United States",    16),
    "54231234": ("mastercard", "Test / MC Prepaid (T)",             "US", "United States",    16),

    # UK MC issuers
    "534214":   ("mastercard", "HSBC Mastercard UK",                "GB", "United Kingdom",   16),
    "518760":   ("mastercard", "Barclaycard Mastercard UK",         "GB", "United Kingdom",   16),
    "535420":   ("mastercard", "Monzo Mastercard UK",               "GB", "United Kingdom",   16),
    "529900":   ("mastercard", "Revolut Mastercard UK",             "GB", "United Kingdom",   16),

    # US MC issuers
    "510677":   ("mastercard", "Citi Mastercard US",                "US", "United States",    16),
    "524030":   ("mastercard", "Chase Mastercard US",               "US", "United States",    16),
    "545616":   ("mastercard", "Capital One MC US",                 "US", "United States",    16),

    # EU MC issuers
    "516730":   ("mastercard", "Société Générale MC FR",            "FR", "France",           16),
    "512001":   ("mastercard", "Sparkasse MC DE",                   "DE", "Germany",          16),

    # 2-series wildcard (2221–2720)
    "222":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "223":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "224":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "225":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "226":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "227":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "228":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "229":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "23":       ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "24":       ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "25":       ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "26":       ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "270":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "271":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),
    "272":      ("mastercard", "Mastercard 2-series (generic)",     "ZZ", "Unknown",          16),

    # 5-series wildcard
    "51":       ("mastercard", "Mastercard (generic 51xx)",         "ZZ", "Unknown",          16),
    "52":       ("mastercard", "Mastercard (generic 52xx)",         "ZZ", "Unknown",          16),
    "53":       ("mastercard", "Mastercard (generic 53xx)",         "ZZ", "Unknown",          16),
    "54":       ("mastercard", "Mastercard (generic 54xx)",         "ZZ", "Unknown",          16),
    "55":       ("mastercard", "Mastercard (generic 55xx)",         "ZZ", "Unknown",          16),

    # ── AMEX ─────────────────────────────────────────────────────────────────
    "341234":   ("amex",       "Test / Amex Green (T)",             "US", "United States",    15),
    "371245":   ("amex",       "Test / Amex Gold (T)",              "US", "United States",    15),
    "378282":   ("amex",       "Test / Amex Platinum (T)",          "US", "United States",    15),
    "371449":   ("amex",       "Test / Amex Corporate (T)",         "US", "United States",    15),
    "34":       ("amex",       "Amex (generic 34xx)",               "US", "United States",    15),
    "37":       ("amex",       "Amex (generic 37xx)",               "US", "United States",    15),

    # ── DISCOVER / DINERS ────────────────────────────────────────────────────
    "60114567": ("discover",   "Test / Discover (T)",               "US", "United States",    16),
    "6011":     ("discover",   "Discover (6011 range)",             "US", "United States",    16),
    "622":      ("unionpay",   "UnionPay (622xxx range)",           "CN", "China",            16),
    "64":       ("discover",   "Discover (64xx range)",             "US", "United States",    16),
    "65":       ("discover",   "Discover (65xx range)",             "US", "United States",    16),
    "36":       ("diners",     "Diners Club International",         "US", "United States",    14),
    "38":       ("diners",     "Diners Club (Carte Blanche)",       "US", "United States",    14),
    "300":      ("diners",     "Diners Club (300-305)",             "US", "United States",    14),
    "301":      ("diners",     "Diners Club (300-305)",             "US", "United States",    14),
    "302":      ("diners",     "Diners Club (300-305)",             "US", "United States",    14),
    "303":      ("diners",     "Diners Club (300-305)",             "US", "United States",    14),
    "304":      ("diners",     "Diners Club (300-305)",             "US", "United States",    14),
    "305":      ("diners",     "Diners Club (300-305)",             "US", "United States",    14),

    # ── JCB ──────────────────────────────────────────────────────────────────
    "3528":     ("jcb",        "JCB (3528 range)",                  "JP", "Japan",            16),
    "3529":     ("jcb",        "JCB (3529 range)",                  "JP", "Japan",            16),
    "353":      ("jcb",        "JCB (353x range)",                  "JP", "Japan",            16),
    "354":      ("jcb",        "JCB (354x range)",                  "JP", "Japan",            16),
    "355":      ("jcb",        "JCB (355x range)",                  "JP", "Japan",            16),
    "356":      ("jcb",        "JCB (356x range)",                  "JP", "Japan",            16),
    "357":      ("jcb",        "JCB (357x range)",                  "JP", "Japan",            16),
    "358":      ("jcb",        "JCB (358x range)",                  "JP", "Japan",            16),

    # ── INTERAC ──────────────────────────────────────────────────────────────
    "4506":     ("interac",    "Interac Debit CA",                  "CA", "Canada",           16),
    "4513":     ("interac",    "Interac Debit CA",                  "CA", "Canada",           16),
    "4532":     ("interac",    "TD Bank Interac CA",                "CA", "Canada",           16),

    # ── UNION PAY ────────────────────────────────────────────────────────────
    "62":       ("unionpay",   "UnionPay (generic)",                "CN", "China",            16),

    # ── MAESTRO ──────────────────────────────────────────────────────────────
    "6304":     ("maestro",    "Maestro (6304)",                    "ZZ", "Unknown",          13),
    "6759":     ("maestro",    "Maestro (6759)",                    "ZZ", "Unknown",          16),
    "6761":     ("maestro",    "Maestro / Visa Debit (6761)",       "ZZ", "Unknown",          16),
    "6763":     ("maestro",    "Maestro (6763)",                    "ZZ", "Unknown",          16),
}

# Pre-sort BIN keys longest-first so matching tries the most specific prefix first.
_SORTED_BINS: List[str] = sorted(_BIN_DB.keys(), key=len, reverse=True)


# ──────────────────────────────────────────────────────────────────────────────
# SCHEME PAN LENGTH RULES
# ──────────────────────────────────────────────────────────────────────────────
# Per ISO 7812-1 and each scheme's technical specifications.
# Format: scheme → (min_len, max_len, expected_lengths)

_SCHEME_PAN_RULES: Dict[str, Tuple[int, int, Tuple[int, ...]]] = {
    "visa":       (13, 19, (13, 16, 19)),
    "mastercard": (16, 16, (16,)),
    "amex":       (15, 15, (15,)),
    "discover":   (16, 19, (16, 17, 18, 19)),
    "diners":     (14, 19, (14, 16, 17, 18, 19)),
    "jcb":        (15, 19, (16,)),
    "unionpay":   (16, 19, (16, 17, 18, 19)),
    "maestro":    (12, 19, (13, 15, 16, 17, 18, 19)),
    "interac":    (16, 16, (16,)),
}

# CVV digit-count rules per scheme
_SCHEME_CVV_LENGTHS: Dict[str, Tuple[int, ...]] = {
    "visa":       (3,),
    "mastercard": (3,),
    "amex":       (4,),       # Amex uses 4-digit CID on the front face
    "discover":   (3,),
    "diners":     (3,),
    "jcb":        (3,),
    "unionpay":   (3,),
    "maestro":    (3,),
    "interac":    (3,),
}

# ──────────────────────────────────────────────────────────────────────────────
# SERVICE CODE DECODER
# ──────────────────────────────────────────────────────────────────────────────
# The 3-digit service code lives on magnetic-stripe track 1 and track 2.
# Each digit has a specific meaning (ISO 7813).

_SERVICE_CODE_POS1: Dict[str, str] = {
    "1": "International interchange OK",
    "2": "International interchange, use ICC where possible",
    "5": "National interchange only",
    "6": "National interchange only, use ICC where possible",
    "7": "Private — no interchange (issuer-proprietary)",
    "9": "Test card",
}
_SERVICE_CODE_POS2: Dict[str, str] = {
    "0": "Normal — no restrictions, PIN required",
    "1": "Normal — no restrictions",
    "2": "Positive card-holder ID (online PIN)",
    "3": "ATM only; PIN required",
    "4": "Cash only",
    "5": "Goods & services only — no cash",
    "6": "No restrictions, PIN if PED available",
    "7": "Goods & services only — PIN if PED available",
}
_SERVICE_CODE_POS3: Dict[str, str] = {
    "0": "No restrictions — PIN required",
    "1": "No restrictions",
    "2": "Goods & services only — no cash",
    "3": "ATM only",
    "4": "Cash only",
    "5": "Goods & services only — no cash, PIN required",
    "6": "No restrictions — use PIN if PED available",
    "7": "Goods & services only — PIN if PED available",
}


# ──────────────────────────────────────────────────────────────────────────────
# RESULT DATACLASS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CardProfile:
    """Complete validation profile for a payment card PAN."""

    pan: str                       # Normalised PAN (digits only)
    luhn_ok: bool                  # Did the Luhn check pass?
    scheme: str                    # "visa", "mastercard", etc.
    bin6: str                      # First 6 digits (classic BIN)
    bin8: str                      # First 8 digits (modern IIN)
    bank_name: str                 # Bank / issuer name from BIN database
    issuer_country: str            # ISO 3166-1 alpha-2 country code
    issuer_country_name: str       # Human-readable country name
    pan_length: int                # Actual length of the PAN
    expected_lengths: Tuple[int, ...] = field(default_factory=tuple)
    pan_length_ok: bool = True     # Does length match scheme rules?
    errors: List[str] = field(default_factory=list)   # Validation errors
    warnings: List[str] = field(default_factory=list) # Non-fatal warnings

    # Optional enriched fields (populated when extra args given to validate_pan)
    expiry_ok: Optional[bool] = None
    cvv_ok: Optional[bool] = None
    service_code_meaning: Optional[str] = None

    @property
    def is_test_pan(self) -> bool:
        """Return True if this looks like a well-known test/EMVCo PAN."""
        return "(T)" in self.bank_name

    @property
    def is_token(self) -> bool:
        """Return True if BIN is a known tokenisation DPAN range."""
        return "Token" in self.bank_name or "DPAN" in self.bank_name

    @property
    def ok(self) -> bool:
        """True if all mandatory checks passed (Luhn + length)."""
        return self.luhn_ok and self.pan_length_ok and not self.errors


# ──────────────────────────────────────────────────────────────────────────────
# CORE LUHN FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

def luhn_checksum(pan: str) -> int:
    """
    Compute the Luhn checksum digit for a partial PAN (without check digit).

    Algorithm (ISO/IEC 7812-1 Annex B):
      Working from right to left, double every second digit.
      If doubling gives > 9, subtract 9.
      Return (10 - sum % 10) % 10.

    Args:
        pan: The PAN WITHOUT the trailing check digit.

    Returns:
        The single check digit (0–9) to append.

    Example:
        luhn_checksum("411111111111111") == 1  → full PAN "4111111111111111"
    """
    total = 0
    # Reverse the digits (we're working right-to-left)
    for i, ch in enumerate(reversed(pan)):
        n = int(ch)
        # Every other digit (starting from position 0 on the right of the
        # *partial* PAN, which is position 1 counting from check-digit side)
        # needs to be doubled.
        if i % 2 == 0:          # 0-indexed, so even positions get doubled
            n *= 2
            if n > 9:
                n -= 9          # same as summing the two digits
        total += n
    return (10 - (total % 10)) % 10


def luhn_valid(pan: str) -> bool:
    """
    Validate a complete PAN (including check digit) against the Luhn algorithm.

    Args:
        pan: Complete PAN string (digits only, or digits+spaces/hyphens).

    Returns:
        True if Luhn check passes, False otherwise.

    Example:
        luhn_valid("4111111111111111")  → True
        luhn_valid("4111111111111112")  → False
    """
    digits = re.sub(r"\D", "", pan)  # strip non-digits
    if len(digits) < 2:
        return False
    # Use the same algorithm but include the check digit:
    # Double every second digit from right, starting at position 1 (0-indexed)
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:          # odd positions from the right get doubled
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def luhn_append(partial_pan: str) -> str:
    """
    Append the correct Luhn check digit to a partial PAN.

    Args:
        partial_pan: PAN digits without the final check digit.

    Returns:
        Complete PAN string (partial_pan + check_digit).

    Example:
        luhn_append("411111111111111") == "4111111111111111"
    """
    check = luhn_checksum(partial_pan)
    result = partial_pan + str(check)
    logger.debug("Luhn append: %s → %s (check=%d)", partial_pan, result, check)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# BIN LOOKUP
# ──────────────────────────────────────────────────────────────────────────────

def lookup_bin(pan: str) -> Optional[Tuple[str, str, str, str, int]]:
    """
    Look up the BIN database for a given PAN.

    Tries the longest matching prefix first (8 digits → 7 → … → 1).

    Args:
        pan: PAN string (at least 6 digits).

    Returns:
        (scheme, bank_name, country_iso2, country_name, pan_length)
        or None if no match found.
    """
    digits = re.sub(r"\D", "", pan)
    for prefix in _SORTED_BINS:
        if digits.startswith(prefix):
            entry = _BIN_DB[prefix]
            logger.debug("BIN match: prefix=%s → %s / %s / %s",
                         prefix, entry[0], entry[1], entry[2])
            return entry
    logger.debug("BIN not found for PAN starting with: %s", digits[:8])
    return None


# ──────────────────────────────────────────────────────────────────────────────
# SERVICE CODE DECODER
# ──────────────────────────────────────────────────────────────────────────────

def decode_service_code(service_code: str) -> str:
    """
    Decode a 3-digit service code (from magnetic stripe track 1 or 2).

    The service code tells POS terminals and ATMs how they are allowed
    to process this card — whether online authorisation is required,
    whether a PIN is needed, and which geographic scope is permitted.

    Args:
        service_code: Exactly 3 ASCII digit characters.

    Returns:
        Human-readable description string.

    Example:
        decode_service_code("101") →
            "Pos1: International interchange OK | Pos2: Normal — no restrictions | Pos3: No restrictions"
    """
    if len(service_code) != 3 or not service_code.isdigit():
        return f"Invalid service code: {service_code!r} (must be 3 digits)"

    d1, d2, d3 = service_code[0], service_code[1], service_code[2]
    p1 = _SERVICE_CODE_POS1.get(d1, f"Reserved/unknown ({d1})")
    p2 = _SERVICE_CODE_POS2.get(d2, f"Reserved/unknown ({d2})")
    p3 = _SERVICE_CODE_POS3.get(d3, f"Reserved/unknown ({d3})")
    return f"Pos1: {p1} | Pos2: {p2} | Pos3: {p3}"


# ──────────────────────────────────────────────────────────────────────────────
# FULL VALIDATION ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def validate_pan(
    pan: str,
    *,
    expiry: Optional[str] = None,
    cvv: Optional[str] = None,
    service_code: Optional[str] = None,
) -> CardProfile:
    """
    Perform full validation of a payment card PAN and return a CardProfile.

    Checks performed:
      1. Luhn (mod-10) checksum
      2. BIN lookup → scheme, bank, country
      3. PAN length vs scheme rules
      4. Expiry date (if provided) — format MM/YY
      5. CVV digit-count (if provided)
      6. Service code decode (if provided)

    Args:
        pan:          PAN string — digits only or formatted (spaces/hyphens stripped).
        expiry:       Optional "MM/YY" expiry date string.
        cvv:          Optional CVV/CVC/CID string (3 or 4 digits).
        service_code: Optional 3-digit magnetic-stripe service code.

    Returns:
        CardProfile with all validation results.

    Example:
        profile = validate_pan("4111111111111111", expiry="12/26", cvv="123")
        assert profile.luhn_ok
        assert profile.scheme == "visa"
        assert profile.issuer_country == "US"
    """
    digits = re.sub(r"\D", "", pan)
    errors: List[str] = []
    warnings: List[str] = []

    # ── 1. Luhn ──────────────────────────────────────────────────────────────
    luhn_ok = luhn_valid(digits)
    if not luhn_ok:
        errors.append(f"Luhn check FAILED for PAN {digits[:6]}...{digits[-4:]}")
        logger.warning("Luhn failure: %s...%s", digits[:6], digits[-4:])
    else:
        logger.debug("Luhn OK: %s...%s", digits[:6], digits[-4:])

    # ── 2. BIN lookup ────────────────────────────────────────────────────────
    bin_entry = lookup_bin(digits)
    if bin_entry:
        scheme, bank_name, iso2, country_name, expected_pan_len = bin_entry
    else:
        scheme = "unknown"
        bank_name = "Unknown issuer (BIN not in database)"
        iso2 = "ZZ"
        country_name = "Unknown"
        expected_pan_len = 16
        warnings.append(f"BIN {digits[:8]!r} not found in database — scheme unknown")

    bin6 = digits[:6]
    bin8 = digits[:8] if len(digits) >= 8 else digits.ljust(8, "?")

    # ── 3. PAN length ────────────────────────────────────────────────────────
    pan_len = len(digits)
    scheme_rule = _SCHEME_PAN_RULES.get(scheme)
    if scheme_rule:
        min_len, max_len, valid_lengths = scheme_rule
        pan_length_ok = pan_len in valid_lengths
        if not pan_length_ok:
            errors.append(
                f"PAN length {pan_len} is not valid for {scheme} "
                f"(expected: {valid_lengths})"
            )
    else:
        pan_length_ok = 13 <= pan_len <= 19
        valid_lengths = tuple(range(13, 20))
        if not pan_length_ok:
            errors.append(f"PAN length {pan_len} is outside 13–19 digit range")

    # ── 4. Expiry ─────────────────────────────────────────────────────────────
    expiry_ok: Optional[bool] = None
    if expiry is not None:
        try:
            exp_dt = datetime.strptime(expiry.strip(), "%m/%y")
            # Card is valid through the last day of the expiry month.
            # Compare to first-of-current-month to allow current month.
            now_first = datetime.now(timezone.utc).replace(tzinfo=None).replace(day=1, hour=0, minute=0,
                                                   second=0, microsecond=0)
            expiry_ok = exp_dt.replace(day=1) >= now_first
            if not expiry_ok:
                errors.append(f"Card expired: {expiry}")
            else:
                logger.debug("Expiry OK: %s", expiry)
        except ValueError:
            expiry_ok = False
            errors.append(f"Expiry format invalid: {expiry!r} (expected MM/YY)")

    # ── 5. CVV ────────────────────────────────────────────────────────────────
    cvv_ok: Optional[bool] = None
    if cvv is not None:
        allowed_cvv_lens = _SCHEME_CVV_LENGTHS.get(scheme, (3, 4))
        cvv_clean = re.sub(r"\D", "", cvv)
        cvv_ok = cvv_clean.isdigit() and len(cvv_clean) in allowed_cvv_lens
        if not cvv_ok:
            errors.append(
                f"CVV length {len(cvv_clean)} invalid for {scheme} "
                f"(expected: {allowed_cvv_lens})"
            )

    # ── 6. Service code ───────────────────────────────────────────────────────
    svc_meaning: Optional[str] = None
    if service_code is not None:
        svc_meaning = decode_service_code(service_code)

    # ── Build profile ─────────────────────────────────────────────────────────
    profile = CardProfile(
        pan=digits,
        luhn_ok=luhn_ok,
        scheme=scheme,
        bin6=bin6,
        bin8=bin8,
        bank_name=bank_name,
        issuer_country=iso2,
        issuer_country_name=country_name,
        pan_length=pan_len,
        expected_lengths=valid_lengths,
        pan_length_ok=pan_length_ok,
        errors=errors,
        warnings=warnings,
        expiry_ok=expiry_ok,
        cvv_ok=cvv_ok,
        service_code_meaning=svc_meaning,
    )

    # Log a clean summary line
    status = "PASS" if profile.ok else "FAIL"
    logger.info(
        "Card validation %s | %s | %s | %s | %s",
        status, scheme.upper(), bank_name, country_name,
        f"{digits[:4]} xxxx xxxx {digits[-4:]}",
    )
    return profile


def validate_pan_batch(pans: List[str], **kwargs) -> List[CardProfile]:
    """
    Validate a list of PANs and return a list of CardProfile objects.

    Any extra keyword arguments (expiry, cvv, service_code) are passed to
    validate_pan for every PAN in the batch — useful when testing a series
    of cards with the same expiry.

    Args:
        pans:    List of PAN strings.
        **kwargs: Passed through to validate_pan.

    Returns:
        List of CardProfile, one per input PAN, in order.
    """
    results = []
    for pan in pans:
        results.append(validate_pan(pan, **kwargs))
    passed = sum(1 for r in results if r.ok)
    logger.info("Batch validation complete: %d/%d passed", passed, len(results))
    return results


# ──────────────────────────────────────────────────────────────────────────────
# CLI DEMO
# ──────────────────────────────────────────────────────────────────────────────

def _print_profile(profile: CardProfile) -> None:
    """Pretty-print a CardProfile to stdout."""
    ok = "✓" if profile.ok else "✗"
    print(f"\n  {ok} PAN      : {profile.pan[:4]} {profile.pan[4:8]} "
          f"{profile.pan[8:12]} {profile.pan[12:]}")
    print(f"     Scheme   : {profile.scheme.upper()}")
    print(f"     Bank     : {profile.bank_name}")
    print(f"     Country  : {profile.issuer_country} – {profile.issuer_country_name}")
    print(f"     BIN6/8   : {profile.bin6} / {profile.bin8}")
    print(f"     Luhn     : {'PASS ✓' if profile.luhn_ok else 'FAIL ✗'}")
    print(f"     Length   : {profile.pan_length} "
          f"({'OK' if profile.pan_length_ok else 'INVALID'},"
          f" expected {profile.expected_lengths})")
    if profile.expiry_ok is not None:
        print(f"     Expiry   : {'OK ✓' if profile.expiry_ok else 'EXPIRED ✗'}")
    if profile.cvv_ok is not None:
        print(f"     CVV      : {'OK ✓' if profile.cvv_ok else 'INVALID ✗'}")
    if profile.service_code_meaning:
        print(f"     SvcCode  : {profile.service_code_meaning}")
    if profile.is_test_pan:
        print("     ⚑ Known test PAN")
    if profile.is_token:
        print("     ⚑ Token / DPAN range")
    if profile.errors:
        for e in profile.errors:
            print(f"     ✗ {e}")
    if profile.warnings:
        for w in profile.warnings:
            print(f"     ⚠ {w}")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)-8s %(message)s")

    TEST_CASES = [
        # (pan, expiry, cvv, service_code)
        ("4111111111111111",  "12/28", "123", "101"),   # Visa test
        ("5500005555555559",  "06/27", "456", "201"),   # MC test
        ("378282246310005",   "03/26", "1234", None),   # Amex test
        ("6011111111111117",  "09/27", "789", None),    # Discover test
        ("4111111111111112",  None,    None,  None),    # Luhn fail
        ("53511001234567890", None,    None,  None),    # MDES DPAN token range
    ]

    print("\n" + "="*60)
    print(" GREENWIRE Card Validator — Test Run")
    print("="*60)

    for pan, exp, cvv, svc in TEST_CASES:
        profile = validate_pan(pan, expiry=exp, cvv=cvv, service_code=svc)
        _print_profile(profile)

    print("\n" + "="*60)
    print(" Luhn utility demos:")
    partial = "411111111111111"
    full = luhn_append(partial)
    print(f"  luhn_append('{partial}') → '{full}'")
    print(f"  luhn_valid('{full}')  → {luhn_valid(full)}")
    print(f"  decode_service_code('101') → {decode_service_code('101')}")
    print("="*60 + "\n")
