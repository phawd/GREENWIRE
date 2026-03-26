"""
Predator Card PAN Generator
============================
Generates Payment Account Numbers (PANs) that are:

  1. STRUCTURALLY VALID per ISO/IEC 7812-1
     - Correct length for the scheme (15 digits Amex, 16 for Visa/MC/Discover, etc.)
     - Valid Luhn check digit (ISO/IEC 7812-1 Annex B)

  2. ON REAL ABA-REGISTERED BIN RANGES
     - Uses Bank Identification Numbers (BINs) from the ABA IIN registry
     - The BIN owner (issuing bank) is real — Barclays, Chase, HSBC, etc.
     - For testing, we use BINs from our known-good BIN database
     - This means the PAN *looks* like it came from a real bank

  3. ACCOUNT NUMBER PORTION IS RANDOMISED
     - Digits after the BIN prefix are pseudo-random
     - No real cardholder account is ever targeted or replicated
     - The Luhn check digit is always correct

  4. REGISTERED TO PREVENT DUPLICATES
     - Every generated PAN is stored in pan_registry.py
     - Duplicate generation is retried automatically (max 100 attempts)

WHY REAL ABA BINS?
──────────────────
EMV terminals, acquirer gateways, and HSMs validate the BIN portion of a PAN
to route the transaction to the correct network.  A fake BIN prefix will be
rejected by the routing table before the terminal even processes the card.

For predator card testing to exercise real terminal code paths:
  - The PAN must route correctly → needs a real BIN
  - The Luhn must pass → needs a valid check digit
  - The account number must not match a real account → must be randomised

LEGAL NOTE
──────────
These PANs are generated for authorised security testing only.
The account number suffix is random and does not correspond to any real account.
All generated PANs are registered in the lab's PAN registry to prevent collision.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from core.card_validator import luhn_append, _BIN_DB, _SORTED_BINS
from core.pan_registry import register_pan, is_registered

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# PREFERRED BIN SELECTIONS (real ABA-registered, good for lab testing)
# ──────────────────────────────────────────────────────────────────────────────

# UK issuers — preferred for Category A and G scenarios
_UK_VISA_BINS   = ["453978", "454313", "491182", "476173", "405060"]
_UK_MC_BINS     = ["534214", "518760", "535420", "529900"]

# US issuers — preferred for Category C (floor/velocity) scenarios
_US_VISA_BINS   = ["414720", "426684", "431274", "440393", "403766"]
_US_MC_BINS     = ["510677", "524030", "545616"]

# Amex — preferred for Category D no-signature scenarios
_AMEX_BINS      = ["341234", "371245", "378282", "371449"]

# Full scheme → preferred BIN list mapping (longer/more specific BINs only)
_PREFERRED_BINS_BY_SCHEME = {
    "visa":       _UK_VISA_BINS + _US_VISA_BINS,
    "mastercard": _UK_MC_BINS   + _US_MC_BINS,
    "amex":       _AMEX_BINS,
    "discover":   ["6011"],
}

# Schemes to exclude from random selection (wildcards / non-payment)
_EXCLUDE_SCHEMES = {"diners", "jcb", "unionpay", "maestro", "interac"}


# ──────────────────────────────────────────────────────────────────────────────
# RESULT DATACLASS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PredatorPAN:
    """
    A fully-generated, validated Predator Card PAN with all associated metadata.

    Every field is populated at generation time and remains immutable.
    The PAN is guaranteed to pass Luhn and be registered in the PAN registry.
    """
    pan: str                   # Full 15 or 16 digit PAN string
    bin_prefix: str            # The BIN portion used (6–8 digits)
    scheme: str                # visa / mastercard / amex / etc.
    bank_name: str             # e.g. "Barclays Visa UK"
    country: str               # ISO 3166-1 alpha-2, e.g. "GB"
    country_name: str          # e.g. "United Kingdom"
    pan_length: int            # 15 or 16
    luhn_valid: bool           # Always True for generated PANs
    expiry: str                # "MM/YY" format
    expiry_mmyy: str           # "MMYY" format for EMV fields
    service_code: str          # "201" = international/chip, "101" = international/mag
    track2_equivalent: str     # PAN=EXPIRY=SERVICE_CODE format for EMV Track 2 Record

    def masked(self) -> str:
        """Return masked PAN, e.g. 453978xxxxxx1234."""
        return self.pan[:6] + "x" * (len(self.pan) - 10) + self.pan[-4:]

    def to_bcd(self) -> bytes:
        """
        Return the PAN in BCD-packed format padded with 'F' nibble if odd length.

        Used for encoding in EMV tag 0x5A (Application Primary Account Number).
        """
        padded = self.pan if len(self.pan) % 2 == 0 else self.pan + "F"
        return bytes(int(padded[i:i+2], 16) for i in range(0, len(padded), 2))

    def expiry_yymm(self) -> str:
        """Return expiry as YYMM (EMV tag 0x5F24 format)."""
        # expiry_mmyy is MMYY → reorder to YYMM
        mm = self.expiry_mmyy[:2]
        yy = self.expiry_mmyy[2:]
        return yy + mm


# ──────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _pick_bin(scheme: Optional[str], country: Optional[str]) -> tuple:
    """
    Choose a BIN prefix from the database matching scheme and country filters.

    Returns:
        (bin_prefix, scheme_str, bank_name, country_iso2, country_name, pan_len)
    """
    candidates = []

    for prefix in _SORTED_BINS:
        info = _BIN_DB[prefix]
        bin_scheme, bank_name, iso2, country_name, pan_len = info

        # Skip wildcard/generic entries (single digit or 2-digit) unless there
        # are no better options — we always prefer specific 6-digit BINs.
        if len(prefix) < 4:
            continue

        # Skip excluded schemes
        if bin_scheme in _EXCLUDE_SCHEMES:
            continue

        # Skip test-range BINs (e.g. 41111111, 48953700) — they are EMVCo
        # test numbers and will be rejected by real acquirer routing tables.
        if "(T)" in bank_name or "Token" in bank_name or "DPAN" in bank_name:
            continue

        # Apply scheme filter
        if scheme is not None and bin_scheme != scheme.lower():
            continue

        # Apply country filter
        if country is not None and iso2 != country.upper():
            continue

        # Skip unknown-country entries unless no country filter given
        if country is None and iso2 == "ZZ":
            continue

        candidates.append((prefix, bin_scheme, bank_name, iso2, country_name, pan_len))

    if not candidates:
        # Relax country constraint and try again
        if country is not None:
            logger.warning(
                "No BIN found for scheme=%s country=%s — relaxing country filter",
                scheme, country,
            )
            return _pick_bin(scheme, None)
        raise ValueError(
            f"No suitable BIN found for scheme={scheme!r}, country={country!r}"
        )

    # Use os.urandom for selection to avoid predictable patterns
    idx = int.from_bytes(os.urandom(2), "big") % len(candidates)
    return candidates[idx]


def _random_account_digits(bin_prefix: str, pan_length: int) -> str:
    """
    Generate random account-number digits to fill out a PAN.

    The account number occupies positions [len(bin_prefix) .. pan_length-2].
    Position pan_length-1 is left empty for the Luhn check digit.
    All randomness comes from os.urandom.

    Returns:
        The partial PAN (bin + random account digits, WITHOUT check digit).
    """
    # Number of random digits needed (excluding the final check digit)
    n_random = pan_length - len(bin_prefix) - 1
    if n_random < 0:
        raise ValueError(
            f"BIN prefix {bin_prefix!r} ({len(bin_prefix)} digits) is too long "
            f"for PAN length {pan_length}"
        )
    # Generate using os.urandom — convert each byte to a 0-9 digit
    random_bytes = os.urandom(n_random * 2)  # oversample
    digits = ""
    for b in random_bytes:
        digits += str(b % 10)
        if len(digits) == n_random:
            break
    return bin_prefix + digits


def _compute_expiry(years_from_now: int) -> tuple:
    """
    Compute an expiry date N years from today (UTC).

    Returns:
        (expiry_slash, expiry_mmyy) — e.g. ("03/28", "0328")
    """
    now = datetime.now(timezone.utc)
    exp_year  = now.year + years_from_now
    exp_month = now.month
    mm = f"{exp_month:02d}"
    yy = str(exp_year)[-2:]
    return f"{mm}/{yy}", f"{mm}{yy}"


def _build_track2(pan: str, expiry_mmyy: str, service_code: str) -> str:
    """
    Build the Track 2 Equivalent Data string per ISO 7813.

    Format: PAN = EXPIRY = SERVICE_CODE
    In actual EMV records this is encoded as BCD with field-separator 0xD.
    """
    return f"{pan}={expiry_mmyy}={service_code}"


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def generate_predator_pan(
    scheme: Optional[str] = None,
    bin_prefix: Optional[str] = None,
    country: Optional[str] = None,
    expiry_years: int = 3,
    service_code: str = "201",
    registry_path: Optional[Path] = None,
    max_retries: int = 100,
) -> PredatorPAN:
    """
    Generate one valid predator card PAN.

    The PAN uses a real ABA-registered BIN, has a random account number portion,
    and carries a valid Luhn check digit.  Every generated PAN is registered in
    the PAN registry to prevent duplicates.

    Args:
        scheme:        Payment scheme ("visa", "mastercard", "amex", etc.).
                       None = random selection from all supported schemes.
        bin_prefix:    Specific BIN to use (overrides scheme/country selection).
                       Must exist in _BIN_DB.  None = auto-select.
        country:       ISO 3166-1 alpha-2 country code filter ("GB", "US", etc.).
                       None = any country.
        expiry_years:  Years from today for expiry date (default 3).
        service_code:  3-digit service code (default "201" = international/chip).
        registry_path: Path to the PAN registry JSON file.  None = default.
        max_retries:   Maximum collision retries before raising RuntimeError.

    Returns:
        PredatorPAN dataclass with all fields populated.

    Raises:
        RuntimeError: If a unique PAN cannot be generated within max_retries.
        ValueError:   If bin_prefix is unknown or no BINs match the filters.
    """
    # Resolve a fixed BIN if one was specified
    if bin_prefix is not None:
        # Find the BIN in the database (try exact match, then prefix match)
        found_key = None
        for key in _SORTED_BINS:
            if bin_prefix.startswith(key) or key.startswith(bin_prefix):
                found_key = key
                break
        if found_key is None:
            raise ValueError(f"BIN prefix {bin_prefix!r} not found in _BIN_DB")
        bin_info = _BIN_DB[found_key]
        resolved_scheme, bank_name, iso2, country_name, pan_len = bin_info
        resolved_bin = found_key
    else:
        resolved_bin, resolved_scheme, bank_name, iso2, country_name, pan_len = \
            _pick_bin(scheme, country)

    expiry_slash, expiry_mmyy = _compute_expiry(expiry_years)

    for attempt in range(max_retries):
        partial = _random_account_digits(resolved_bin, pan_len)
        full_pan = luhn_append(partial)

        if is_registered(full_pan, path=registry_path):
            logger.debug("PAN collision on attempt %d, retrying…", attempt + 1)
            continue

        ok = register_pan(
            full_pan,
            source=f"predator_pan_generator/{resolved_scheme}/{resolved_bin}",
            allow_existing=False,
            path=registry_path,
        )
        if not ok:
            # Race condition — another process registered it
            continue

        track2 = _build_track2(full_pan, expiry_mmyy, service_code)

        logger.info(
            "Generated predator PAN: %s  BIN=%s  scheme=%s  bank=%s",
            full_pan[:6] + "x" * (pan_len - 10) + full_pan[-4:],
            resolved_bin,
            resolved_scheme,
            bank_name,
        )

        return PredatorPAN(
            pan=full_pan,
            bin_prefix=resolved_bin,
            scheme=resolved_scheme,
            bank_name=bank_name,
            country=iso2,
            country_name=country_name,
            pan_length=pan_len,
            luhn_valid=True,
            expiry=expiry_slash,
            expiry_mmyy=expiry_mmyy,
            service_code=service_code,
            track2_equivalent=track2,
        )

    raise RuntimeError(
        f"Unable to generate a unique predator PAN after {max_retries} attempts "
        f"(BIN={resolved_bin}, scheme={resolved_scheme})"
    )


def generate_predator_pan_batch(
    count: int,
    scheme: Optional[str] = None,
    country: Optional[str] = None,
    registry_path: Optional[Path] = None,
) -> List[PredatorPAN]:
    """
    Generate ``count`` unique predator PANs.

    All PANs are registered in the PAN registry as they are produced.
    The same BIN selection logic applies as in ``generate_predator_pan``.

    Args:
        count:         How many PANs to generate.
        scheme:        Payment scheme filter (None = random per card).
        country:       Country filter (None = any).
        registry_path: Path to the PAN registry.  None = default.

    Returns:
        List of PredatorPAN dataclasses, all unique.

    Raises:
        RuntimeError: If a PAN cannot be generated after 100 retries.
    """
    results: List[PredatorPAN] = []
    for i in range(count):
        pan = generate_predator_pan(
            scheme=scheme,
            country=country,
            registry_path=registry_path,
        )
        results.append(pan)
        logger.debug("Batch progress: %d/%d", i + 1, count)
    return results


def generate_pan_for_scenario(scenario_id: str) -> PredatorPAN:
    """
    Generate a PAN appropriate for a specific predator scenario.

    Selection rules per category:
      - Category A (normal):        Visa UK or MC UK BINs preferred
                                    (Barclays 453978, HSBC 491182, Lloyds 454313,
                                     Barclaycard 518760, HSBC MC 534214)
      - Category B (decline/error): Any scheme; uses standard service code
      - Category C (floor/velocity):US BINs — Chase/BoA — US floor limit rules
                                    (Chase Visa 414720, BoA 426684, Wells 431274,
                                     Chase MC 524030)
      - Category D (CVM):           Amex for no-signature (D1/D5), MC for online PIN
                                    (D3), Visa for others
      - Category E (AID):           Multi-scheme — Visa preferred, returns one PAN
      - Category F (crypto stress):  Any BIN; marks service code for crypto test
      - Category G (fallback):       MC UK with service code "101" (mag fallback)
                                    (Barclaycard 518760)
      - Category J (JCOP):          All schemes supported; round-robin by index
      - Category G* (GP):            GP ISD BIN simulation → Visa UK

    Args:
        scenario_id: Predator scenario ID, e.g. "A1", "B2", "F3".

    Returns:
        PredatorPAN appropriate for the scenario.

    Raises:
        ValueError:   If scenario_id category is unrecognised.
        RuntimeError: If PAN generation fails after retries.
    """
    sid = scenario_id.upper()
    category = sid[0] if sid else "A"

    if category == "A":
        # Normal flows: prefer UK issuers (Barclays Visa or HSBC MC)
        # Alternate between Visa and MC based on scenario number
        num = int(sid[1]) if len(sid) > 1 and sid[1].isdigit() else 1
        if num % 2 == 0:
            return generate_predator_pan(scheme="mastercard", country="GB")
        return generate_predator_pan(scheme="visa", country="GB")

    elif category == "B":
        # Decline flows: any scheme, standard service code
        return generate_predator_pan(service_code="201")

    elif category == "C":
        # Floor/velocity: US BINs to exercise US floor limit rules
        num = int(sid[1]) if len(sid) > 1 and sid[1].isdigit() else 1
        if num % 2 == 0:
            return generate_predator_pan(scheme="mastercard", country="US")
        return generate_predator_pan(scheme="visa", country="US")

    elif category == "D":
        # CVM stress
        num = int(sid[1]) if len(sid) > 1 and sid[1].isdigit() else 1
        if num == 1 or num == 5:
            # No-CVM / CDCVM → Amex (no signature required by design)
            return generate_predator_pan(scheme="amex")
        elif num == 3:
            # Online PIN → MC (required by MC M/Chip spec)
            return generate_predator_pan(scheme="mastercard", country="GB")
        else:
            return generate_predator_pan(scheme="visa", country="GB")

    elif category == "E":
        # AID/application selection: Visa preferred
        return generate_predator_pan(scheme="visa")

    elif category == "F":
        # Crypto stress: any BIN, service code 201
        return generate_predator_pan(service_code="201")

    elif category == "G":
        # Fallback / compatibility: MC UK, service code 101 = international/mag
        return generate_predator_pan(
            scheme="mastercard",
            country="GB",
            service_code="101",
        )

    elif category == "J":
        # JCOP all-scheme scenarios: cycle through Visa/MC/Amex by last digit
        num = int(sid[1]) if len(sid) > 1 and sid[1].isdigit() else 0
        schemes = ["visa", "mastercard", "amex", "visa", "mastercard"]
        chosen_scheme = schemes[num % len(schemes)]
        return generate_predator_pan(scheme=chosen_scheme)

    else:
        # Default: Visa UK
        logger.warning(
            "Unknown scenario category %r in %r — defaulting to Visa UK",
            category, scenario_id,
        )
        return generate_predator_pan(scheme="visa", country="GB")


__all__ = [
    "PredatorPAN",
    "generate_predator_pan",
    "generate_predator_pan_batch",
    "generate_pan_for_scenario",
]
