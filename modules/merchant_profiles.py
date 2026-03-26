"""
modules/merchant_profiles.py
─────────────────────────────────────────────────────────────────────────────
GREENWIRE — Merchant POS Terminal Emulator Profiles
Two fully-configured merchant profiles with complete transaction simulation:
  • Tesco UK  — Barclaycard acquiring, Verifone VX820, GBP, Chip+PIN
  • TJ Maxx US — Chase Paymentech acquiring, Ingenico iCT220, USD, Chip+Sig

Each profile encodes the per-merchant rules that govern how real POS terminals
behave: floor limits, CVM policy, acquirer routing, accepted schemes, and the
country-specific quirks that make UK and US terminals behave very differently.
─────────────────────────────────────────────────────────────────────────────

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
UK vs US CVM (Cardholder Verification Method) DIFFERENCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The UK and US have fundamentally different cardholder verification cultures:

UK (Chip & PIN):
  • Signature was removed as an accepted CVM for UK card payments in February
    2006, when the entire UK payment industry completed its migration to EMV
    Chip & PIN. Since then, UK-issued cards do not carry a signature strip as
    a usable verification method. Terminals set TVR bit "CVM not successful"
    if a signature CVM is attempted. If the card's CVMR only lists signature,
    a UK terminal will decline — it will NOT fall back and accept the sig.
  • UK terminals mandate Online PIN above the contactless CVM limit.
  • CDCVM (Consumer Device CVM — e.g. Face ID / fingerprint on a phone) is
    accepted for contactless transactions via Apple Pay and Google Pay.

US (Chip & Signature):
  • The US completed its EMV migration on 1 October 2015 (liability shift),
    but chose to adopt Chip + Signature rather than Chip + PIN for credit
    transactions. This was a deliberate choice by US issuers who argued that
    PIN does not prevent card-not-present fraud (the dominant US fraud vector)
    and that US consumers were trained on signature.
  • PIN IS required for US debit transactions (regulated by Regulation E).
  • No-CVM is allowed below $25 for contactless (raised to $100 floor in 2020).
  • Many US terminals still accept mag-stripe fallback, though liability for
    fraudulent mag-stripe transactions now falls on the merchant (post-shift).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
UK CONTACTLESS LIMIT HISTORY — £30 → £45 → £100
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The UK contactless Payment Industry Limit (CPIL) has been raised twice:

  • 2007–2012 : £10  — initial limit when contactless was introduced in the UK
  • 2012–2015 : £20  — raised by UK Cards Association
  • 2015–2020 : £30  — raised April 2015
  • Sep 2021   : £45  — temporary raise during COVID-19 pandemic (April 2020),
                        then made permanent in September 2020
  • Oct 2021   : £100 — raised to £100 on 15 October 2021, following the
                        EU's revised PSD2 Strong Customer Authentication rules
                        which set a €150 (~£130) single-transaction limit.
                        The UK retained a tighter £100 limit post-Brexit.

Tesco raised its contactless limit to £100 on 15 October 2021 across all
UK stores. The CDCVM (phone/watch authentication) removes this limit entirely
for Apple Pay, Google Pay, and Samsung Pay transactions.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
US EMV LIABILITY SHIFT — OCTOBER 2015
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
On 1 October 2015, the four major US card networks (Visa, Mastercard,
Discover, Amex) shifted liability for counterfeit card fraud:

  Before shift: Issuer absorbs counterfeit card losses.
  After  shift: If the merchant does not have an EMV-capable terminal, and a
                fraudulent transaction is made using a counterfeit EMV card
                (with a mag-stripe fallback), the MERCHANT is liable.

This created a strong economic incentive for US retailers to install chip
readers. TJ Maxx/TJX was notably involved in the largest pre-EMV US data
breach (2007, ~94 million cards compromised via mag-stripe skimming).
Despite this history, TJX still allows mag-stripe fallback for operational
reasons — older cards and non-EMV cards remain in circulation.

Automated Fuel Dispensers (gas pumps) had their shift delayed to April 2021
(contact) and October 2020 (contactless). ATMs had their shift in October 2016
for Mastercard and October 2017 for Visa.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BARCLAYCARD vs CHASE PAYMENTECH — ACQUIRER ROUTING DIFFERENCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Barclaycard Merchant Services (UK):
  • Operates on the Barclays Payment Network (BPN), connecting to Visa EU
    and Mastercard EU via the UK Faster Payments and CHAPS infrastructure.
  • Acquirer BIN: 676703 (Barclaycard acquiring BIN range)
  • Uses ISO 8583:1993 message format over private leased lines and VPN.
  • Settlement: T+1 business days into the merchant's Barclays current account.
  • Tesco has a dedicated acquiring agreement with guaranteed interchange rates
    due to transaction volume (Tesco processes ~6M card transactions/day UK).
  • Contactless: routed via Visa payWave / MC PayPass / Amex ExpressPay.
  • Authorisation host: Barclaycard's data centres (Northampton + DR site).

Chase Paymentech (US):
  • One of the largest US acquirers, formerly known as Paymentech (joint
    venture of First Data and Bank One, acquired by JPMorgan Chase 2005).
  • Operates on the Chase Paymentech Network, connecting to Visa Net,
    Banknet (Mastercard), and the Federal Reserve ACH network.
  • Uses ISO 8583:2003 message format.
  • Settlement: T+2 for most merchants; T+1 negotiated for large retailers.
  • Dual-message processing: authorisation and capture are separate messages,
    allowing TJ Maxx to authorise at point of sale and capture at batch close.
  • Debit routing: Chase Paymentech supports PIN debit via interbank networks
    (STAR, NYCE, Pulse) — the merchant's terminal selects the cheapest route
    (Durbin Amendment, 2011: debit routing choice required by law for merchants).
"""

from __future__ import annotations

import logging
import random
import string
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# ISO CODE REFERENCE CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# ISO 4217 numeric currency codes
ISO4217_GBP = 826   # British Pound Sterling
ISO4217_USD = 840   # US Dollar

# ISO 3166-1 numeric country codes
ISO3166_GB = 826    # United Kingdom of Great Britain and Northern Ireland
ISO3166_US = 840    # United States of America

# ISO 18245 Merchant Category Codes
MCC_GROCERY_SUPERMARKET = "5411"      # Grocery Stores, Supermarkets
MCC_WOMENS_CLOTHING = "5621"          # Women's Ready-to-Wear Stores
MCC_MISC_GENERAL_RETAIL = "5999"      # Miscellaneous and Specialty Retail

# EMV response codes (ISO 8583 field 39)
RESPONSE_APPROVED = "00"
RESPONSE_REFER_TO_ISSUER = "01"
RESPONSE_DECLINED = "05"
RESPONSE_INVALID_TRANSACTION = "12"
RESPONSE_INVALID_AMOUNT = "13"
RESPONSE_CASHBACK_NOT_AVAILABLE = "57"   # Not standard but used in simulation
RESPONSE_EXCEEDS_LIMIT = "61"
RESPONSE_RESTRICTED_CARD = "62"
RESPONSE_PIN_TRIES_EXCEEDED = "75"
RESPONSE_WRONG_PIN = "55"
RESPONSE_CARD_NOT_ACCEPTED = "57"

# CVM (Cardholder Verification Method) identifiers
CVM_NO_CVM = "NO_CVM"
CVM_SIGNATURE = "SIGNATURE"
CVM_OFFLINE_PIN = "OFFLINE_PIN"
CVM_ONLINE_PIN = "ONLINE_PIN"
CVM_CDCVM = "CDCVM"       # Consumer Device CVM (mobile/wearable wallet)


# ─────────────────────────────────────────────────────────────────────────────
# MerchantProfile dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MerchantProfile:
    """
    Complete merchant terminal configuration.

    This encodes all the per-merchant rules that affect how a POS terminal
    processes EMV transactions — floor limits, CVM policies, acquirer routing,
    accepted schemes, currency, and country-specific quirks.

    All monetary amounts are stored in the currency's minor unit (pence for
    GBP, cents for USD) to avoid floating-point rounding errors — a critical
    requirement for financial applications.

    Attributes:
        merchant_name:           Human-readable merchant name (appears on receipt).
        merchant_id:             Acquirer-assigned merchant identifier (up to 15 chars).
        terminal_id:             Physical terminal identifier (acquirer-assigned).
        acquirer_name:           Name of the acquiring bank/processor.
        acquirer_bin:            BIN (Bank Identification Number) of the acquirer.
        mcc:                     ISO 18245 Merchant Category Code (4 digits, as str).
        currency_code:           ISO 4217 numeric currency code (int).
        currency_symbol:         Symbol for display, e.g. "£" or "$".
        country_code:            ISO 3166-1 numeric country code (int).
        country_name:            Full country name.
        contactless_limit_minor: Max contactless no-CVM amount (minor units).
        floor_limit_minor:       Transactions above this require online authorisation.
        cvm_above_limit:         CVM required above contactless_limit_minor.
        cvm_below_limit:         CVM used below contactless_limit_minor.
        signature_accepted:      UK = False (removed 2006), US = True.
        mag_stripe_fallback:     Whether mag-stripe fallback is permitted.
        cashback_available:      Whether cashback can be added to a transaction.
        cashback_max_minor:      Maximum cashback amount (minor units); 0 if N/A.
        accepted_schemes:        List of card scheme names this terminal accepts.
        terminal_hardware:       Description of physical terminal hardware.
        receipt_header:          Multi-line text for top of printed receipt.
        receipt_footer:          Multi-line text for bottom of printed receipt.
        extra_fields:            Merchant-specific additional configuration.
    """

    merchant_name: str
    merchant_id: str
    terminal_id: str
    acquirer_name: str
    acquirer_bin: str
    mcc: str                       # ISO 18245 Merchant Category Code
    currency_code: int             # ISO 4217 numeric
    currency_symbol: str           # e.g. "£" or "$"
    country_code: int              # ISO 3166-1 numeric
    country_name: str
    contactless_limit_minor: int   # minor units (pence or cents)
    floor_limit_minor: int         # online auth required above this
    cvm_above_limit: str           # "ONLINE_PIN" / "SIGNATURE" / "PIN_OR_SIGNATURE"
    cvm_below_limit: str           # "NO_CVM" or "CDCVM"
    signature_accepted: bool       # UK = False, US credit = True
    mag_stripe_fallback: bool
    cashback_available: bool
    cashback_max_minor: int
    accepted_schemes: List[str]
    terminal_hardware: str
    receipt_header: str
    receipt_footer: str
    extra_fields: Dict[str, str] = field(default_factory=dict)

    def format_amount(self, minor: int) -> str:
        """
        Format a minor-unit amount as a human-readable string with currency symbol.

        For example, 2350 pence → "£23.50", 4799 cents → "$47.99".

        Args:
            minor: Amount in minor units (pence / cents).

        Returns:
            Formatted string, e.g. "£23.50".
        """
        major = minor // 100
        frac = minor % 100
        return f"{self.currency_symbol}{major}.{frac:02d}"

    def accepts_scheme(self, scheme: str) -> bool:
        """
        Check whether this terminal accepts the given card scheme.

        Args:
            scheme: Card scheme name (case-insensitive), e.g. "visa", "MASTERCARD".

        Returns:
            True if the scheme is in accepted_schemes.
        """
        result = scheme.upper() in [s.upper() for s in self.accepted_schemes]
        if result:
            logger.debug("[%s] Scheme '%s' accepted.", self.merchant_name, scheme)
        else:
            logger.warning("[%s] Scheme '%s' NOT in accepted list %s.",
                           self.merchant_name, scheme, self.accepted_schemes)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# MerchantTerminalEmulator
# ─────────────────────────────────────────────────────────────────────────────

class MerchantTerminalEmulator:
    """
    Simulates the full transaction flow of a POS terminal configured with a
    given MerchantProfile.

    This class models the decision logic embedded in a real EMV terminal:
    - Floor limit checks (online vs offline authorisation)
    - CVM (Cardholder Verification Method) selection
    - Contactless vs contact entry modes
    - Cashback validation
    - Refund / void authorisation rules
    - Receipt generation
    - Batch close (end-of-day settlement trigger)

    All amounts are handled in minor currency units to avoid floating-point
    errors. Conversion to display strings is done only at the presentation
    layer (receipt generation, log messages).
    """

    def __init__(self, profile: MerchantProfile) -> None:
        """
        Initialise the emulator with a MerchantProfile.

        Args:
            profile: The MerchantProfile that configures this terminal instance.
        """
        self.profile = profile
        self._transaction_log: List[dict] = []
        self._batch_total_minor: int = 0
        self._batch_count: int = 0
        self._powered_on: bool = False
        self._pin_tries: Dict[str, int] = {}  # PAN → consecutive wrong PIN count
        logger.info("[%s] Terminal emulator initialised. TID=%s MID=%s",
                    profile.merchant_name, profile.terminal_id, profile.merchant_id)

    # ─── Terminal lifecycle ───────────────────────────────────────────────────

    def power_on(self) -> str:
        """
        Simulate terminal power-on / boot sequence.

        In a real Verifone VX820 or Ingenico iCT220 this sequence contacts the
        acquirer host to confirm the terminal is registered, downloads parameter
        updates, and displays the idle screen.

        Returns:
            A multi-line string representing the terminal's idle display.
        """
        self._powered_on = True
        p = self.profile
        display = (
            f"{'─' * 32}\n"
            f"  {p.merchant_name}\n"
            f"  TID: {p.terminal_id}   MID: {p.merchant_id}\n"
            f"  {p.acquirer_name}\n"
            f"  {p.terminal_hardware}\n"
            f"  {datetime.now().strftime('%d %b %Y  %H:%M:%S')}\n"
            f"{'─' * 32}\n"
            f"  WELCOME — INSERT/TAP CARD\n"
            f"{'─' * 32}"
        )
        logger.info("[%s] Terminal powered on. TID=%s", p.merchant_name, p.terminal_id)
        return display

    # ─── Amount entry ─────────────────────────────────────────────────────────

    def enter_amount(self, amount_minor: int,
                     currency_override: Optional[int] = None) -> bool:
        """
        Validate a transaction amount entered by the cashier.

        Checks that the amount is positive and that the currency matches the
        terminal's configured currency (unless overridden for DCC scenarios).

        Args:
            amount_minor:      Purchase amount in minor units (pence / cents).
            currency_override: If provided, use this ISO 4217 code instead of
                               the profile default (used for DCC).

        Returns:
            True if the amount is valid and accepted; False otherwise.
        """
        currency = currency_override or self.profile.currency_code
        if amount_minor <= 0:
            logger.warning("[%s] Invalid amount %d (must be > 0).",
                           self.profile.merchant_name, amount_minor)
            return False
        if currency != self.profile.currency_code and currency_override is None:
            logger.warning("[%s] Currency mismatch: got %d, expected %d.",
                           self.profile.merchant_name, currency,
                           self.profile.currency_code)
            return False
        logger.info("[%s] Amount entered: %s",
                    self.profile.merchant_name,
                    self.profile.format_amount(amount_minor))
        return True

    # ─── Card presentation ────────────────────────────────────────────────────

    def present_card(self, pan: str, contactless: bool = True) -> dict:
        """
        Simulate card presentation to the terminal.

        Validates that the card's scheme is accepted by this terminal and that
        the card has not exceeded its PIN retry limit. Returns a dict with card
        details used in subsequent transaction steps.

        Args:
            pan:         Primary Account Number (PAN), at least 6 digits.
            contactless: True for NFC tap; False for contact chip or swipe.

        Returns:
            A dict with keys:
              - accepted (bool)
              - scheme (str)
              - entry_mode (str): "CONTACTLESS", "CHIP", or "MAGSTRIPE"
              - masked_pan (str)
              - error (str | None)
        """
        if len(pan) < 6:
            logger.warning("[%s] PAN too short: '%s'", self.profile.merchant_name, pan)
            return {"accepted": False, "error": "INVALID_PAN"}

        # Derive scheme from BIN (first 1–2 digits)
        scheme = self._derive_scheme(pan)
        logger.info("[%s] Card presented. Scheme=%s entry=%s PAN=****%s",
                    self.profile.merchant_name, scheme,
                    "CONTACTLESS" if contactless else "CONTACT", pan[-4:])

        if not self.profile.accepts_scheme(scheme):
            return {"accepted": False, "scheme": scheme,
                    "error": "SCHEME_NOT_ACCEPTED"}

        if self._pin_tries.get(pan, 0) >= 3:
            logger.warning("[%s] PAN ****%s blocked — PIN tries exceeded.",
                           self.profile.merchant_name, pan[-4:])
            return {"accepted": False, "scheme": scheme,
                    "error": "PIN_TRIES_EXCEEDED"}

        entry_mode = "CONTACTLESS" if contactless else "CHIP"
        masked = "*" * (len(pan) - 4) + pan[-4:]
        return {
            "accepted": True,
            "scheme": scheme,
            "entry_mode": entry_mode,
            "masked_pan": masked,
            "error": None,
        }

    # ─── CVM selection ────────────────────────────────────────────────────────

    def determine_cvm(self, amount_minor: int, contactless: bool,
                      cdcvm_signalled: bool) -> str:
        """
        Determine the Cardholder Verification Method for this transaction.

        This implements the terminal-side CVM selection logic, which combines:
        - The merchant's configured CVM policy (profile.cvm_above_limit, etc.)
        - Whether the transaction is contactless or contact
        - Whether the device has already performed CDCVM (wallet authentication)
        - The UK rule: signature is NEVER accepted
        - The US rule: contactless below $25 may be no-CVM

        Args:
            amount_minor:     Transaction amount in minor units.
            contactless:      True if the card was tapped (NFC).
            cdcvm_signalled:  True if the wallet (Apple Pay etc.) has already
                              authenticated the cardholder biometrically.

        Returns:
            One of: CVM_NO_CVM, CVM_CDCVM, CVM_ONLINE_PIN, CVM_SIGNATURE,
            CVM_OFFLINE_PIN.
        """
        p = self.profile
        limit = p.contactless_limit_minor

        logger.debug("[%s] CVM check: amount=%s limit=%s contactless=%s cdcvm=%s",
                     p.merchant_name, p.format_amount(amount_minor),
                     p.format_amount(limit), contactless, cdcvm_signalled)

        # CDCVM (biometric device authentication) overrides all other CVM checks.
        # Apple Pay / Google Pay / Samsung Pay signal CDCVM in the kernel 2/3
        # CTLS data, which removes the need for any further cardholder verification.
        if cdcvm_signalled:
            logger.info("[%s] CVM=CDCVM — device wallet authentication accepted "
                        "(no amount limit applies).", p.merchant_name)
            return CVM_CDCVM

        if contactless:
            if amount_minor <= limit:
                # Below the contactless limit: use the profile's below-limit CVM.
                # UK: this will be NO_CVM for standard contactless.
                # US: NO_CVM below $25, otherwise profile cvm_below_limit.
                cvm = p.cvm_below_limit
                logger.info("[%s] CVM=%s — contactless below limit (%s ≤ %s).",
                            p.merchant_name, cvm,
                            p.format_amount(amount_minor), p.format_amount(limit))
                return cvm
            else:
                # Above the contactless limit: the cardholder must insert and
                # use the chip. The CVM applied is the contact CVM.
                cvm = p.cvm_above_limit
                # UK-specific rule: signature is never acceptable, even if the
                # card's CVMR lists it. The terminal must decline or force PIN.
                if cvm == CVM_SIGNATURE and not p.signature_accepted:
                    logger.warning(
                        "[%s] CVM requested SIGNATURE but signature_accepted=False "
                        "(UK rule: signature removed 2006). Forcing ONLINE_PIN.",
                        p.merchant_name)
                    cvm = CVM_ONLINE_PIN
                logger.info("[%s] CVM=%s — amount %s exceeds contactless limit %s.",
                            p.merchant_name, cvm,
                            p.format_amount(amount_minor), p.format_amount(limit))
                return cvm
        else:
            # Contact (chip) transaction: apply the above-limit CVM regardless
            # of amount, because the cardholder has already inserted the card.
            cvm = p.cvm_above_limit
            if cvm == CVM_SIGNATURE and not p.signature_accepted:
                logger.warning(
                    "[%s] Contact chip: SIGNATURE not accepted (UK rule). "
                    "Forcing ONLINE_PIN.", p.merchant_name)
                cvm = CVM_ONLINE_PIN
            logger.info("[%s] CVM=%s — contact chip transaction.", p.merchant_name, cvm)
            return cvm

    # ─── Full transaction processing ─────────────────────────────────────────

    def process_transaction(self, amount_minor: int, pan: str,
                            contactless: bool = True,
                            predator_scenario: Optional[str] = None) -> dict:
        """
        Simulate a complete purchase transaction from card presentation to receipt.

        This models the full EMV transaction flow:
        1. Terminal power-on check
        2. Amount validation
        3. Card presentation and scheme check
        4. CVM determination
        5. Floor limit check → online vs offline authorisation
        6. Approval or decline simulation
        7. Batch total update
        8. Receipt generation

        The optional predator_scenario parameter allows GREENWIRE fuzzing
        sessions to inject specific test scenarios (e.g. "force_decline",
        "wrong_pin", "exceed_contactless_limit") for security testing.

        Args:
            amount_minor:       Purchase amount in minor units.
            pan:                Primary Account Number string.
            contactless:        True for NFC tap, False for chip/swipe.
            predator_scenario:  Optional GREENWIRE test scenario override.

        Returns:
            A dict with keys:
              - success (bool)
              - approval_code (str | None)
              - response_code (str)
              - cvm_applied (str)
              - authorisation_type (str): "ONLINE" or "OFFLINE"
              - amount_minor (int)
              - amount_display (str)
              - scheme (str)
              - entry_mode (str)
              - txn_id (str)
              - timestamp (str)
              - receipt (str)
              - error (str | None)
        """
        p = self.profile
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        txn_id = _generate_txn_id()

        logger.info("[%s] ── BEGIN TRANSACTION txn_id=%s amount=%s ──",
                    p.merchant_name, txn_id, p.format_amount(amount_minor))

        # Step 1 – power-on guard
        if not self._powered_on:
            self.power_on()

        # Step 2 – amount validation
        if not self.enter_amount(amount_minor):
            return _declined_result(txn_id, timestamp, RESPONSE_INVALID_AMOUNT,
                                    p.format_amount(amount_minor),
                                    "INVALID_AMOUNT")

        # Step 3 – card presentation
        card = self.present_card(pan, contactless)
        if not card["accepted"]:
            return _declined_result(txn_id, timestamp, RESPONSE_RESTRICTED_CARD,
                                    p.format_amount(amount_minor),
                                    card.get("error", "CARD_REJECTED"))

        scheme = card["scheme"]
        entry_mode = card["entry_mode"]

        # Step 4 – CVM selection
        # cdcvm_signalled is True when the wallet (Apple Pay etc.) indicates
        # the cardholder was authenticated by biometric on their device.
        cdcvm_signalled = (predator_scenario == "cdcvm_wallet")
        cvm = self.determine_cvm(amount_minor, contactless, cdcvm_signalled)

        # Simulate wrong-PIN scenario for fuzzing / test purposes
        if predator_scenario == "wrong_pin" and cvm in (CVM_ONLINE_PIN, CVM_OFFLINE_PIN):
            self._pin_tries[pan] = self._pin_tries.get(pan, 0) + 1
            tries_left = 3 - self._pin_tries[pan]
            logger.warning("[%s] Wrong PIN entered. Attempts left: %d",
                           p.merchant_name, tries_left)
            if tries_left <= 0:
                return _declined_result(txn_id, timestamp,
                                        RESPONSE_PIN_TRIES_EXCEEDED,
                                        p.format_amount(amount_minor),
                                        "PIN_TRIES_EXCEEDED")
            return _declined_result(txn_id, timestamp, RESPONSE_WRONG_PIN,
                                    p.format_amount(amount_minor), "WRONG_PIN")

        # Step 5 – floor limit check (determines online vs offline path)
        # Above the floor limit → MUST go online (live auth from issuer).
        # Below the floor limit → OFFLINE approval is permitted.
        #
        # Note: UK contactless transactions above the contactless limit
        # require the card to be inserted and a new contact authorisation
        # performed, so they always go online.
        if amount_minor > p.floor_limit_minor:
            auth_type = "ONLINE"
            logger.info("[%s] Amount %s > floor limit %s → ONLINE authorisation.",
                        p.merchant_name, p.format_amount(amount_minor),
                        p.format_amount(p.floor_limit_minor))
        else:
            auth_type = "OFFLINE"
            logger.info("[%s] Amount %s ≤ floor limit %s → OFFLINE approval.",
                        p.merchant_name, p.format_amount(amount_minor),
                        p.format_amount(p.floor_limit_minor))

        # Step 6 – approval simulation
        if predator_scenario == "force_decline":
            response_code = RESPONSE_DECLINED
            approval_code = None
            success = False
            logger.info("[%s] predator_scenario=force_decline → DECLINED.", p.merchant_name)
        elif predator_scenario == "exceed_contactless_limit" and contactless and amount_minor > p.contactless_limit_minor:
            # Terminal should have caught this in CVM; if somehow reached, decline
            response_code = RESPONSE_EXCEEDS_LIMIT
            approval_code = None
            success = False
            logger.warning("[%s] Contactless amount %s exceeds limit %s. DECLINED.",
                           p.merchant_name, p.format_amount(amount_minor),
                           p.format_amount(p.contactless_limit_minor))
        else:
            response_code = RESPONSE_APPROVED
            approval_code = _generate_approval_code()
            success = True
            logger.info("[%s] Transaction APPROVED. auth_code=%s", p.merchant_name, approval_code)

        # Step 7 – update batch totals (only for approvals)
        if success:
            self._batch_total_minor += amount_minor
            self._batch_count += 1
            self._pin_tries.pop(pan, None)  # Reset PIN try counter on success

        txn = {
            "success": success,
            "approval_code": approval_code,
            "response_code": response_code,
            "cvm_applied": cvm,
            "authorisation_type": auth_type,
            "amount_minor": amount_minor,
            "amount_display": p.format_amount(amount_minor),
            "scheme": scheme,
            "entry_mode": entry_mode,
            "masked_pan": card["masked_pan"],
            "txn_id": txn_id,
            "timestamp": timestamp,
            "merchant_name": p.merchant_name,
            "terminal_id": p.terminal_id,
            "merchant_id": p.merchant_id,
            "error": None if success else response_code,
        }
        self._transaction_log.append(txn)

        # Step 8 – receipt
        txn["receipt"] = self.generate_receipt(txn)

        logger.info("[%s] ── END TRANSACTION txn_id=%s result=%s ──",
                    p.merchant_name, txn_id, "APPROVED" if success else "DECLINED")
        return txn

    # ─── Receipt generation ───────────────────────────────────────────────────

    def generate_receipt(self, txn: dict) -> str:
        """
        Generate a formatted receipt string for a completed transaction.

        Reproduces the layout used by Verifone VX820 (Tesco) and Ingenico
        iCT220 (TJ Maxx) paper receipts, including merchant header, card
        details, CVM confirmation line, and acquirer footer.

        Args:
            txn: Transaction result dict as returned by process_transaction().

        Returns:
            Multi-line string representing the printed receipt.
        """
        p = self.profile
        w = 32  # receipt width in chars (standard thermal roll)
        line = "─" * w

        status = "** APPROVED **" if txn["success"] else "** DECLINED **"
        cvm_line = {
            CVM_NO_CVM: "NO VERIFICATION REQUIRED",
            CVM_CDCVM: "VERIFIED BY DEVICE",
            CVM_ONLINE_PIN: "PIN VERIFIED",
            CVM_OFFLINE_PIN: "PIN VERIFIED (OFFLINE)",
            CVM_SIGNATURE: "PLEASE SIGN BELOW",
        }.get(txn.get("cvm_applied", ""), "CARDHOLDER VERIFIED")

        lines = [
            p.receipt_header,
            line,
            f"DATE: {txn['timestamp'][:10]}  {txn['timestamp'][11:16]}",
            f"TXN:  {txn['txn_id']}",
            f"TID:  {p.terminal_id}",
            f"MID:  {p.merchant_id}",
            line,
            f"CARD: {txn.get('masked_pan', '************')}",
            f"MODE: {txn.get('entry_mode', 'CHIP')} / {txn.get('scheme', 'UNKNOWN')}",
            f"CVM:  {cvm_line}",
            line,
            f"AMOUNT: {txn['amount_display'].rjust(w - 8)}",
        ]

        if txn["success"]:
            lines += [
                f"AUTH: {txn['approval_code']}",
                "",
                status,
            ]
        else:
            lines += ["", status, f"CODE: {txn.get('response_code', 'XX')}"]

        # Tesco-specific: Clubcard number line
        if p.extra_fields.get("clubcard_prompt"):
            lines.append(f"\n{p.extra_fields['clubcard_prompt']}")

        # TJ Maxx-specific: signature line for credit
        if txn.get("cvm_applied") == CVM_SIGNATURE and p.signature_accepted:
            lines += ["", "X _______________________________", "CARDHOLDER SIGNATURE"]

        lines += [line, p.receipt_footer]
        return "\n".join(lines)

    # ─── Refund processing ────────────────────────────────────────────────────

    def process_refund(self, amount_minor: int, auth_code: str,
                       manager_auth: bool = False) -> dict:
        """
        Process a refund / return transaction.

        For Tesco UK, refunds require a manager card authorisation (simulated
        by the manager_auth flag). For TJ Maxx US, refunds can be processed
        by any cashier but require the original transaction reference.

        Partial refunds are supported. The amount must not exceed the original
        transaction amount, but this emulator does not track original amounts —
        it trusts the auth_code reference.

        Args:
            amount_minor:  Refund amount in minor units.
            auth_code:     Original transaction authorisation code.
            manager_auth:  Whether manager authorisation has been provided.
                           Required for Tesco UK; ignored for TJ Maxx US.

        Returns:
            Dict with success, response_code, refund_amount_display, message.
        """
        p = self.profile
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # UK rule: manager card required for all refunds at Tesco
        if p.extra_fields.get("refund_requires_manager") == "true" and not manager_auth:
            logger.warning("[%s] Refund REJECTED — manager authorisation required.",
                           p.merchant_name)
            return {
                "success": False,
                "response_code": RESPONSE_DECLINED,
                "refund_amount_display": p.format_amount(amount_minor),
                "message": "MANAGER AUTHORISATION REQUIRED FOR REFUNDS",
                "timestamp": timestamp,
            }

        if amount_minor <= 0:
            return {
                "success": False,
                "response_code": RESPONSE_INVALID_AMOUNT,
                "refund_amount_display": p.format_amount(amount_minor),
                "message": "INVALID REFUND AMOUNT",
                "timestamp": timestamp,
            }

        # Deduct from batch total (refunds reduce settlement amount)
        self._batch_total_minor -= amount_minor
        self._batch_count += 1
        logger.info("[%s] Refund APPROVED. auth_ref=%s amount=%s",
                    p.merchant_name, auth_code, p.format_amount(amount_minor))
        return {
            "success": True,
            "response_code": RESPONSE_APPROVED,
            "refund_amount_display": p.format_amount(amount_minor),
            "original_auth_code": auth_code,
            "message": "REFUND APPROVED",
            "timestamp": timestamp,
        }

    # ─── Cashback processing ──────────────────────────────────────────────────

    def process_cashback(self, purchase_minor: int, cashback_minor: int) -> dict:
        """
        Process a purchase-with-cashback transaction.

        Cashback is an add-on to a debit purchase where the cardholder
        receives physical cash from the merchant's till. Only available on
        debit transactions via PIN-authenticated card entry.

        Tesco UK does NOT offer cashback at checkouts (policy decision).
        TJ Maxx US supports cashback on debit transactions up to $40.

        Args:
            purchase_minor:  Goods purchase amount in minor units.
            cashback_minor:  Requested cashback amount in minor units.

        Returns:
            Dict with success, total_amount_display, response_code, message.
        """
        p = self.profile
        total_minor = purchase_minor + cashback_minor

        if not p.cashback_available:
            logger.warning("[%s] Cashback requested but not available at this terminal.",
                           p.merchant_name)
            return {
                "success": False,
                "response_code": RESPONSE_CASHBACK_NOT_AVAILABLE,
                "total_amount_display": p.format_amount(total_minor),
                "message": f"CASHBACK NOT AVAILABLE AT {p.merchant_name.upper()}",
            }

        if cashback_minor > p.cashback_max_minor:
            logger.warning("[%s] Cashback %s exceeds maximum %s.",
                           p.merchant_name, p.format_amount(cashback_minor),
                           p.format_amount(p.cashback_max_minor))
            return {
                "success": False,
                "response_code": RESPONSE_EXCEEDS_LIMIT,
                "total_amount_display": p.format_amount(total_minor),
                "message": f"CASHBACK MAX {p.format_amount(p.cashback_max_minor)}",
            }

        if cashback_minor <= 0 or purchase_minor <= 0:
            return {
                "success": False,
                "response_code": RESPONSE_INVALID_AMOUNT,
                "total_amount_display": p.format_amount(total_minor),
                "message": "INVALID CASHBACK/PURCHASE AMOUNT",
            }

        logger.info("[%s] Cashback transaction: purchase=%s cashback=%s total=%s",
                    p.merchant_name, p.format_amount(purchase_minor),
                    p.format_amount(cashback_minor), p.format_amount(total_minor))

        return {
            "success": True,
            "response_code": RESPONSE_APPROVED,
            "purchase_display": p.format_amount(purchase_minor),
            "cashback_display": p.format_amount(cashback_minor),
            "total_amount_display": p.format_amount(total_minor),
            "message": f"CASHBACK {p.format_amount(cashback_minor)} APPROVED",
        }

    # ─── Batch close ──────────────────────────────────────────────────────────

    def batch_close(self) -> dict:
        """
        Perform end-of-day batch close / settlement.

        In a real terminal this transmits all authorised transactions to the
        acquirer host for settlement. The host responds with a batch summary
        and the terminal prints an end-of-day report.

        For Barclaycard (Tesco): settlement at 23:00 UK time automatically.
        For Chase Paymentech (TJ Maxx): merchant initiates batch close at
        store close, triggering dual-message capture for all pre-authorised
        transactions.

        Returns:
            Dict with batch_count, batch_total_display, settlement_reference,
            settlement_timestamp.
        """
        p = self.profile
        settlement_ref = _generate_approval_code()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        logger.info("[%s] BATCH CLOSE initiated. count=%d total=%s ref=%s",
                    p.merchant_name, self._batch_count,
                    p.format_amount(self._batch_total_minor), settlement_ref)

        summary = {
            "batch_count": self._batch_count,
            "batch_total_minor": self._batch_total_minor,
            "batch_total_display": p.format_amount(self._batch_total_minor),
            "settlement_reference": settlement_ref,
            "settlement_timestamp": timestamp,
            "acquirer": p.acquirer_name,
            "terminal_id": p.terminal_id,
            "merchant_id": p.merchant_id,
        }

        # Reset batch accumulators
        self._batch_total_minor = 0
        self._batch_count = 0
        self._transaction_log.clear()

        return summary

    # ─── Internal helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _derive_scheme(pan: str) -> str:
        """
        Heuristically derive the card scheme from the PAN BIN (first digits).

        This mimics the BIN table lookup performed by real terminals, which
        download scheme BIN ranges from the acquirer parameter file.

        Args:
            pan: PAN string (digits only, at least 1 character).

        Returns:
            Scheme name string: "VISA", "MASTERCARD", "AMEX", "DISCOVER",
            "UNIONPAY", "DINERS", or "UNKNOWN".
        """
        if pan.startswith("4"):
            return "VISA"
        if pan[:2] in ("51", "52", "53", "54", "55") or (
            2221 <= int(pan[:4]) <= 2720
        ):
            return "MASTERCARD"
        if pan[:2] in ("34", "37"):
            return "AMEX"
        if pan[:4] in ("6011", "6440", "6441", "6442", "6443") or pan[:2] == "65":
            return "DISCOVER"
        if pan[:2] == "62":
            return "UNIONPAY"
        if pan[:4] in ("3000", "3001", "3002", "3003", "3004", "3005") or pan[:2] in ("36", "38"):
            return "DINERS"
        return "UNKNOWN"


# ─────────────────────────────────────────────────────────────────────────────
# Internal utility functions
# ─────────────────────────────────────────────────────────────────────────────

def _generate_txn_id() -> str:
    """Generate a random 12-character alphanumeric transaction identifier."""
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=12))


def _generate_approval_code() -> str:
    """Generate a 6-character alphanumeric acquirer approval code."""
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def _declined_result(txn_id: str, timestamp: str, response_code: str,
                     amount_display: str, error: str) -> dict:
    """Build a standardised declined-transaction result dict."""
    return {
        "success": False,
        "approval_code": None,
        "response_code": response_code,
        "cvm_applied": None,
        "authorisation_type": None,
        "amount_minor": 0,
        "amount_display": amount_display,
        "scheme": None,
        "entry_mode": None,
        "masked_pan": None,
        "txn_id": txn_id,
        "timestamp": timestamp,
        "receipt": "",
        "error": error,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Factory functions — Tesco UK
# ─────────────────────────────────────────────────────────────────────────────

def get_tesco_uk_profile() -> MerchantProfile:
    """
    Return a fully-configured MerchantProfile for Tesco UK supermarket checkout.

    Configuration reflects Tesco's live UK checkout setup as of October 2021:
    - Barclaycard Merchant Services acquiring
    - Verifone VX820 with PIN pad (or iWL250 for contactless-only lanes)
    - £100 contactless limit (raised 15 October 2021, per UK CPIL)
    - Signature NOT accepted (UK removed signature CVM in February 2006)
    - MCC 5411 — Grocery Stores, Supermarkets
    - Currency GBP (ISO 4217 = 826)  Country GB (ISO 3166 = 826)
    - Cashback: NOT available at Tesco checkouts
    - Clubcard loyalty integration enabled

    Terminal ID format: "T" + 7 digits  (e.g. T0012345)
    Merchant ID format: 15 digits starting with 0022 (e.g. 002200001234567)

    Returns:
        MerchantProfile configured for Tesco UK.
    """
    return MerchantProfile(
        merchant_name="TESCO STORES LTD",
        merchant_id="002200001234567",           # 15-digit Barclaycard MID starting 0022
        terminal_id="T0012345",                  # "T" + 7 digits
        acquirer_name="Barclaycard Merchant Services",
        acquirer_bin="676703",                   # Barclaycard acquiring BIN
        mcc=MCC_GROCERY_SUPERMARKET,             # 5411 — Grocery Stores, Supermarkets
        currency_code=ISO4217_GBP,               # 826 — British Pound Sterling
        currency_symbol="£",
        country_code=ISO3166_GB,                 # 826 — United Kingdom
        country_name="United Kingdom",
        contactless_limit_minor=10000,           # £100.00 (10000 pence) — raised Oct 2021
        floor_limit_minor=0,                     # £0 floor limit = all txns go online
        cvm_above_limit=CVM_ONLINE_PIN,          # UK: Chip & PIN above contactless limit
        cvm_below_limit=CVM_NO_CVM,              # UK: no-CVM for contactless ≤ £100
        signature_accepted=False,                # UK: signature removed Feb 2006
        mag_stripe_fallback=False,               # UK: mag-stripe not accepted at Tesco
        cashback_available=False,                # Tesco policy: no cashback at checkout
        cashback_max_minor=0,
        accepted_schemes=[
            "VISA",
            "MASTERCARD",
            "AMEX",
            "DISCOVER",     # via Diners Club International arrangement
            "UNIONPAY",     # added at major UK retailers post-2015
        ],
        terminal_hardware="Verifone VX820 + PIN pad / iWL250 contactless",
        receipt_header=(
            "        TESCO STORES LTD\n"
            "      www.tesco.com/help\n"
            "     Tesco House, Welwyn Garden City\n"
            "             AL7 1GA"
        ),
        receipt_footer=(
            "    THANK YOU FOR SHOPPING AT TESCO\n"
            "  Collect Clubcard points every visit\n"
            "  0800 505555  |  tesco.com/clubcard"
        ),
        extra_fields={
            # Loyalty: Tesco Clubcard number appended to receipt
            "clubcard_prompt": "CLUBCARD: **** **** **** 1234 (+15 pts)",
            # UK rule: all refunds require manager card authorisation
            "refund_requires_manager": "true",
            # UK CPIL date of last contactless limit change
            "contactless_limit_date": "2021-10-15",
            # UK: void only allowed same-day (before batch close)
            "void_same_day_only": "true",
            # Tap & Go enabled for all contactless-capable schemes
            "tap_and_go_enabled": "true",
            # Acquirer settlement time (automated, 23:00 UK time)
            "settlement_time": "23:00 GMT",
            # PIN tries before card block (UK standard: 3)
            "pin_tries_before_block": "3",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Factory functions — TJ Maxx US
# ─────────────────────────────────────────────────────────────────────────────

def get_tjmaxx_us_profile() -> MerchantProfile:
    """
    Return a fully-configured MerchantProfile for TJ Maxx US retail checkout.

    Configuration reflects TJX Companies' US store setup post-EMV migration:
    - Chase Paymentech acquiring (formerly First Data / Paymentech joint venture)
    - Ingenico iCT220 contact terminal + contactless reader attachment
    - $100 contactless limit (US standard since 2020)
    - Signature accepted and preferred for credit (US standard Chip+Sig)
    - PIN required for debit transactions
    - Mag-stripe fallback: ALLOWED (US retail operational requirement)
    - Cashback on debit: up to $40
    - MCC 5621 — Women's Ready-to-Wear Stores (primary TJX MCC)
    - Currency USD (ISO 4217 = 840)  Country US (ISO 3166 = 840)

    Historical note: TJX suffered the largest retail data breach before EMV
    (2007, ~94M cards via mag-stripe skimming). Post-liability-shift (Oct 2015),
    mag-stripe fraud liability falls on the merchant, not the issuer.

    Terminal ID: 8-digit numeric (e.g. 12345678)
    Merchant ID: 15-digit Chase Paymentech format (e.g. 495301234567890)

    Returns:
        MerchantProfile configured for TJ Maxx US.
    """
    return MerchantProfile(
        merchant_name="TJ MAXX",
        merchant_id="495301234567890",           # 15-digit Chase Paymentech MID
        terminal_id="12345678",                  # 8-digit numeric
        acquirer_name="Chase Paymentech",
        acquirer_bin="403587",                   # Chase Paymentech acquiring BIN range
        mcc=MCC_WOMENS_CLOTHING,                 # 5621 — Women's Ready-to-Wear Stores
        currency_code=ISO4217_USD,               # 840 — US Dollar
        currency_symbol="$",
        country_code=ISO3166_US,                 # 840 — United States of America
        country_name="United States",
        contactless_limit_minor=10000,           # $100.00 (10000 cents) — US 2020 standard
        floor_limit_minor=5000,                  # $50.00 floor — above = online auth required
        cvm_above_limit=CVM_SIGNATURE,           # US credit standard: Chip + Signature
        cvm_below_limit=CVM_NO_CVM,              # No-CVM for contactless ≤ $100
        signature_accepted=True,                 # US: signature accepted for credit
        mag_stripe_fallback=True,                # US retail: fallback still operationally required
        cashback_available=True,                 # Debit cashback available
        cashback_max_minor=4000,                 # $40.00 maximum cashback
        accepted_schemes=[
            "VISA",
            "MASTERCARD",
            "AMEX",
            "DISCOVER",
        ],
        terminal_hardware="Ingenico iCT220 + contactless reader",
        receipt_header=(
            "           TJ MAXX\n"
            "        THE TJX COMPANIES\n"
            "    770 Cochituate Rd, Framingham MA\n"
            "         1-800-926-6299"
        ),
        receipt_footer=(
            "     THANK YOU FOR SHOPPING TJ MAXX\n"
            "  TJX Rewards Card: 1-800-952-6133\n"
            " Returns accepted within 30 days w/ receipt"
        ),
        extra_fields={
            # US Durbin Amendment (2011): merchant may route debit to cheapest network
            "debit_routing": "STAR,NYCE,PULSE",
            # TJX Rewards co-branded credit card (second AID in wallet)
            "tjx_rewards_aid": "A000000003101001",   # simulated TJX Rewards AID
            # US: no same-day void restriction (voids allowed within 24h)
            "void_same_day_only": "false",
            # Cashback available on PIN debit only
            "cashback_debit_only": "true",
            # EMV liability shift date
            "emv_liability_shift_date": "2015-10-01",
            # No-CVM threshold for contactless (below $25 no CVM needed)
            "no_cvm_threshold_minor": "2500",
            # Gift card support (separate processing flow)
            "gift_card_supported": "true",
            # US: refunds do not require manager auth at TJ Maxx
            "refund_requires_manager": "false",
            # Settlement: merchant-initiated batch close at store close
            "settlement_type": "merchant_initiated",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Module-level profiles registry
# ─────────────────────────────────────────────────────────────────────────────

#: Pre-built profile instances, keyed by short name.
#: Used by the GREENWIRE menu system and CLI for quick access.
MERCHANT_PROFILES: Dict[str, MerchantProfile] = {
    "tesco_uk": get_tesco_uk_profile(),
    "tjmaxx_us": get_tjmaxx_us_profile(),
}


# ─────────────────────────────────────────────────────────────────────────────
# Demo function
# ─────────────────────────────────────────────────────────────────────────────

def demo_merchants() -> None:
    """
    Run a demonstration of both merchant terminal emulators.

    Scenario 1 — Tesco UK:
      A customer taps their Visa contactless card for £23.50 of groceries.
      Amount is below the £100 contactless limit, so no CVM is required.

    Scenario 2 — TJ Maxx US:
      A customer swipes their Mastercard for $47.99 of clothing.
      Mag-stripe fallback is allowed. Amount is below the $50 floor limit
      so offline approval is possible, but signature is still requested
      (US Chip+Sig standard applies to contact/swipe transactions).

    Output is printed to stdout for quick visual verification.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── SCENARIO 1: Tesco UK — £23.50 contactless tap ──────────────────────
    print("\n" + "═" * 60)
    print("  SCENARIO 1 — TESCO UK  |  £23.50 contactless tap")
    print("═" * 60)

    tesco_profile = get_tesco_uk_profile()
    tesco_terminal = MerchantTerminalEmulator(tesco_profile)
    print(tesco_terminal.power_on())

    # Visa card tap — £23.50 = 2350 pence
    # PAN starting with 4 → VISA scheme
    tesco_result = tesco_terminal.process_transaction(
        amount_minor=2350,                        # £23.50 in pence
        pan="4111111111111111",                   # Visa test PAN
        contactless=True,
    )
    print(tesco_result["receipt"])
    print(f"\n  CVM applied : {tesco_result['cvm_applied']}")
    print(f"  Auth type   : {tesco_result['authorisation_type']}")
    print(f"  Response    : {'APPROVED' if tesco_result['success'] else 'DECLINED'}")

    # Show cashback rejection (Tesco does not offer cashback)
    print("\n  [Testing cashback rejection at Tesco]")
    cb_result = tesco_terminal.process_cashback(
        purchase_minor=2350,
        cashback_minor=2000,   # £20 cashback request
    )
    print(f"  Cashback result: {cb_result['message']}")

    # ── SCENARIO 2: TJ Maxx US — $47.99 mag-stripe swipe ───────────────────
    print("\n" + "═" * 60)
    print("  SCENARIO 2 — TJ MAXX US  |  $47.99 mag-stripe swipe")
    print("═" * 60)

    tjmaxx_profile = get_tjmaxx_us_profile()
    tjmaxx_terminal = MerchantTerminalEmulator(tjmaxx_profile)
    print(tjmaxx_terminal.power_on())

    # Mastercard swipe — $47.99 = 4799 cents
    # PAN starting with 51 → MASTERCARD scheme
    tjmaxx_result = tjmaxx_terminal.process_transaction(
        amount_minor=4799,                         # $47.99 in cents
        pan="5100000000000000",                    # Mastercard test PAN
        contactless=False,                         # mag-stripe swipe (fallback allowed)
    )
    print(tjmaxx_result["receipt"])
    print(f"\n  CVM applied : {tjmaxx_result['cvm_applied']}")
    print(f"  Auth type   : {tjmaxx_result['authorisation_type']}")
    print(f"  Response    : {'APPROVED' if tjmaxx_result['success'] else 'DECLINED'}")

    # Show cashback success (TJ Maxx debit cashback up to $40)
    print("\n  [Testing $20 cashback on debit at TJ Maxx]")
    cb_result2 = tjmaxx_terminal.process_cashback(
        purchase_minor=2000,    # $20.00 purchase
        cashback_minor=2000,    # $20.00 cashback
    )
    print(f"  Cashback result : {cb_result2['message']}")
    print(f"  Total charged   : {cb_result2.get('total_amount_display', 'N/A')}")

    # Batch close both terminals
    print("\n  [Batch close — Tesco UK]")
    tesco_batch = tesco_terminal.batch_close()
    print(f"  Transactions : {tesco_batch['batch_count']}  "
          f"Total : {tesco_batch['batch_total_display']}  "
          f"Ref : {tesco_batch['settlement_reference']}")

    print("\n  [Batch close — TJ Maxx US]")
    tjmaxx_batch = tjmaxx_terminal.batch_close()
    print(f"  Transactions : {tjmaxx_batch['batch_count']}  "
          f"Total : {tjmaxx_batch['batch_total_display']}  "
          f"Ref : {tjmaxx_batch['settlement_reference']}")

    print("\n" + "═" * 60)
    print("  Demo complete.")
    print("═" * 60 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    demo_merchants()
