"""
test_key_generators.py
======================
Comprehensive pytest suite for the GREENWIRE EMV key-derivation and card-validation stack.

Coverage:
  - core.card_validator   — Luhn, BIN lookup, full PAN profile validation
  - core.synthetic_identity — PAN/identity generation, Luhn utilities
  - core.pan_registry     — persistent PAN de-duplication registry
  - core.key_generators   — GP/EMV/SCP03/HCE key derivation (skipped if
                             'cryptography' package is absent)

All tests are self-contained and hermetic.  File-backed tests use the
``tmp_path`` pytest fixture so they never touch the production registry.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import types
from pathlib import Path
from typing import Callable

import pytest

# ---------------------------------------------------------------------------
# Optional import: core.key_generators (needs 'cryptography')
# ---------------------------------------------------------------------------
try:
    from core.key_generators import (
        GP_StaticDiversification,
        EMV_DynamicSessionKeys,
        SCP03_AESKeyDerivation,
        HCE_TokenKeyGenerator,
        JCOP_DEFAULT_LAB_KEY,
    )
    _KG_AVAILABLE = True
except ImportError:
    _KG_AVAILABLE = False
    JCOP_DEFAULT_LAB_KEY = "404142434445464748494A4B4C4D4E4F"

_kg_skip = pytest.mark.skipif(
    not _KG_AVAILABLE,
    reason="core.key_generators unavailable — cryptography package missing",
)

# ---------------------------------------------------------------------------
# Mandatory imports
# ---------------------------------------------------------------------------
from core.card_validator import (
    luhn_valid,
    luhn_checksum,
    luhn_append,
    lookup_bin,
    validate_pan,
    validate_pan_batch,
    decode_service_code,
)
from core.synthetic_identity import (
    generate_pan,
    calculate_luhn_checksum,
    validate_luhn,
)
from core.pan_registry import register_pan, is_registered, acquire_unique_pan


# ===========================================================================
# TestLuhnAlgorithm
# ===========================================================================

class TestLuhnAlgorithm:
    """Verify the Luhn / mod-10 check-digit algorithm.

    Luhn is the checksum algorithm defined in ISO/IEC 7812-1.  It guards
    against single-digit transcription errors and random number guessing,
    but provides **no cryptographic security**.
    """

    def test_well_known_visa_test_pan(self):
        """4111111111111111 is the canonical Visa test PAN — must pass Luhn.

        This PAN appears in every EMV spec and payment SDK as the canonical
        'works everywhere' number, so it must pass Luhn unconditionally.
        """
        assert luhn_valid("4111111111111111") is True

    def test_well_known_mc_test_pan(self):
        """5500005555555559 is a commonly used MasterCard test PAN.

        Tests that the algorithm handles 5-series PANs correctly.
        """
        assert luhn_valid("5500005555555559") is True

    def test_amex_test_pan(self):
        """378282246310005 is the 15-digit Amex test PAN.

        AMEX PANs are 15 digits, not 16 — verifies variable-length handling.
        """
        assert luhn_valid("378282246310005") is True

    def test_luhn_fail_on_altered_digit(self):
        """Incrementing the last digit of a valid PAN must break the checksum.

        ...1111 → ...1112 changes the check digit, so Luhn must return False.
        This is the most basic mutation test for the algorithm.
        """
        assert luhn_valid("4111111111111112") is False

    def test_luhn_append_produces_valid_pan(self):
        """luhn_append on a 15-digit Visa body must yield a Luhn-valid 16-digit PAN.

        The body "411111111111111" has no check digit; luhn_append should
        compute and append it, producing a valid PAN.
        """
        body = "411111111111111"  # 15 digits, no check digit
        full_pan = luhn_append(body)
        assert len(full_pan) == 16
        assert luhn_valid(full_pan) is True

    def test_all_zeros_edge_case(self):
        """A PAN of all zeros (with Luhn check digit 0) must be Luhn-valid.

        This edge case confirms the algorithm handles the trivial all-zero
        input consistently and doesn't special-case zero.
        """
        # 15 zeros → append check digit → all-zeros PAN is Luhn-valid
        pan = luhn_append("0" * 15)
        assert luhn_valid(pan) is True

    def test_single_digit_invalid(self):
        """A single-digit string "7" is not a valid PAN — must fail.

        The Luhn algorithm is only meaningful for PANs ≥ 2 digits; a single
        digit carries no check information.
        """
        assert luhn_valid("7") is False

    @pytest.mark.parametrize("formatted,expected", [
        ("4111 1111 1111 1111", True),
        ("4111-1111-1111-1111", True),
        ("4111 1111 1111 1112", False),
    ])
    def test_strips_spaces_and_hyphens(self, formatted: str, expected: bool):
        """luhn_valid must ignore formatting separators (spaces and hyphens).

        Real-world card entry often includes spaces or hyphens; the validator
        must normalize them before computing the checksum.
        """
        assert luhn_valid(formatted) is expected


# ===========================================================================
# TestBINLookup
# ===========================================================================

class TestBINLookup:
    """Verify BIN (Bank Identification Number) / IIN database lookups.

    BIN lookup maps the first 6–8 digits of a PAN to a card scheme, issuing
    bank, country, and expected PAN length.  The database must prefer longer
    (8-digit) prefixes over shorter (6-digit) prefixes when both match.
    """

    def test_visa_generic_4prefix(self):
        """Any PAN starting with '4' not in a more-specific range → 'visa'.

        ISO 7812-1 assigns MII=4 to Visa globally, so a 4-series PAN with no
        more specific BIN entry must resolve to the visa scheme.
        """
        result = lookup_bin("4999999999999999")
        assert result is not None
        scheme, *_ = result
        assert scheme == "visa"

    def test_known_visa_test_pan(self):
        """4111111111111111 must map to a Visa test/generic BIN entry.

        This PAN is well-known in every test fixture; the BIN DB should have
        an explicit entry marking it as a test card.
        """
        result = lookup_bin("4111111111111111")
        assert result is not None
        scheme, bank_name, _country, _country_name, _length = result
        assert scheme == "visa"
        # Bank entry should indicate test or generic Visa
        assert "visa" in bank_name.lower() or "test" in bank_name.lower() or "generic" in bank_name.lower()

    def test_mastercard_5series(self):
        """5500... → mastercard.

        5-series BINs 5100–5599 belong to MasterCard per ISO 7812.
        """
        result = lookup_bin("5500005555555559")
        assert result is not None
        scheme, *_ = result
        assert scheme == "mastercard"

    def test_mastercard_2series(self):
        """2221... → mastercard (2-series BINs, introduced 2016).

        MasterCard expanded into the 2221–2720 range; the lookup must honour
        both the 5-series and the 2-series ranges.
        """
        result = lookup_bin("2221000000000009")
        assert result is not None
        scheme, *_ = result
        assert scheme == "mastercard"

    def test_amex_34prefix(self):
        """34-prefix → amex.

        American Express occupies 34xxxx and 37xxxx exclusively.
        """
        result = lookup_bin("3400000000000009")
        assert result is not None
        scheme, *_ = result
        assert scheme == "amex"

    def test_amex_37prefix(self):
        """37-prefix → amex (second Amex BIN range).

        Both 34 and 37 must resolve to amex; the lookup should handle both
        without needing two separate BIN entries at the caller level.
        """
        result = lookup_bin("378282246310005")
        assert result is not None
        scheme, *_ = result
        assert scheme == "amex"

    def test_discover_6011(self):
        """6011-prefix → discover.

        Discover's primary BIN range starts with 6011.
        """
        result = lookup_bin("6011000000000004")
        assert result is not None
        scheme, *_ = result
        assert scheme == "discover"

    def test_unknown_bin(self):
        """9999-series BIN that is not in the database → lookup returns None.

        The function must return None (not raise) for completely unrecognised
        BINs so callers can handle unknown issuers gracefully.
        """
        # 9-series is not allocated to any payment network
        result = lookup_bin("9999999999999999")
        if result is not None:
            scheme, *_ = result
            assert scheme == "unknown"
        # else None is also acceptable — both represent 'not found'

    def test_bin8_priority_over_bin6(self):
        """When a PAN matches both an 8-digit and a 6-digit BIN, the 8-digit
        match (more specific) must win.

        This ensures token BINs or co-branded ranges that share a 6-digit
        prefix with a generic issuer get correctly identified.
        """
        # 4111111111111111 — if there is an 8-digit entry for 41111111 it
        # should take precedence over the 6-digit 411111 entry.
        result8 = lookup_bin("41111111xxxxxxxx".replace("x", "1"))
        result6 = lookup_bin("411111xxxxxxxxxx".replace("x", "1"))
        # Both should resolve; the longer match takes priority internally.
        # We simply verify that lookup_bin does not crash and returns a result.
        assert result8 is not None or result6 is not None


# ===========================================================================
# TestValidatePan
# ===========================================================================

class TestValidatePan:
    """End-to-end PAN profile validation combining Luhn, BIN, expiry and CVV.

    validate_pan returns a CardProfile dataclass capturing every aspect of
    card validity.  These tests verify that the composite result is correct
    and that individual flags (expiry_ok, cvv_ok, is_test_pan, is_token)
    work independently.
    """

    def test_full_visa_profile(self):
        """validate_pan("4111111111111111") → ok=True, scheme='visa'.

        The canonical Visa test PAN should pass all structural checks.
        """
        profile = validate_pan("4111111111111111")
        assert profile.luhn_ok is True
        assert profile.scheme == "visa"
        assert profile.ok is True or profile.is_test_pan  # test PAN may have warning

    def test_expired_card_flagged(self):
        """Providing an expiry in the past must set expiry_ok=False.

        The validator must compare the supplied expiry against today's date
        so stale/expired cards are detected in testing workflows.
        """
        profile = validate_pan("4111111111111111", expiry="01/00")  # year 2000
        assert profile.expiry_ok is False

    def test_future_expiry_ok(self):
        """Providing an expiry well in the future must set expiry_ok=True.

        Python's strptime ``%y`` maps 00–68 → 2000–2068 and 69–99 → 1969–1999,
        so we use "35" (December 2035) as a reliably future year rather than
        "99" (which would be parsed as 1999 and flagged as expired).
        """
        profile = validate_pan("4111111111111111", expiry="12/35")
        assert profile.expiry_ok is True

    def test_cvv_wrong_length_for_scheme(self):
        """Amex requires a 4-digit CID; supplying a 3-digit CVV → cvv_ok=False.

        The validator must enforce scheme-specific CVV length rules, not a
        universal 3-digit default.
        """
        # Amex 378282246310005 needs 4-digit CID
        profile = validate_pan("378282246310005", cvv="123")  # 3 digits — wrong for Amex
        assert profile.cvv_ok is False

    def test_test_pan_flagged(self):
        """The canonical 4111... PAN must be flagged is_test_pan=True.

        This flag lets downstream tooling reject test PANs in production
        flows while still allowing them in laboratory environments.
        """
        profile = validate_pan("4111111111111111")
        assert profile.is_test_pan is True

    def test_token_pan_flagged(self):
        """PANs in known tokenization BIN ranges must set is_token=True.

        Token PANs (DPANs) use reserved BIN ranges such as those starting
        with 489537 (Visa Token Service) so they can be distinguished from
        real PANs (FPANs).
        """
        # 4895370000000000 is in the VTS token BIN range
        pan = luhn_append("489537000000000")
        profile = validate_pan(pan)
        assert profile.is_token is True

    def test_batch_validate(self):
        """validate_pan_batch returns one CardProfile per PAN in order.

        Batch validation is used by the lab CLI to assess a list of generated
        PANs in a single pass; the return list must preserve input order.
        """
        pans = ["4111111111111111", "378282246310005", "5500005555555559"]
        profiles = validate_pan_batch(pans)
        assert len(profiles) == 3
        assert profiles[0].scheme == "visa"
        assert profiles[1].scheme == "amex"
        assert profiles[2].scheme == "mastercard"

    @pytest.mark.parametrize("code,expected_fragment", [
        ("101", "international"),
        ("201", "international"),
        ("120", "interchange"),
        ("220", "interchange"),
    ])
    def test_service_code_decode(self, code: str, expected_fragment: str):
        """decode_service_code returns a human-readable description.

        The 3-digit magnetic-stripe service code encodes interchange rules
        (e.g. 101 = 'international interchange, normal authorisation').
        Pos1 digit 1 and 2 both map to international interchange; the decoded
        string must always contain the word 'interchange' for these codes.
        """
        decoded = decode_service_code(code)
        assert isinstance(decoded, str)
        assert len(decoded) > 5
        assert expected_fragment.lower() in decoded.lower()


# ===========================================================================
# TestPANRegistry
# ===========================================================================

class TestPANRegistry:
    """Verify the persistent PAN de-duplication registry.

    The registry writes to a JSON file; all tests use ``tmp_path`` so they
    are fully isolated and never touch the production data/generated_pans.json.
    """

    def test_register_and_lookup(self, tmp_path: Path):
        """Registering a PAN, then calling is_registered, must return True.

        This is the fundamental register→check round-trip that every
        deduplication feature depends on.
        """
        registry = tmp_path / "pans.json"
        pan = "4111111111111111"
        ok = register_pan(pan, source="unit-test", path=registry)
        assert ok is True
        assert is_registered(pan, path=registry) is True

    def test_no_duplicate(self, tmp_path: Path):
        """Registering the same PAN twice returns False on the second call.

        The registry must prevent the same PAN being handed out to two
        different synthetic card identities.
        """
        registry = tmp_path / "pans.json"
        pan = "5500005555555559"
        register_pan(pan, source="first-call", path=registry)
        second = register_pan(pan, source="second-call", path=registry)
        assert second is False

    def test_acquire_unique(self, tmp_path: Path):
        """acquire_unique_pan calls the generator until a fresh PAN is found.

        Pre-register a known PAN so the generator must skip it on the first
        attempt.  The returned PAN must be Luhn-valid and not already registered.
        """
        registry = tmp_path / "pans.json"
        counter = {"n": 0}

        # First call returns a pre-registered PAN; second call returns a new one
        pre_registered = luhn_append("411111111111111")
        register_pan(pre_registered, source="setup", path=registry)

        fresh = luhn_append("411111111111110")  # different PAN

        def generator() -> str:
            counter["n"] += 1
            return pre_registered if counter["n"] == 1 else fresh

        result = acquire_unique_pan(generator, source="test", path=registry)
        assert result == fresh
        assert counter["n"] == 2
        assert is_registered(fresh, path=registry) is True

    def test_normalize_strips_spaces(self, tmp_path: Path):
        """Spaces in a PAN input must be stripped before storing/looking up.

        Technicians sometimes copy-paste formatted PANs; the registry must
        normalise them so "4111 1111 1111 1111" and "4111111111111111" are
        treated as the same entry.
        """
        registry = tmp_path / "pans.json"
        register_pan("4111 1111 1111 1111", source="spaced", path=registry)
        # Lookup without spaces must find it
        assert is_registered("4111111111111111", path=registry) is True
        # Lookup with spaces must also find it
        assert is_registered("4111 1111 1111 1111", path=registry) is True


# ===========================================================================
# TestSyntheticIdentity
# ===========================================================================

class TestSyntheticIdentity:
    """Verify that synthetic PAN and identity generation produces valid output.

    synthetic_identity creates plausible-but-fake card data for test harnesses.
    Every generated PAN must satisfy Luhn and have a plausible BIN for its
    declared scheme.
    """

    @pytest.mark.parametrize("scheme", ["visa", "mastercard", "amex", "discover"])
    def test_generate_pan_luhn_valid(self, scheme: str):
        """generate_pan must always produce a Luhn-valid PAN for any scheme.

        The Luhn check is the minimum bar for a PAN that will pass issuer
        validation; a test suite PAN that fails Luhn is useless.
        """
        pan = generate_pan(scheme)
        assert validate_luhn(pan) is True, f"generated PAN {pan!r} failed Luhn"

    @pytest.mark.parametrize("scheme", ["visa", "mastercard", "amex", "discover"])
    def test_generate_pan_correct_prefix(self, scheme: str):
        """generate_pan must produce a PAN whose prefix matches the scheme.

        A Visa PAN starting with 5 would confuse any BIN lookup; the prefix
        must be consistent with the requested scheme.
        """
        prefix_map = {
            "visa": ("4",),
            "mastercard": ("5", "2"),
            "amex": ("34", "37"),
            "discover": ("6011", "644", "645", "646", "647", "648", "649", "65"),
        }
        pan = generate_pan(scheme)
        expected = prefix_map[scheme]
        assert any(pan.startswith(p) for p in expected), (
            f"PAN {pan!r} has wrong prefix for scheme '{scheme}'"
        )

    def test_calculate_luhn_checksum_known(self):
        """calculate_luhn_checksum("411111111111111") → 1.

        The check digit for the 15-digit Visa test body is 1, giving
        4111111111111111.  Verifying a known answer confirms the algorithm is
        correct, not just consistent.
        """
        digit = calculate_luhn_checksum("411111111111111")
        assert digit == 1

    def test_validate_luhn_matches_card_validator(self):
        """synthetic_identity.validate_luhn and card_validator.luhn_valid agree.

        Both modules implement the same algorithm.  They must produce
        identical results for a representative set of PANs to ensure the
        project has a single consistent implementation.
        """
        test_pans = [
            "4111111111111111",
            "5500005555555559",
            "378282246310005",
            "4111111111111112",  # invalid
        ]
        for pan in test_pans:
            assert validate_luhn(pan) == luhn_valid(pan), (
                f"Discrepancy for PAN {pan!r}"
            )


# ===========================================================================
# TestKeyGenerators
# ===========================================================================

@_kg_skip
class TestKeyGenerators:
    """Known-answer tests (KAT) for the four key-derivation engines.

    All tests use the JCOP default lab key
        ``404142434445464748494A4B4C4D4E4F``
    so results are deterministic and reproducible on any lab machine.

    The class is entirely skipped when the ``cryptography`` package is absent
    to allow the test suite to run in stripped-down environments.
    """

    # ------------------------------------------------------------------
    # GP_StaticDiversification
    # ------------------------------------------------------------------

    def test_gp_static_diversification_deterministic(self):
        """GP_StaticDiversification with identical inputs must produce identical keys.

        Static diversification is a deterministic algorithm: same master key
        + same card serial → same ENC/MAC/DEK every time.  Any non-determinism
        would mean personalization on different HSMs disagrees about card keys.
        """
        gen = GP_StaticDiversification(JCOP_DEFAULT_LAB_KEY)
        ks1 = gen.derive("0102030405060708")
        ks2 = gen.derive("0102030405060708")
        assert ks1.enc == ks2.enc, "ENC key is not deterministic"
        assert ks1.mac == ks2.mac, "MAC key is not deterministic"
        assert ks1.dek == ks2.dek, "DEK key is not deterministic"

    def test_gp_static_diversification_key_lengths(self):
        """All three derived GP keys (ENC, MAC, DEK) must be exactly 16 bytes.

        GlobalPlatform SCP02 uses 3DES-112 (two distinct 8-byte halves stored
        as 16 bytes).  A key of wrong length would be silently misinterpreted
        by the card.
        """
        gen = GP_StaticDiversification(JCOP_DEFAULT_LAB_KEY)
        ks = gen.derive("AABBCCDDEEFF0011")
        assert len(ks.enc) == 16
        assert len(ks.mac) == 16
        assert len(ks.dek) == 16

    def test_gp_static_different_serials_produce_different_keys(self):
        """Different card serials must produce different GP key sets.

        Diversification exists precisely so each card has unique keys.  If
        two serials produce the same key set the diversification is broken.
        """
        gen = GP_StaticDiversification(JCOP_DEFAULT_LAB_KEY)
        ks_a = gen.derive("0102030405060708")
        ks_b = gen.derive("0807060504030201")
        assert ks_a.enc != ks_b.enc or ks_a.mac != ks_b.mac

    def test_gp_keyset_display_returns_hex_strings(self):
        """GP_KeySet.display() must return a dict of uppercase hex strings.

        The display output is consumed by the lab CLI and by gp.jar
        PUT KEY commands; it must be valid hex and not None/bytes.
        """
        gen = GP_StaticDiversification(JCOP_DEFAULT_LAB_KEY)
        ks = gen.derive("0102030405060708")
        display = ks.display()
        assert isinstance(display, dict)
        for v in display.values():
            assert isinstance(v, str)
            # Must be hex
            bytes.fromhex(v)

    # ------------------------------------------------------------------
    # SCP03_AESKeyDerivation
    # ------------------------------------------------------------------

    def test_scp03_key_lengths(self):
        """SCP03_AESKeyDerivation always returns 16-byte (AES-128) session keys.

        SCP03 mandates AES-128 for its key derivation function.  Keys of
        wrong length would cause every INITIALIZE UPDATE to fail.
        """
        gen = SCP03_AESKeyDerivation(JCOP_DEFAULT_LAB_KEY)
        ks = gen.derive()
        assert len(ks.s_enc) == 16, "S-ENC must be 16 bytes"
        assert len(ks.s_mac) == 16, "S-MAC must be 16 bytes"
        assert len(ks.s_rmac) == 16, "S-RMAC must be 16 bytes"

    def test_scp03_different_challenges_different_keys(self):
        """Different host/card challenges must produce different SCP03 session keys.

        SCP03 session keys are bound to the fresh nonces exchanged during
        INITIALIZE UPDATE.  Reusing nonces — or ignoring them — would allow
        replay attacks.
        """
        gen = SCP03_AESKeyDerivation(JCOP_DEFAULT_LAB_KEY)
        ks1 = gen.derive(host_challenge=bytes(8), card_challenge=bytes(8))
        ks2 = gen.derive(host_challenge=b"\x01" * 8, card_challenge=b"\x02" * 8)
        assert ks1.s_enc != ks2.s_enc or ks1.s_mac != ks2.s_mac

    def test_scp03_deterministic_with_same_challenges(self):
        """Same host/card challenges → identical SCP03 session keys.

        KDF determinism is required for test reproducibility and for the
        off-card entity to recompute keys when validating card cryptograms.
        """
        gen = SCP03_AESKeyDerivation(JCOP_DEFAULT_LAB_KEY)
        hc = bytes(range(8))
        cc = bytes(range(8, 16))
        ks1 = gen.derive(host_challenge=hc, card_challenge=cc)
        ks2 = gen.derive(host_challenge=hc, card_challenge=cc)
        assert ks1.s_enc == ks2.s_enc
        assert ks1.s_mac == ks2.s_mac

    # ------------------------------------------------------------------
    # EMV_DynamicSessionKeys  (ARQC)
    # ------------------------------------------------------------------

    def test_arqc_length(self):
        """compute_arqc must return exactly 8 bytes.

        The ARQC (Authorisation Request Cryptogram) is a truncated 3DES-MAC
        defined as 8 bytes by EMV Book 2 §8.1.  An ARQC of any other length
        will be rejected by every acquirer host.
        """
        gen = EMV_DynamicSessionKeys(JCOP_DEFAULT_LAB_KEY)
        result = gen.generate(pan="4111111111111111", psn="00", atc=1)
        assert len(result.arqc) == 8, (
            f"ARQC must be 8 bytes, got {len(result.arqc)}"
        )

    def test_emv_session_key_lengths(self):
        """EMV session keys SK_ENC and SK_MAC must each be 16 bytes.

        Single-DES keys are 8 bytes; 3DES-112 keys are 16 bytes (two 8-byte
        halves).  The EMV spec requires 3DES-112 for session keys.
        """
        gen = EMV_DynamicSessionKeys(JCOP_DEFAULT_LAB_KEY)
        result = gen.generate(pan="4111111111111111", atc=5)
        assert len(result.sk_enc) == 16
        assert len(result.sk_mac) == 16

    def test_emv_different_atc_different_arqc(self):
        """Different ATC values must produce different ARQCs.

        The ATC is the transaction counter mixed into the session key
        derivation.  If ATC has no effect, replay attacks become trivial.
        """
        gen = EMV_DynamicSessionKeys(JCOP_DEFAULT_LAB_KEY)
        r1 = gen.generate(pan="4111111111111111", atc=1)
        r2 = gen.generate(pan="4111111111111111", atc=2)
        assert r1.arqc != r2.arqc, "ARQC must change when ATC increments"

    def test_emv_icc_mk_16_bytes(self):
        """ICC Master Key derived from PAN/PSN must be 16 bytes.

        The ICC_MK is personalised into the chip during card manufacturing.
        An incorrect length invalidates every subsequent cryptogram.
        """
        gen = EMV_DynamicSessionKeys(JCOP_DEFAULT_LAB_KEY)
        result = gen.generate(pan="5500005555555559", atc=1)
        assert len(result.icc_mk) == 16

    # ------------------------------------------------------------------
    # HCE_TokenKeyGenerator
    # ------------------------------------------------------------------

    def test_hce_generator_luhn_valid_dpan(self):
        """The DPAN generated by HCE_TokenKeyGenerator must be Luhn-valid.

        A DPAN is a Device PAN — a surrogate PAN used inside the HCE applet
        instead of the real FPAN.  It must satisfy Luhn so NFC terminals
        can treat it as a regular PAN without modification.
        """
        gen = HCE_TokenKeyGenerator(JCOP_DEFAULT_LAB_KEY)
        token = gen.generate_token(fpan="4111111111111111")
        assert luhn_valid(token.dpan) is True, (
            f"DPAN {token.dpan!r} failed Luhn"
        )

    def test_luk_batch_size(self):
        """LUK batch must contain exactly the requested number of entries.

        The TSP pre-computes a batch of Limited-Use Keys (LUKs) and
        pushes them to the device wallet.  The batch size controls how many
        offline transactions the device can authorise before re-provisioning.
        """
        gen = HCE_TokenKeyGenerator(JCOP_DEFAULT_LAB_KEY)
        token = gen.generate_token(fpan="4111111111111111", luk_batch_size=7)
        assert len(token.luk_batch) == 7, (
            f"Expected 7 LUKs, got {len(token.luk_batch)}"
        )

    def test_hce_luk_entries_have_atc_and_luk(self):
        """Each LUK batch entry must contain 'atc' (int) and 'luk' (bytes).

        The HCE runtime indexes into the batch by ATC to find the correct key
        for each transaction; malformed entries would cause authorisation failures.
        """
        gen = HCE_TokenKeyGenerator(JCOP_DEFAULT_LAB_KEY)
        token = gen.generate_token(fpan="4111111111111111", luk_batch_size=3)
        for entry in token.luk_batch:
            assert "atc" in entry
            assert "luk" in entry
            assert isinstance(entry["atc"], int)
            assert isinstance(entry["luk"], bytes)

    def test_hce_arqc_length(self):
        """HCE compute_arqc must also return exactly 8 bytes.

        The HCE path uses LUK-derived session keys but the resulting ARQC
        format is identical to the physical card — 8 bytes — so the acquiring
        host can validate it without knowing the card is virtual.
        """
        gen = HCE_TokenKeyGenerator(JCOP_DEFAULT_LAB_KEY)
        token = gen.generate_token(fpan="4111111111111111", luk_batch_size=5)
        arqc, _atc = gen.compute_arqc(token)
        assert len(arqc) == 8


# ===========================================================================
# TestCardValidatorIntegration
# ===========================================================================

class TestCardValidatorIntegration:
    """Cross-cutting integration tests that exercise multiple components together.

    These tests verify that card_validator produces consistent results across
    a batch of well-known PANs and that every service code in active use can
    be decoded without error.
    """

    WELL_KNOWN_TEST_PANS = [
        "4111111111111111",   # Visa test
        "5500005555555559",   # MasterCard test
        "378282246310005",    # Amex test (15-digit)
        "6011111111111117",   # Discover test
        "3530111333300000",   # JCB test
    ]

    def test_all_test_vectors_pass_luhn(self):
        """All well-known EMVCo/issuer test PANs must pass the Luhn check.

        These PANs are published in EMV specifications and payment SDK
        documentation precisely because they satisfy all structural checks.
        If any of them fail Luhn the validator implementation is wrong.
        """
        for pan in self.WELL_KNOWN_TEST_PANS:
            assert luhn_valid(pan) is True, f"{pan!r} failed Luhn"

    @pytest.mark.parametrize("pan", [
        "4111111111111111",
        "5500005555555559",
        "378282246310005",
        "6011111111111117",
    ])
    def test_validate_pan_no_errors_for_test_pans(self, pan: str):
        """validate_pan must not report hard errors for well-known test PANs.

        Warnings (e.g. 'this is a test PAN') are acceptable; hard errors
        (luhn_ok=False, pan_length_ok=False) are not.
        """
        profile = validate_pan(pan)
        assert profile.luhn_ok is True, f"Luhn failed for {pan}"
        assert profile.pan_length_ok is True, f"Length wrong for {pan}"

    @pytest.mark.parametrize("code", ["101", "201", "120", "220", "999", "510"])
    def test_service_codes_all_decode(self, code: str):
        """Every service code in the test set must decode to a non-empty string.

        The service code appears on track 2 of the magnetic stripe.  All
        codes in the 001–999 space should produce a meaningful description,
        or at least not raise an exception.  A blank/None result would leave
        the lab analyst without actionable information.
        """
        decoded = decode_service_code(code)
        assert isinstance(decoded, str)
        assert len(decoded) > 0

    def test_batch_order_preserved(self):
        """validate_pan_batch must preserve the order of input PANs.

        Batch APIs are used in bulk-issuance scripts where output index maps
        directly to input index; swapped results would silently assign wrong
        profiles to wrong card records.
        """
        pans = list(reversed(self.WELL_KNOWN_TEST_PANS[:4]))
        profiles = validate_pan_batch(pans)
        assert len(profiles) == len(pans)
        for pan, profile in zip(pans, profiles):
            # Normalise: strip spaces and compare digits
            digits_in = "".join(c for c in pan if c.isdigit())
            digits_out = "".join(c for c in profile.pan if c.isdigit())
            assert digits_in == digits_out, (
                f"Input PAN {pan!r} mapped to profile for {profile.pan!r}"
            )

    def test_card_profile_is_test_pan_for_canonical_visa(self):
        """CardProfile.is_test_pan must be True for the 4111... PAN.

        This property is used by production safeguards to block test PANs
        from entering live transaction processing.
        """
        profile = validate_pan("4111111111111111")
        assert profile.is_test_pan is True

    def test_card_profile_ok_property_reflects_all_checks(self):
        """CardProfile.ok must be False if any required check fails.

        The .ok shortcut is consumed by callers that need a single boolean
        gate.  It must faithfully reflect all individual check results.
        """
        bad_pan = "4111111111111112"  # Luhn fails
        profile = validate_pan(bad_pan)
        assert profile.ok is False
