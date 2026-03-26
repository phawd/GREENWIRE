"""greenwire.core.jcop_predator_scenarios
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
JCOP-specific predator card scenario library for the GREENWIRE EMV/smartcard
security testing framework.

Attack-category overview
------------------------
J1 – Lifecycle Attacks
    Race conditions and edge-cases in the GlobalPlatform INSTALL / DELETE /
    LOAD lifecycle state-machine as implemented by NXP JCOP firmware.

J2 – Secure Channel Confusion
    Protocol-downgrade, key-version mismatch, and out-of-sequence attacks
    against JCOP's SCP02/SCP03 secure channel negotiation.

J3 – Memory Boundary
    APDU-buffer overflows, NVM pre-allocation exhaustion, and transient-
    buffer flooding via STORE DATA and LOAD command sequences.

J4 – Key Diversification Edges
    Degenerate CPLC diversification inputs, self-referential key derivation,
    key-type mismatches, and atomic key-rotation races in PUT KEY.

J5 – Applet Selection Conflicts
    Partial-AID tiebreaker, post-failed-SELECT command routing, lifecycle-
    state enforcement, and logical-channel context isolation.

Platform context
----------------
All scenarios target the NXP JCOP family (J2A, J2E, J3A, J3D) running
GlobalPlatform 2.2 / 2.3 with optional SCP02 or SCP03 secure channels.
Scenarios are framed as *predator* tests: each one demonstrates a specific
attack vector, labels the expected hardened response, and optionally injects
a known-bad SW so the GREENWIRE fuzzer can exercise the error path.

Usage example
-------------
    from core.jcop_predator_scenarios import (
        load_jcop_scenario, list_jcop_scenarios, jcop_scenario_summary,
    )

    # Load a specific scenario by ID
    s = load_jcop_scenario("JCOP_J2_01")
    for apdu in s.apdu_sequence:
        print(apdu)

    # List all HIGH/CRITICAL scenarios in category J2
    for s in list_jcop_scenarios("J2"):
        if s.severity in ("HIGH", "CRITICAL"):
            print(s.id, s.name)

    # Print summary statistics
    print(jcop_scenario_summary())
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class JCOPPredatorScenario:
    """Descriptor for a single JCOP predator-card attack scenario.

    Attributes
    ----------
    id : str
        Unique scenario identifier following the pattern ``JCOP_<cat>_<nn>``,
        e.g. ``"JCOP_J1_01"``.  All IDs are stored upper-case in the registry.
    name : str
        Short human-readable title for display and reporting.
    category : str
        Attack category code (``"J1"`` … ``"J5"``).  Used for filtering via
        :func:`list_jcop_scenarios`.
    description : str
        3–5 sentence explanation of the attack, covering the attack primitive,
        the vulnerable vs. hardened card response, and the practical impact.
    target_platform : str
        Target hardware/firmware family.  Defaults to ``"JCOP"``; may be
        narrowed to e.g. ``"JCOP3"`` for version-specific issues.
    expected_sw_list : List[str]
        Acceptable two-byte status word strings (hex, no spaces) that a
        *hardened* card should return at the critical step,
        e.g. ``["6985", "6A82"]``.
    apdu_sequence : List[str]
        Ordered list of hex-encoded APDUs (no spaces) that constitute the
        complete attack sequence.  Each entry is a full command APDU including
        CLA, INS, P1, P2, and optional Lc/data/Le.
    inject_bad_sw : Optional[str]
        If set, the SW the GREENWIRE injector should forge at the critical
        step to test downstream handling.  ``None`` means observe actual
        card response.
    severity : str
        One of ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, ``"CRITICAL"``.
    tags : List[str]
        Free-form labels for programmatic filtering
        (e.g. ``"scp02"``, ``"nvm-corruption"``).
    notes : str
        Technical commentary covering: relevant GP / ISO spec section,
        difference between vulnerable and hardened card behaviour, and
        real-world attack surface.
    """

    #: Unique scenario ID (upper-case, e.g. 'JCOP_J1_01').
    id: str
    #: Human-readable scenario name.
    name: str
    #: Attack category code ('J1'–'J5').
    category: str
    #: 3–5 sentence attack description.
    description: str
    #: Target hardware/firmware family.
    target_platform: str = "JCOP"
    #: Status words a hardened card should return at the critical step.
    expected_sw_list: List[str] = field(default_factory=list)
    #: Ordered list of hex APDUs constituting the attack sequence.
    apdu_sequence: List[str] = field(default_factory=list)
    #: SW to inject at the critical step, or None to observe actual response.
    inject_bad_sw: Optional[str] = None
    #: Severity classification: LOW | MEDIUM | HIGH | CRITICAL.
    severity: str = "MEDIUM"
    #: Filtering labels.
    tags: List[str] = field(default_factory=list)
    #: Technical notes: spec references, vulnerable vs hardened, attack surface.
    notes: str = ""


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_JCOP_SCENARIOS: Dict[str, JCOPPredatorScenario] = {}


def _jreg(s: JCOPPredatorScenario) -> JCOPPredatorScenario:
    _JCOP_SCENARIOS[s.id] = s
    logger.debug("Registered JCOP scenario: %s – %s", s.id, s.name)
    return s


# ---------------------------------------------------------------------------
# ── Category J1 – Lifecycle Attacks ─────────────────────────────────────────
# ---------------------------------------------------------------------------

_jreg(JCOPPredatorScenario(
    id="JCOP_J1_01",
    name="Install-then-immediately-delete race",
    category="J1",
    description=(
        "Send DELETE before INSTALL FOR INSTALL completes. "
        "On JCOP, the card-side install may be atomic but some firmware "
        "versions have a window between NVM commit phases. "
        "This tests whether the card correctly handles a DELETE arriving "
        "mid-install — a hardened card returns 6985 (Conditions of Use Not "
        "Satisfied) because the applet state is INSTALLING. "
        "A vulnerable card may corrupt its NVM or enter an undefined state."
    ),
    expected_sw_list=["6985", "6A82", "9000"],
    apdu_sequence=[
        "00A4040000",                                                              # SELECT ISD (empty AID)
        "8050000008DEADBEEFCAFEBABE00",                                            # INITIALIZE UPDATE kv=00 ki=00, 8-byte challenge, Le=00
        "848200001000000000000000000000000000000000",                              # EXTERNAL AUTHENTICATE sec_level=00, 16-byte {cryptogram||C-MAC}
        "80E60C001E07A000000151000007A000000151000107A0000001510001010002C90000",  # INSTALL FOR INSTALL+SELECTABLE
        "80E40000094F07A0000001510001",                                            # DELETE applet (race — immediate after INSTALL)
    ],
    inject_bad_sw="6985",
    severity="HIGH",
    tags=["jcop", "lifecycle", "race-condition", "nvm"],
    notes=(
        "GP Card Spec §11.4 defines the INSTALL command and lifecycle state "
        "transitions. JCOP3 firmware versions prior to 3.2 do not enforce "
        "atomic install at the NVM commit boundary, leaving a window between "
        "the AID table entry being written and the applet instance being "
        "fully committed. "
        "A hardened card must validate that the applet is in INSTALLED (0x03) "
        "or SELECTABLE (0x07) state before accepting a DELETE; returning 6985 "
        "while the applet state is INSTALLING (pre-commit) is the correct "
        "hardened behaviour. "
        "Attack surface: an adversary holding GP keys who can issue rapid-fire "
        "APDUs over a high-speed contactless or USB interface may corrupt the "
        "applet state table, producing a partially-installed entry that "
        "consumes NVM quota but cannot be selected or deleted normally."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J1_02",
    name="Re-install to pre-existing AID without prior DELETE",
    category="J1",
    description=(
        "Attempt INSTALL FOR INSTALL to an AID that already has a registered "
        "instance without first issuing DELETE. "
        "GP spec §11.4.3 states the card SHOULD return 6985 or 6A80. "
        "Some JCOP versions incorrectly allow silent overwrite, which can "
        "replace a production applet without audit trail. "
        "A hardened card rejects the second install with 6985 or 6A80."
    ),
    expected_sw_list=["6985", "6A80"],
    apdu_sequence=[
        "00A4040000",                                                              # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                                            # INITIALIZE UPDATE
        "848200001000000000000000000000000000000000",                              # EXTERNAL AUTHENTICATE
        "80E60C001E07A000000151000007A000000151000107A0000001510001010002C90000",  # INSTALL FOR INSTALL (1st — succeeds)
        "80E60C001E07A000000151000007A000000151000107A0000001510001010002C90000",  # INSTALL FOR INSTALL (2nd — same AID, the attack)
    ],
    inject_bad_sw="6985",
    severity="HIGH",
    tags=["jcop", "lifecycle", "overwrite", "aid-collision"],
    notes=(
        "GP Card Spec §11.4.3 explicitly forbids reinstalling to an AID that "
        "is already registered in the card's registry without first deleting "
        "the existing instance. "
        "If 9000 is returned on the second INSTALL FOR INSTALL, the card is "
        "vulnerable to silent applet replacement: an adversary with GP keys "
        "can swap out an issuer applet (e.g., an EMV payment application) for "
        "a malicious clone without leaving a lifecycle event in the audit log. "
        "The absence of a DELETE event is particularly dangerous in environments "
        "where a security auditor monitors the card's lifecycle log for "
        "unexpected deletions. "
        "Attack surface: malicious card-update scenario where an attacker "
        "holding stolen GP keys replaces the payment applet with a Trojan "
        "clone that exfiltrates transaction data."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J1_03",
    name="INSTALL with malformed package AID length (Lc mismatch)",
    category="J1",
    description=(
        "INSTALL FOR INSTALL with pkg_aid_len field set to 0x0A (10 bytes) "
        "but only 7 bytes of AID data follow, creating an Lc/data "
        "inconsistency. "
        "Tests parser robustness in JCOP's install parameter decoder. "
        "A hardened card returns 6A80 (Incorrect Parameters in Command Data "
        "Field). "
        "A vulnerable parser may read 3 bytes past the AID buffer into "
        "adjacent install fields, corrupting the applet AID or privilege byte."
    ),
    expected_sw_list=["6A80", "6700", "6984"],
    apdu_sequence=[
        "00A4040000",                                                              # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                                            # INITIALIZE UPDATE
        "848200001000000000000000000000000000000000",                              # EXTERNAL AUTHENTICATE
        # INSTALL FOR INSTALL — pkg_len=0x0A claims 10 bytes but only 7 AID bytes present;
        # total Lc=0x1E is unchanged, creating internal field-offset confusion.
        "80E60C001E0AA000000151000007A000000151000107A0000001510001010002C90000",
    ],
    inject_bad_sw="6A80",
    severity="MEDIUM",
    tags=["jcop", "lifecycle", "malformed", "parser", "buffer-confusion"],
    notes=(
        "GP Card Spec §11.4.2 requires that the install command data decoder "
        "validates that the sum of all length-prefixed fields equals Lc before "
        "acting on any decoded field. "
        "In the malformed APDU, pkg_len=0x0A claims 10 bytes of AID follow "
        "while only 7 are present, so a naive parser reads 3 bytes from the "
        "immediately following applet-AID length field as part of the package "
        "AID, shifting all subsequent TLV parsing by 3 bytes. "
        "A vulnerable parser may then write the mis-decoded applet AID into "
        "the registry, permanently associating the package with a wrong AID "
        "that cannot be easily corrected without full card re-personalisation. "
        "Attack surface: malformed INSTALL data injection for AID spoofing or "
        "to trigger a card-halt condition via parser crash."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J1_04",
    name="LOAD block sequence skip (block 3 before blocks 1 and 2)",
    category="J1",
    description=(
        "Normal LOAD sends blocks 0, 1, 2, 3 in order. "
        "This scenario sends block 0 then jumps to block 3 (P2=0x03), "
        "skipping blocks 1 and 2. "
        "Tests JCOP's load sequencing enforcement; GP spec §11.3.1 requires "
        "blocks arrive in monotonically increasing sequence. "
        "A vulnerable card may attempt to write block 3 at the wrong NVM "
        "offset, corrupting the CAP file structure."
    ),
    expected_sw_list=["6985", "6700", "6A86"],
    apdu_sequence=[
        "00A4040000",                                                  # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                                # INITIALIZE UPDATE
        "848200001000000000000000000000000000000000",                  # EXTERNAL AUTHENTICATE
        "80E602000C07A000000151000000000000",                          # INSTALL FOR LOAD (pkg=A0000001510000, no SD/hash/params)
        "80E8800010C4FECAFEBABE01020304050607080910",                  # LOAD block 0 (P1=0x80 more blocks, P2=0x00)
        "80E8000310C4FECAFEBABE01020304050607080910",                  # LOAD block 3 (P1=0x00 last block, P2=0x03 — skips 1,2)
    ],
    inject_bad_sw="6985",
    severity="HIGH",
    tags=["jcop", "lifecycle", "load", "sequence-skip", "nvm-corruption"],
    notes=(
        "GP Card Spec §11.3.1 mandates monotonically increasing block sequence "
        "numbers in LOAD: the card must reject any block whose P2 value is not "
        "exactly one greater than the previously accepted block. "
        "JCOP stores partial CAP blocks in a staging NVM area; if block "
        "sequencing is not enforced, block 3 is written at the NVM offset "
        "calculated for block 3 while the blocks 1 and 2 NVM space is zeroed, "
        "producing a structurally invalid CAP file. "
        "The resulting corrupt applet could execute arbitrary bytecode if the "
        "JavaCard VM loads the CAP without a secondary integrity check on "
        "block continuity. "
        "Attack surface: out-of-order LOAD injection during a legitimate load "
        "session to plant a malformed CAP, exploitable at subsequent "
        "installation time."
    ),
))

# ---------------------------------------------------------------------------
# ── Category J2 – Secure Channel Confusion ──────────────────────────────────
# ---------------------------------------------------------------------------

_jreg(JCOPPredatorScenario(
    id="JCOP_J2_01",
    name="SCP02 session with SCP03 MAC in EXTERNAL AUTHENTICATE",
    category="J2",
    description=(
        "Complete INITIALIZE UPDATE using SCP02 key version, then send "
        "EXTERNAL AUTHENTICATE with a C-MAC computed using SCP03's S-MAC "
        "derivation algorithm (single AES-CMAC instead of 3DES CBC-MAC). "
        "A hardened card detects the MAC verification failure and returns "
        "6300 (Authentication of host cryptogram failed) or 6988. "
        "A vulnerable JCOP may accept if the MAC byte count matches and "
        "no algorithm identifier is verified."
    ),
    expected_sw_list=["6300", "6988", "6982"],
    apdu_sequence=[
        "00A4040000",                                        # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                      # INITIALIZE UPDATE (SCP02, kv=00)
        # EXTERNAL AUTHENTICATE — payload format identical but C-MAC was computed
        # using SCP03 AES-CMAC derivation instead of SCP02 3DES CBC-MAC.
        "848200001000000000000000000000000000000000",
    ],
    inject_bad_sw="6300",
    severity="CRITICAL",
    tags=["jcop", "scp02", "scp03", "protocol-confusion", "secure-channel"],
    notes=(
        "GP SCP02 Spec §B.1.2.2 specifies C-MAC computation using 3DES "
        "CBC-MAC over the command data with a chained IV; GP SCP03 Spec "
        "§B.1.2.3 uses a single-pass AES-CMAC. "
        "The EXTERNAL AUTHENTICATE APDU format is identical for both "
        "protocols — only the MAC computation algorithm differs — so a card "
        "that does not track which SCP version was negotiated during "
        "INITIALIZE UPDATE cannot distinguish a valid SCP02 MAC from an "
        "SCP03 MAC of the same byte length. "
        "If the card accepts the SCP03 MAC, an attacker who can compute "
        "AES-CMAC (far simpler than cracking 3DES) can establish an "
        "authenticated secure channel against a card that believes it is "
        "running SCP02, bypassing the intended 3DES key requirement. "
        "Attack surface: downgrade the effective secure channel algorithm "
        "from 3DES to AES-CMAC, which may be easier to compute in a "
        "constrained attack environment."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J2_02",
    name="EXTERNAL AUTHENTICATE before INITIALIZE UPDATE (out of sequence)",
    category="J2",
    description=(
        "Send EXTERNAL AUTHENTICATE without first sending INITIALIZE UPDATE. "
        "The card has no session state — no card challenge, no session keys "
        "derived. "
        "GP spec §E.5.1 requires strict command sequencing. "
        "A hardened card returns 6985 (Conditions of Use Not Satisfied). "
        "A vulnerable JCOP may use stale session data from a previous "
        "session to validate the supplied cryptogram."
    ),
    expected_sw_list=["6985", "6982"],
    apdu_sequence=[
        "00A4040000",                                        # SELECT ISD
        # EXTERNAL AUTHENTICATE sent with no prior INITIALIZE UPDATE.
        # The 16-byte payload is a replayed {host_cryptogram||C-MAC} from a
        # previously captured session.
        "848200001000000000000000000000000000000000",
    ],
    inject_bad_sw="6985",
    severity="HIGH",
    tags=["jcop", "scp02", "sequence", "state-machine"],
    notes=(
        "GP Card Spec §E.5.1 defines the secure channel state machine: "
        "EXTERNAL AUTHENTICATE is only valid after a successful "
        "INITIALIZE UPDATE within the same logical channel session. "
        "A card that does not clear its session state between card "
        "activations (e.g., due to a soft-reset vulnerability) may retain "
        "the card challenge and derived session keys from the previous "
        "session, allowing a replayed EXTERNAL AUTHENTICATE to succeed. "
        "This is the classic 'stale session replay' attack: an adversary who "
        "eavesdropped on one authenticated session can reactivate the card "
        "and replay the captured EXTERNAL AUTHENTICATE without knowing the "
        "underlying GP master keys. "
        "Attack surface: replay of a captured EXTERNAL AUTHENTICATE from a "
        "prior session to establish a bogus secure channel and issue "
        "privileged commands."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J2_03",
    name="INITIALIZE UPDATE with non-existent key version (P1=0x7F)",
    category="J2",
    description=(
        "Send INITIALIZE UPDATE with P1 (key version number) = 0x7F, a "
        "version that does not exist on the card. "
        "GP spec §E.5.1 states the card returns 6A88 (Referenced Data Not "
        "Found) if the key version is unknown. "
        "Tests whether JCOP correctly validates the key version before "
        "beginning session key derivation."
    ),
    expected_sw_list=["6A88", "6A86"],
    apdu_sequence=[
        "00A4040000",                                        # SELECT ISD
        "80507F0008DEADBEEFCAFEBABE00",                      # INITIALIZE UPDATE P1=0x7F (non-existent key version)
    ],
    inject_bad_sw="6A88",
    severity="LOW",
    tags=["jcop", "scp02", "key-version", "error-handling"],
    notes=(
        "GP Card Spec §E.5.1 requires the card to return 6A88 (Referenced "
        "Data Not Found) when the requested key version in P1 of "
        "INITIALIZE UPDATE does not match any installed key set. "
        "Key version 0x7F is chosen because it falls outside the range of "
        "standard GP key sets (0x01–0x7E) and should not exist in any "
        "standard test environment. "
        "A subtle vulnerability exists if the card returns a partial "
        "INITIALIZE UPDATE response (card challenge, key info) even for an "
        "unknown key version — this leaks timing information and confirms "
        "which key versions do not exist. "
        "Attack surface: key-version enumeration — iterate P1 values from "
        "0x01 to 0x7F to map which key versions are installed, aiding "
        "targeted brute-force of specific key slots."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J2_04",
    name="SCP02 EXTERNAL AUTHENTICATE with all-zeros C-MAC IV (replay)",
    category="J2",
    description=(
        "In SCP02, the C-MAC chaining value starts from a card-derived IV. "
        "Sending EXTERNAL AUTHENTICATE where the C-MAC was computed starting "
        "from an all-zeros IV (0000000000000000) tests whether JCOP checks "
        "the MAC chaining value origin. "
        "A hardened card rejects this with 6300. "
        "A vulnerable implementation may accept if only the final 8 bytes "
        "of the MAC are checked without validating the chaining value."
    ),
    expected_sw_list=["6300", "6988", "6982"],
    apdu_sequence=[
        "00A4040000",                                        # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                      # INITIALIZE UPDATE (SCP02)
        # EXTERNAL AUTHENTICATE — C-MAC computed using 00000000 00000000 as
        # the initial chaining value instead of the card-derived session IV.
        "848200001000000000000000000000000000000000",
    ],
    inject_bad_sw="6300",
    severity="CRITICAL",
    tags=["jcop", "scp02", "cmac", "zeros-iv", "replay"],
    notes=(
        "GP SCP02 Spec §B.1.2.2 specifies that the C-MAC chaining value is "
        "initialised from a card-provided value derived during INITIALIZE "
        "UPDATE, not from a fixed all-zeros constant. "
        "The all-zeros IV is the classic SCP02 offline pre-computation setup: "
        "if a card accepts a MAC chained from zeros, any captured "
        "EXTERNAL AUTHENTICATE from any prior session can be replayed because "
        "the chaining value is session-independent. "
        "This vulnerability effectively collapses the per-session freshness "
        "guarantee of SCP02, reducing MAC verification to a static check "
        "against a pre-computed value. "
        "Attack surface: an adversary who captures one valid EXTERNAL "
        "AUTHENTICATE from any card of the same type can reuse it indefinitely "
        "to open authenticated secure channels without the master key."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J2_05",
    name="SCP03 S-ENC key used as S-MAC key (key role confusion)",
    category="J2",
    description=(
        "In SCP03, three session keys are derived: S-ENC, S-MAC, S-RMAC "
        "using distinct derivation constants. "
        "This scenario uses S-ENC (derivation constant 0x04) as S-MAC "
        "(derivation constant 0x06) in EXTERNAL AUTHENTICATE. "
        "Tests whether JCOP enforces key-role separation at the derivation "
        "constant level. "
        "A vulnerable card shares derivation constants across a single master "
        "key, making this attack feasible if constants are not enforced."
    ),
    expected_sw_list=["6300", "6988"],
    apdu_sequence=[
        "00A4040000",                                        # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                      # INITIALIZE UPDATE (SCP03 key version)
        # EXTERNAL AUTHENTICATE — S-ENC material (DDC=0x04) used as S-MAC (DDC=0x06).
        # Byte layout is identical; only the underlying key value differs.
        "848200001000000000000000000000000000000000",
    ],
    inject_bad_sw="6300",
    severity="HIGH",
    tags=["jcop", "scp03", "key-confusion", "derivation", "session-keys"],
    notes=(
        "GP SCP03 Spec §4.1.5 defines three derivation data constants (DDC): "
        "S-ENC=0x04, S-MAC=0x06, S-RMAC=0x07; each is mixed into the "
        "AES-CMAC-based KDF to produce domain-separated session keys. "
        "If the card does not validate which DDC was used to generate the "
        "key material in EXTERNAL AUTHENTICATE, an attacker who knows S-ENC "
        "(e.g., via side-channel) can compute a valid-looking S-MAC and "
        "open an authenticated channel without ever recovering S-MAC. "
        "This is particularly relevant on JCOP variants where the KDF "
        "implementation reuses the same AES engine for all three derivations "
        "without tagging which output is which. "
        "Attack surface: side-channel recovery of S-ENC (the encryption key) "
        "is leveraged to forge a valid S-MAC, fully compromising the SCP03 "
        "secure channel authentication."
    ),
))

# ---------------------------------------------------------------------------
# ── Category J3 – Memory Boundary ───────────────────────────────────────────
# ---------------------------------------------------------------------------

_jreg(JCOPPredatorScenario(
    id="JCOP_J3_01",
    name="STORE DATA with 255-byte payload (APDU buffer boundary)",
    category="J3",
    description=(
        "STORE DATA with 255 bytes of data in a single block (Lc=0xFF). "
        "JCOP J2A040/J3A040 have 40 KB NVM but the internal APDU buffer is "
        "typically 261 bytes for ISO short-APDU case 4. "
        "Sending maximum-length STORE DATA tests whether the NVM write path "
        "correctly bounds-checks before committing. "
        "Expected: 9000 if the card handles max short-APDU data length, "
        "or 6700 (Wrong Length) if capped at a shorter frame size."
    ),
    expected_sw_list=["9000", "6700", "6F00"],
    apdu_sequence=[
        "00A4040000",                                        # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                      # INITIALIZE UPDATE
        "848200001000000000000000000000000000000000",         # EXTERNAL AUTHENTICATE
        # STORE DATA block 0, P1=0x80 (more blocks), Lc=0xFF=255 bytes of payload.
        # 'AB' * 255 produces 255 repetitions of byte 0xAB (510 hex chars of data).
        "80E28000FF" + "AB" * 255,
    ],
    inject_bad_sw=None,
    severity="HIGH",
    tags=["jcop", "memory", "store-data", "buffer", "apdu-length"],
    notes=(
        "JCOP3 User Manual §5.3 and NXP AN10609 document the APDU buffer "
        "constraints: J3A040 supports short APDU with a maximum data field of "
        "255 bytes, meaning Lc=0xFF is the largest valid short-APDU case 3. "
        "Extended APDUs (Le > 255) require explicit extended-length support, "
        "which not all JCOP variants provide. "
        "The risk is in the NVM write path: if the buffer is 261 bytes and the "
        "STORE DATA handler writes Lc bytes without bounds-checking the "
        "destination NVM page, an off-by-one at Lc=0xFF may write one byte "
        "beyond the staging buffer. "
        "Attack surface: trigger a one-byte NVM overwrite at the staging buffer "
        "boundary, potentially corrupting the next NVM object header and "
        "enabling a controlled NVM corruption primitive."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J3_02",
    name="LOAD CAP with declared size 0x7FFF but only 16-byte actual block",
    category="J3",
    description=(
        "INSTALL FOR LOAD with the load parameters field containing a size "
        "indicator of 0x7FFF (32767 bytes) but only one small LOAD block "
        "containing 16 bytes follows. "
        "Tests whether JCOP validates that the declared CAP size matches "
        "what is actually delivered before committing NVM. "
        "A vulnerable card allocates 32 KB of NVM upfront based on the "
        "declared size, wasting quota for only 16 bytes of actual data."
    ),
    expected_sw_list=["6985", "6700", "6A80", "9000"],
    apdu_sequence=[
        "00A4040000",                                        # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                      # INITIALIZE UPDATE
        "848200001000000000000000000000000000000000",         # EXTERNAL AUTHENTICATE
        # INSTALL FOR LOAD — params field contains C6 02 7F FF (size tag 0xC6, value 0x7FFF).
        # Lc=0x10: [07][A0000001510000][00 SD][00 hash][04 params_len][C6 02 7F FF][00 token]
        "80E602001007A0000001510000000004C6027FFF00",
        # LOAD block 0, P1=0x00 (last/only block), 16 bytes of CAP data — far less than 32 KB declared.
        "80E8000010C4FECAFEBABE01020304050607080910",
    ],
    inject_bad_sw="6985",
    severity="MEDIUM",
    tags=["jcop", "memory", "cap-load", "nvm", "size-mismatch"],
    notes=(
        "GP Card Spec §11.3 permits a load file data block hash and optional "
        "size parameters to be included in INSTALL FOR LOAD; some JCOP "
        "implementations use the declared size to pre-allocate an NVM segment "
        "before any LOAD blocks arrive. "
        "If pre-allocation is not capped, an adversary can exhaust the card's "
        "NVM by sending many INSTALL FOR LOAD commands each declaring 32 KB, "
        "consuming the entire available NVM quota without loading any "
        "meaningful data. "
        "A hardened card should either ignore the declared size and allocate "
        "dynamically, or reject the LOAD session if actual delivered data "
        "significantly underruns the declared allocation. "
        "Attack surface: NVM exhaustion denial-of-service preventing legitimate "
        "applet installation on a production card."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J3_03",
    name="Rapid successive STORE DATA to exhaust transient COR buffer",
    category="J3",
    description=(
        "Send 30 STORE DATA blocks in rapid succession without INSTALL FOR "
        "INSTALL, targeting JCOP's transient CLEAR_ON_RESET (COR) array "
        "buffer used for STORE DATA assembly. "
        "JCOP allocates a fixed-size transient buffer for STORE DATA; if no "
        "per-session limit is enforced, an adversary can exhaust this buffer. "
        "After the buffer fills, legitimate personalisation STORE DATA "
        "commands fail with 6A84 (Not Enough Memory Space)."
    ),
    expected_sw_list=["9000", "6985", "6A84"],
    apdu_sequence=[
        "00A4040000",                                        # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                      # INITIALIZE UPDATE
        "848200001000000000000000000000000000000000",         # EXTERNAL AUTHENTICATE
        # 30 STORE DATA blocks, each 16 bytes, all marked P1=0x80 (more blocks coming).
        # P2 increments 0x00–0x1D as the block sequence counter.
        # 30 × 16 bytes = 480 bytes — exceeds typical 256–512 byte COR buffer.
        *[f"80E280{i:02X}10" + "AB" * 16 for i in range(30)],
    ],
    inject_bad_sw="6A84",
    severity="HIGH",
    tags=["jcop", "memory", "transient", "dos", "store-data", "exhaustion"],
    notes=(
        "JavaCard 3.0.4 spec §2.2.1 defines CLEAR_ON_RESET (COR) transient "
        "memory: it is allocated per-session and cleared on card reset or "
        "deselect; JCOP's typical COR budget is 256–512 bytes per session. "
        "Sending 30 × 16-byte STORE DATA blocks = 480 bytes fills a 512-byte "
        "COR buffer, leaving only 32 bytes of headroom; a 31st block of "
        "≥ 33 bytes triggers 6A84. "
        "Once the COR buffer is exhausted, the legitimate card issuer cannot "
        "personalise the card in the same session without performing a reset, "
        "which clears the attacker's data but also aborts the session. "
        "Attack surface: denial-of-service against card personalisation — "
        "useful when an attacker has physical access to a card before the "
        "issuer completes the personalisation workflow."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J3_04",
    name="INSTALL with privileges=0xFF (all GP privileges requested)",
    category="J3",
    description=(
        "INSTALL FOR INSTALL with the privileges field set to 0xFF, requesting "
        "all 8 defined GlobalPlatform privileges simultaneously. "
        "GP spec §C.4.1 states non-Security-Domain packages cannot hold SD "
        "privileges; a hardened card returns 6985. "
        "If 9000 is returned, the installed applet gains SD-level access "
        "including the ability to load, install, and delete other applets."
    ),
    expected_sw_list=["6985", "6A80"],
    apdu_sequence=[
        "00A4040000",                                                              # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                                            # INITIALIZE UPDATE
        "848200001000000000000000000000000000000000",                              # EXTERNAL AUTHENTICATE
        # INSTALL FOR INSTALL — privileges byte = 0xFF (all 8 GP privilege bits set).
        # Data: [07 pkg_AID][07 applet_AID][07 instance_AID][01 priv=FF][02 C900][00 token]
        "80E60C001E07A000000151000007A000000151000107A000000151000101FF02C90000",
    ],
    inject_bad_sw="6985",
    severity="CRITICAL",
    tags=["jcop", "privileges", "escalation", "security-domain", "install"],
    notes=(
        "GP Card Spec §C.4.1 defines eight application privileges: Security "
        "Domain, DAP Verification, Delegated Management, Card Lock, Card "
        "Terminate, Default Selected, CVM Management, and Mandated DAP; "
        "privilege byte 0xFF requests all eight simultaneously. "
        "A non-Security-Domain Application Package must not be granted SD "
        "privileges; the ISD must reject this with 6985. "
        "If a JCOP returns 9000, the installed applet can invoke the "
        "GlobalPlatform API to load/install/delete applets, lock or terminate "
        "the card, and intercept CVM (PIN) verification — full card manager "
        "compromise from a single malformed INSTALL command. "
        "Attack surface: privilege escalation from a normal application package "
        "to card-manager level, bypassing all subsequent GP security domain "
        "access controls."
    ),
))

# ---------------------------------------------------------------------------
# ── Category J4 – Key Diversification Edges ─────────────────────────────────
# ---------------------------------------------------------------------------

_jreg(JCOPPredatorScenario(
    id="JCOP_J4_01",
    name="Key derivation with all-zero CPLC serial (degenerate diversification)",
    category="J4",
    description=(
        "GP SCP02 key derivation uses the card serial number from CPLC data "
        "as a diversification input. "
        "When the serial is all-zeros — a common factory-default state on "
        "uninitialized JCOP test cards — the derived keys are identical for "
        "every card with the same master key. "
        "This scenario reads CPLC to confirm the zero serial, then attempts "
        "INITIALIZE UPDATE using keys derived from that all-zero input. "
        "A hardened issuer should detect and reject zero-serial cards during "
        "personalisation."
    ),
    expected_sw_list=["9000", "6300"],
    apdu_sequence=[
        "80CA9F7F00",                                        # GET DATA tag 9F7F = CPLC (confirm zero serial)
        "00A4040000",                                        # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                      # INITIALIZE UPDATE (keys derived from all-zero CPLC serial)
        "848200001000000000000000000000000000000000",         # EXTERNAL AUTHENTICATE
    ],
    inject_bad_sw=None,
    severity="HIGH",
    tags=["jcop", "key-diversification", "cplc", "zero-serial", "weak-keys"],
    notes=(
        "NXP AN10228 describes the EMV SCP02 key diversification scheme: the "
        "card serial number (bytes 15–16 of CPLC tag 9F7F) is XOR-combined "
        "with the master key material in the HSM to produce unique per-card "
        "keys. "
        "When the CPLC serial is all-zeros (factory default before "
        "personalisation), the derived key collapses to a static value "
        "identical for every uninitialized card produced with the same "
        "master key batch. "
        "An attacker who obtains one such card can derive the 'unique' key "
        "for all similarly uninitialized cards in the batch, gaining GP key "
        "access across the entire batch. "
        "Attack surface: bulk compromise of factory-fresh cards not yet "
        "personalized with unique CPLC serials, allowing GP master operations "
        "on all affected cards with a single derived key."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J4_02",
    name="Self-referential key derivation (CPLC input equals master key bytes)",
    category="J4",
    description=(
        "If the CPLC-based diversification input equals the master key bytes "
        "themselves, the derived key satisfies f(K, K) where f is the "
        "diversification function. "
        "This scenario installs a master key whose value matches the card's "
        "CPLC data, then verifies that the resulting derived key is weak. "
        "A hardened implementation rejects known-weak diversification inputs "
        "or detects the self-referential state during PUT KEY."
    ),
    expected_sw_list=["6300", "9000"],
    apdu_sequence=[
        "80CA9F7F00",                                                        # GET DATA CPLC (read serial to craft key)
        # PUT KEY — install a DES key whose 16-byte value is all zeros (placeholder
        # for a key matched to the CPLC bytes in a real attack).
        # CLA=84 INS=D8 P1=00(kv) P2=01(kid) Lc=0x16=22
        # Data: [key_type=01][key_len=0x10=16][16-byte key][KCV_len=03][KCV AA BB CC]
        "84D800011601100000000000000000000000000000000003AABBCC",
        "8050000008DEADBEEFCAFEBABE00",                                       # INITIALIZE UPDATE
        "848200001000000000000000000000000000000000",                         # EXTERNAL AUTHENTICATE
    ],
    inject_bad_sw=None,
    severity="HIGH",
    tags=["jcop", "key-diversification", "self-referential", "put-key", "crypto"],
    notes=(
        "This is a theoretical edge case with practical relevance in HSM-free "
        "personalisation setups where the operator manually loads key material "
        "that is not cryptographically independent of the card's identity data. "
        "When master key = CPLC-based diversification input, some KDF "
        "constructions collapse to f(K, K) = K (identity-like), meaning the "
        "derived key equals the master key and key uniqueness is lost. "
        "The PUT KEY step establishes the self-referential state; the "
        "subsequent INITIALIZE UPDATE exercises the KDF with that state. "
        "Attack surface: an adversary who knows the master key and the CPLC "
        "data can predict the derived session keys for all cards personalized "
        "with this misconfigured key loading procedure."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J4_03",
    name="PUT KEY to existing key version (overwrite vs. silent-ignore test)",
    category="J4",
    description=(
        "GP spec §11.8 states that PUT KEY to an existing key version should "
        "atomically overwrite it. "
        "Some JCOP implementations return 9000 but silently ignore the update, "
        "leaving known-weak keys permanently installed after an attempted "
        "rotation. "
        "This scenario installs a key, calls PUT KEY to the same version, "
        "then re-authenticates to verify whether the new or old key is active."
    ),
    expected_sw_list=["9000", "6985"],
    apdu_sequence=[
        "00A4040000",                                                        # SELECT ISD
        "8050010008DEADBEEFCAFEBABE00",                                       # INITIALIZE UPDATE (kv=01)
        "848200001000000000000000000000000000000000",                         # EXTERNAL AUTHENTICATE (with current kv=01 key)
        # PUT KEY — P1=01 (replace key version 01), P2=01 (key ID 1).
        # CLA=84 INS=D8 P1=01 P2=01 Lc=0x16=22
        "84D801011601100000000000000000000000000000000003AABBCC",
        "8050010008DEADBEEFCAFEBABE00",                                       # INITIALIZE UPDATE again — verify which key answers
    ],
    inject_bad_sw=None,
    severity="MEDIUM",
    tags=["jcop", "put-key", "key-rotation", "overwrite", "key-management"],
    notes=(
        "GP Card Spec §11.8 requires PUT KEY to be atomic: either the new key "
        "is fully written and activated, or the original key remains intact — "
        "there must be no intermediate state where neither key is valid. "
        "A JCOP that silently accepts PUT KEY (returns 9000) but does not "
        "actually update the key material is vulnerable to key-rotation "
        "failure: security teams believe the compromised key has been rotated, "
        "but the card continues to accept authentication with the old key. "
        "A second INITIALIZE UPDATE after the PUT KEY is the verification "
        "step — if the old challenge response still succeeds, the PUT KEY "
        "was silently ignored. "
        "Attack surface: an attacker who has stolen the old master key retains "
        "GP access to the card indefinitely despite an attempted key rotation."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J4_04",
    name="SCP03 AES key slot used for SCP02 session (key-type protocol mismatch)",
    category="J4",
    description=(
        "After installing an AES-128 key (key type 0x88) for SCP03, send "
        "INITIALIZE UPDATE pointing to that key version to request an SCP02 "
        "session. "
        "SCP02 requires 3DES keys (key type 0x82); using an AES key slot "
        "should trigger 6A88 or 6985. "
        "Tests whether JCOP enforces key-type compatibility with the "
        "requested secure channel protocol."
    ),
    expected_sw_list=["6A88", "6985", "6300"],
    apdu_sequence=[
        "00A4040000",                                                        # SELECT ISD
        # PUT KEY — install AES-128 key at version 01, key type 0x88=AES-128.
        # CLA=84 INS=D8 P1=01(new kv) P2=01(kid) Lc=0x16=22
        # Data: [key_type=88][key_len=0x10=16][16-byte AES key][KCV_len=03][KCV AA BB CC]
        "84D801011688100000000000000000000000000000000003AABBCC",
        "8050010008DEADBEEFCAFEBABE00",                                       # INITIALIZE UPDATE P1=01 (AES key version) — implicit SCP02 request
    ],
    inject_bad_sw="6A88",
    severity="HIGH",
    tags=["jcop", "scp02", "scp03", "key-type", "protocol-mismatch"],
    notes=(
        "GP SCP02 spec §B.1 specifies key type 0x82 (Triple-DES) for all "
        "SCP02 static key slots; GP SCP03 spec §4.1 specifies key type 0x88 "
        "(AES-128/192/256). "
        "The INITIALIZE UPDATE response format also differs: SCP02 response is "
        "28 bytes while SCP03 response is 29 bytes (additional key info). "
        "A card that allows an SCP02 session establishment against an AES-keyed "
        "slot is effectively downgrading the secure channel from AES to 3DES "
        "derivation semantics applied to AES key material, which is "
        "cryptographically undefined and potentially exploitable. "
        "Attack surface: protocol downgrade from SCP03 to SCP02 by exploiting "
        "key-type confusion, allowing attacks designed for 3DES-based SCP02 "
        "to be applied against a card intended to use AES-based SCP03."
    ),
))

# ---------------------------------------------------------------------------
# ── Category J5 – Applet Selection Conflicts ────────────────────────────────
# ---------------------------------------------------------------------------

_jreg(JCOPPredatorScenario(
    id="JCOP_J5_01",
    name="SELECT by 4-byte partial AID prefix (multiple candidates)",
    category="J5",
    description=(
        "Two applets sharing an AID prefix (A0000001510001 and "
        "A00000015100010F) are assumed installed. "
        "Sending SELECT with P2=0x00 (first or only occurrence) and a "
        "4-byte prefix A0000001 exercises the candidate list tiebreaker. "
        "GP spec §11.1.1 says if multiple matches exist and P2=0x00, select "
        "the one with the longest matching AID. "
        "Tests JCOP priority resolution for ambiguous AID prefixes."
    ),
    expected_sw_list=["9000", "6A82", "6310"],
    apdu_sequence=[
        # SELECT P1=0x04 (by name/AID), P2=0x00 (first/only), Lc=0x04, data=A0000001 (4-byte prefix).
        "00A4040004A0000001",
    ],
    inject_bad_sw=None,
    severity="MEDIUM",
    tags=["jcop", "select", "partial-aid", "aid-collision", "application-selection"],
    notes=(
        "GP Card Spec §11.1.1 and ISO 7816-5 define AID hierarchy: during "
        "partial-AID SELECT with P2=0x00, if multiple installed applications "
        "match the prefix, the card should select the application with the "
        "longest matching AID, breaking ties by registry order. "
        "Cycling through candidates using P2=0x02 (SELECT next occurrence) "
        "after an initial P2=0x00 SELECT allows enumeration of all installed "
        "AIDs sharing a prefix — an information disclosure that reveals the "
        "card's application inventory to an unauthenticated terminal. "
        "A hardened card should return 6310 (More Data Available) or 9000 "
        "for the first match but refuse further enumeration via P2=0x02 for "
        "applications outside the current security domain's visibility scope. "
        "Attack surface: unauthenticated application inventory enumeration "
        "via repeated SELECT with P2=0x02 cycling through all installed AIDs."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J5_02",
    name="SELECT non-existent AID then GENERATE AC (post-failure state confusion)",
    category="J5",
    description=(
        "SELECT a non-existent AID (card returns 6A82), then immediately send "
        "GENERATE AC as if selection succeeded. "
        "Tests whether JCOP correctly tracks that no applet is selected after "
        "a failed SELECT. "
        "A hardened card returns 6D00 (Instruction Code Not Supported) or "
        "6985. "
        "A vulnerable card may route GENERATE AC to the last successfully "
        "selected applet."
    ),
    expected_sw_list=["6D00", "6985", "6A82"],
    apdu_sequence=[
        # SELECT non-existent 7-byte AID DEADBEEF000000 — expect 6A82.
        "00A4040007DEADBEEF000000",
        # GENERATE AC (EMV INS=0xAE) — sent with no valid applet context.
        # P1=0x80 = ARQC request, Lc=0x1D=29 bytes of zeroed CDOL1 response data.
        "80AE80001D" + "00" * 29,
    ],
    inject_bad_sw="6D00",
    severity="HIGH",
    tags=["jcop", "select", "state-confusion", "generate-ac", "context-routing"],
    notes=(
        "ISO 7816-4 §7.1 defines the card state machine: after a failed SELECT "
        "(6A82 File Not Found), the 'currently selected application' pointer "
        "must remain at its previous value or be set to null — it must never "
        "be left in an undefined state pointing at partially-matched data. "
        "JCOP maintains a per-channel application context pointer; after a "
        "failed SELECT this pointer should be unchanged (or nulled), so "
        "subsequent commands issued on the same channel are rejected with "
        "6D00 because no valid application is active. "
        "A vulnerability where the failed-SELECT partially advances the "
        "context pointer allows an attacker to route EMV payment commands "
        "(GENERATE AC, GET PROCESSING OPTIONS) to the wrong applet, "
        "potentially triggering an unintended cryptographic operation. "
        "Attack surface: context hijacking — craft a non-existent AID that "
        "partially overlaps with a real applet AID to advance the context "
        "pointer to an unintended application before issuing payment commands."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J5_03",
    name="SELECT applet in INSTALLED lifecycle state (not yet SELECTABLE)",
    category="J5",
    description=(
        "Applet lifecycle states in JCOP: INSTALLED (0x03, not yet selectable), "
        "SELECTABLE (0x07), LOCKED, DELETED. "
        "After INSTALL FOR INSTALL with P1=0x04 (install only, no MAKE "
        "SELECTABLE), the applet is in INSTALLED state. "
        "Tests whether JCOP enforces the lifecycle state check during SELECT. "
        "A hardened card returns 6985 (Conditions of Use Not Satisfied)."
    ),
    expected_sw_list=["6985", "6A82"],
    apdu_sequence=[
        "00A4040000",                                                              # SELECT ISD
        "8050000008DEADBEEFCAFEBABE00",                                            # INITIALIZE UPDATE
        "848200001000000000000000000000000000000000",                              # EXTERNAL AUTHENTICATE
        # INSTALL FOR INSTALL with P1=0x04 (install only — no MAKE SELECTABLE).
        # Applet ends up in INSTALLED (0x03) state, not SELECTABLE (0x07).
        "80E604001E07A000000151000007A000000151000107A0000001510001010002C90000",
        # SELECT the newly installed applet — expect 6985 (not yet selectable).
        "00A4040007A0000001510001",
    ],
    inject_bad_sw="6985",
    severity="MEDIUM",
    tags=["jcop", "lifecycle", "selectable", "state", "install"],
    notes=(
        "GP Card Spec §11.4 distinguishes P1=0x04 (INSTALL only) from "
        "P1=0x0C (INSTALL + MAKE SELECTABLE): an applet installed with "
        "P1=0x04 is registered in the GP registry at lifecycle state "
        "INSTALLED (0x03) and must not respond to SELECT until a separate "
        "INSTALL [for MAKE SELECTABLE] command advances it to SELECTABLE "
        "(0x07). "
        "A card that allows SELECT of an INSTALLED-state applet bypasses the "
        "intended two-phase installation, which exists to allow issuers to "
        "install an applet but delay activation until post-issuance "
        "personalisation is complete. "
        "Premature selection may expose an incompletely initialised applet "
        "to terminal commands it is not ready to handle. "
        "Attack surface: send GP commands to an applet before personalisation "
        "completes, exploiting uninitialised field values or missing PIN state."
    ),
))

_jreg(JCOPPredatorScenario(
    id="JCOP_J5_04",
    name="Concurrent SELECT on two logical channels (channel context isolation)",
    category="J5",
    description=(
        "Open logical channel 1 via MANAGE CHANNEL, SELECT applet A on "
        "channel 0, SELECT applet B on channel 1 (CLA=0x01), then send "
        "GET DATA commands alternating between channels. "
        "Tests whether JCOP's channel dispatch table maintains separate "
        "application contexts per channel. "
        "A vulnerable JCOP may share a single context object across channels, "
        "causing commands on channel 1 to affect applet A's state."
    ),
    expected_sw_list=["9000"],
    apdu_sequence=[
        # MANAGE CHANNEL OPEN — P1=0x00 open, P2=0x00 assign next available, Le=0x01 (return channel number).
        "0070000001",
        # SELECT applet A on channel 0 (CLA=0x00).
        "00A4040007A0000001510000",
        # SELECT applet B on channel 1 (CLA=0x01 — logical channel 1 in basic interindustry class).
        "01A4040007A0000001510001",
        # GET DATA tag 9F36 (ATC) on channel 1 (CLA=0x81 = GP proprietary + channel 1).
        "81CA9F3600",
        # GET DATA tag 9F36 (ATC) on channel 0 (CLA=0x80 = GP proprietary + channel 0).
        "80CA9F3600",
    ],
    inject_bad_sw=None,
    severity="MEDIUM",
    tags=["jcop", "logical-channels", "concurrent-select", "channel-isolation", "context"],
    notes=(
        "ISO 7816-4 §6.16 defines logical channels (0–3) each with independent "
        "application selection state; JCOP supports up to 4 channels, each "
        "maintaining a separate 'currently selected application' pointer in "
        "the channel dispatch table. "
        "A vulnerability where channel contexts share the same object pointer "
        "means that a SELECT on channel 1 silently changes the active applet "
        "for channel 0, so a GET DATA on channel 0 after the channel 1 SELECT "
        "is routed to the wrong applet. "
        "This can be exploited to read data from applet A (e.g., an EMV "
        "payment application) by first selecting a data-exfiltration applet "
        "on channel 1, then issuing GET DATA on channel 0 while the context "
        "is confused to point at the exfiltration applet. "
        "Attack surface: cross-applet data read via channel confusion — "
        "particularly dangerous if an issuer installs both a payment applet "
        "and an OTA management applet on the same card."
    ),
))

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_jcop_scenario(scenario_id: str) -> JCOPPredatorScenario:
    """Load a JCOP predator scenario by ID.

    Parameters
    ----------
    scenario_id : str
        Case-insensitive scenario identifier, e.g. ``"jcop_j1_01"`` or
        ``"JCOP_J1_01"``.

    Returns
    -------
    JCOPPredatorScenario

    Raises
    ------
    KeyError
        If *scenario_id* is not found in the registry.
    """
    key = scenario_id.upper()
    if key not in _JCOP_SCENARIOS:
        available = ", ".join(sorted(_JCOP_SCENARIOS.keys()))
        raise KeyError(
            f"JCOP scenario {scenario_id!r} not found. Available: {available}"
        )
    s = _JCOP_SCENARIOS[key]
    logger.info("Loaded JCOP scenario: [%s] %s", s.id, s.name)
    return s


def list_jcop_scenarios(category: str = None) -> List[JCOPPredatorScenario]:
    """Return all JCOP scenarios, optionally filtered by category.

    Parameters
    ----------
    category : str, optional
        Category code to filter on, e.g. ``"J1"`` or ``"j2"`` (case-
        insensitive).  If *None*, all scenarios are returned.

    Returns
    -------
    List[JCOPPredatorScenario]
        Scenarios sorted by :attr:`~JCOPPredatorScenario.id`.
    """
    scenarios = list(_JCOP_SCENARIOS.values())
    if category is not None:
        cat = category.upper()
        scenarios = [s for s in scenarios if s.category == cat]
    return sorted(scenarios, key=lambda s: s.id)


def jcop_scenario_summary() -> dict:
    """Return aggregate counts per category and severity.

    Returns
    -------
    dict
        ``{"total": int, "by_category": {cat: count}, "by_severity": {sev: count}}``
    """
    counts_by_cat = Counter(s.category for s in _JCOP_SCENARIOS.values())
    counts_by_sev = Counter(s.severity for s in _JCOP_SCENARIOS.values())
    return {
        "total": len(_JCOP_SCENARIOS),
        "by_category": dict(counts_by_cat),
        "by_severity": dict(counts_by_sev),
    }


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    summary = jcop_scenario_summary()
    print("=== JCOP Predator Scenario Registry ===")
    print(json.dumps(summary, indent=2))
    print()

    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    all_scenarios = sorted(
        list_jcop_scenarios(),
        key=lambda s: (_SEV_ORDER.get(s.severity, 99), s.id),
    )

    col_id   = max(len(s.id)   for s in all_scenarios)
    col_sev  = max(len(s.severity) for s in all_scenarios)
    col_name = 50

    header = f"{'ID':<{col_id}}  {'SEV':<{col_sev}}  {'NAME':<{col_name}}  APDUs"
    print(header)
    print("-" * len(header))

    for s in all_scenarios:
        name_trunc = s.name[:col_name].ljust(col_name)
        print(
            f"{s.id:<{col_id}}  {s.severity:<{col_sev}}  {name_trunc}  "
            f"{len(s.apdu_sequence)} commands"
        )

    print()
    print("--- Sample scenario detail: JCOP_J2_01 ---")
    demo = load_jcop_scenario("JCOP_J2_01")
    print(f"  Category : {demo.category}")
    print(f"  Severity : {demo.severity}")
    print(f"  Tags     : {', '.join(demo.tags)}")
    print(f"  Inject SW: {demo.inject_bad_sw}")
    print(f"  Expected : {demo.expected_sw_list}")
    print(f"  APDUs ({len(demo.apdu_sequence)}):")
    for i, apdu in enumerate(demo.apdu_sequence):
        preview = apdu[:64] + ("…" if len(apdu) > 64 else "")
        print(f"    [{i}] {preview}")
    print(f"  Notes:\n    {demo.notes[:300]}…")
