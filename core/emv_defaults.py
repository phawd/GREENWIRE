"""Loose EMV defaults for private testing.

Provides a central place for common AIDs, sample keys, default tags, and
simple helpers so tools can work out-of-the-box without strict validation.
"""
from __future__ import annotations

from typing import Dict, List

# Common payment application AIDs (loose set)
COMMON_AIDS: List[str] = [
    'A0000000031010',  # VISA Credit/Debit
    'A0000000041010',  # MasterCard
    'A00000002501',    # American Express
    'A0000001523010',  # Discover D-PAS
    'A0000003241010',  # JCB
    'A0000000651010',  # UnionPay
]

# Default CA/public keys (placeholder/test). Do not use in production.
TEST_KEYS: Dict[str, str] = {
    'rid': 'A000000003',
    'ca_public_mod': 'C1E3...FA',  # shortened sample
    'ca_public_exp': '03',
}

# Lenient status words map
SW_DESCRIPTIONS: Dict[str, str] = {
    '9000': 'Success',
    '6283': 'Selected file invalidated',
    '6285': 'Conditions of use not satisfied (warning)',
    '6300': 'Authentication failed (generic)',
    '6A82': 'File/Application not found',
    '6A86': 'Incorrect P1/P2',
    '6D00': 'INS not supported',
    '6E00': 'CLA not supported',
    '6700': 'Wrong length',
}


def preferred_aids() -> List[str]:
    return COMMON_AIDS[:]


def describe_sw(sw_hex: str) -> str:
    sw = sw_hex.upper()
    return SW_DESCRIPTIONS.get(sw, 'Unknown')


def loose_is_emv_aid(aid_hex: str) -> bool:
    # Accept anything 5–16 bytes hex as "EMV-like" for private testing
    s = aid_hex.replace(':', '').replace(' ', '').upper()
    if len(s) % 2 != 0:
        return False
    return 10 <= len(s) <= 32
