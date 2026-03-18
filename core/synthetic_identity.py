"""Synthetic but plausible payment identity generation helpers."""

from __future__ import annotations

import random
import secrets
import string
from dataclasses import dataclass


_FIRST_NAMES = (
    "ALEX",
    "CASEY",
    "JORDAN",
    "MORGAN",
    "RILEY",
    "TAYLOR",
    "CAMERON",
    "DREW",
    "PARKER",
    "QUINN",
    "SKYLAR",
    "DEVON",
)

_LAST_NAMES = (
    "MORGAN",
    "BENNETT",
    "CARTER",
    "HAYES",
    "REED",
    "BROOKS",
    "ELLIS",
    "FOSTER",
    "COLEMAN",
    "JENSEN",
    "WALKER",
    "PERRY",
)


@dataclass(frozen=True)
class IssuerProfile:
    scheme: str
    issuer_name: str
    iins: tuple[str, ...]
    default_pan_length: int
    cvv_length: int


_ISSUER_PROFILES: dict[str, tuple[IssuerProfile, ...]] = {
    "visa": (
        IssuerProfile("visa", "Northstar Digital Bank", ("40031234", "41184210", "42715600"), 16, 3),
        IssuerProfile("visa", "Summit Retail Bank", ("43890122", "44551234"), 16, 3),
    ),
    "mastercard": (
        IssuerProfile("mastercard", "Harbor City Bank", ("22214567", "23190018", "27201234"), 16, 3),
        IssuerProfile("mastercard", "Bluepeak Financial", ("51014567", "54231234"), 16, 3),
    ),
    "amex": (
        IssuerProfile("amex", "Sterling Card Services", ("341234", "371245"), 15, 4),
    ),
    "discover": (
        IssuerProfile("discover", "Crescent Financial", ("60114567", "65001234", "64412345"), 16, 3),
    ),
}


def _profile_key(scheme: str) -> str:
    return (scheme or "visa").strip().lower()


def _normalize_ascii_upper(value: str, *, max_len: int | None = None) -> str:
    cleaned = "".join(ch for ch in value.upper() if ch in string.ascii_uppercase + " /.-")
    cleaned = " ".join(cleaned.split())
    if max_len is not None:
        cleaned = cleaned[:max_len].rstrip()
    return cleaned


def calculate_luhn_checksum(partial_pan: str) -> int:
    total = 0
    reverse_digits = partial_pan[::-1]
    for index, digit in enumerate(reverse_digits):
        value = int(digit)
        if index % 2 == 0:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return (10 - (total % 10)) % 10


def validate_luhn(pan: str) -> bool:
    if not pan.isdigit():
        return False
    return calculate_luhn_checksum(pan[:-1]) == int(pan[-1])


def get_issuer_profile(scheme: str, issuer_name: str | None = None) -> IssuerProfile:
    profiles = _ISSUER_PROFILES.get(_profile_key(scheme), _ISSUER_PROFILES["visa"])
    if issuer_name:
        normalized = _normalize_ascii_upper(issuer_name)
        for profile in profiles:
            if _normalize_ascii_upper(profile.issuer_name) == normalized:
                return profile
    return secrets.choice(profiles)


def generate_cardholder_name(name: str | None = None) -> str:
    if name:
        normalized = _normalize_ascii_upper(name, max_len=26)
        if len(normalized) >= 2:
            return normalized
    generated = f"{secrets.choice(_FIRST_NAMES)} {secrets.choice(_LAST_NAMES)}"
    return _normalize_ascii_upper(generated, max_len=26)


def generate_pan(
    scheme: str,
    *,
    length: int | None = None,
    iin: str | None = None,
    issuer_name: str | None = None,
) -> str:
    profile = get_issuer_profile(scheme, issuer_name=issuer_name)
    pan_length = length or profile.default_pan_length
    chosen_iin = "".join(ch for ch in (iin or secrets.choice(profile.iins)) if ch.isdigit())
    if len(chosen_iin) < 6:
        raise ValueError("IIN/BIN prefix must contain at least 6 digits")
    if pan_length <= len(chosen_iin):
        raise ValueError("PAN length must exceed IIN/BIN prefix length")
    account_digits = pan_length - len(chosen_iin) - 1
    body = chosen_iin + "".join(str(secrets.randbelow(10)) for _ in range(account_digits))
    return body + str(calculate_luhn_checksum(body))


def generate_cvv(scheme: str) -> str:
    profile = get_issuer_profile(scheme)
    upper_bound = 10 ** profile.cvv_length
    lower_bound = 10 ** (profile.cvv_length - 1)
    return str(random.randint(lower_bound, upper_bound - 1))


def generate_issuer_name(scheme: str) -> str:
    return get_issuer_profile(scheme).issuer_name


def generate_identity(
    scheme: str,
    *,
    cardholder_name: str | None = None,
    issuer_name: str | None = None,
    pan_length: int | None = None,
    iin: str | None = None,
) -> dict[str, str]:
    profile = get_issuer_profile(scheme, issuer_name=issuer_name)
    resolved_issuer = issuer_name or profile.issuer_name
    return {
        "cardholder_name": generate_cardholder_name(cardholder_name),
        "issuer_name": resolved_issuer,
        "pan": generate_pan(
            scheme,
            length=pan_length or profile.default_pan_length,
            iin=iin,
            issuer_name=resolved_issuer,
        ),
        "scheme": profile.scheme,
    }
