"""Utility functions for generating sample EMV card data."""

import random, secrets
from datetime import UTC, datetime, timedelta


def _luhn_checksum(number: str) -> int:
    digits = [int(d) for d in number]
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10


def luhn_validate(number: str) -> bool:
    """Return True if the provided number passes the Luhn check."""
    return _luhn_checksum(number) == 0


def _calculate_luhn_digit(number: str) -> str:
    """Return the Luhn check digit for the given number string."""
    check = _luhn_checksum(number + "0")
    return str((10 - check) % 10)


def random_pan(iin: str = "400000") -> str:
    """Generate a random 16-digit PAN using the provided IIN prefix."""
    body_length = 15 - len(iin)
    body = iin + ''.join(str(random.randint(0, 9)) for _ in range(body_length))
    check_digit = _calculate_luhn_digit(body)
    return body + check_digit


def random_expiry(years_valid: int = 3) -> str:
    """Return an expiration date in YYMM format some years in the future.

    The current time is taken in UTC to ensure timezone-aware calculations.
    """
    exp = datetime.now(UTC) + timedelta(days=365 * years_valid)
    return exp.strftime("%y%m")


def generate_card(issuer: str = "TEST BANK", iin: str = "400000") -> dict:
    """Generate basic EMV card data with a unique encryption key."""
    pan = random_pan(iin)
    card = {
        "issuer": issuer,
        "pan": pan,
        "expiry": random_expiry(),
        "service_code": "101",
        "cvv": f"{random.randint(0, 999):03d}",
        # 256-bit encryption key for stronger test coverage
        "encryption_key": secrets.token_hex(32),
    }
    return card


if __name__ == "__main__":
    import json
    import argparse

    parser = argparse.ArgumentParser(description="Generate a sample EMV card")
    parser.add_argument("--issuer", type=str, default="TEST BANK",
                        help="Issuer name")
    parser.add_argument("--iin", type=str, default="400000",
                        help="Issuer Identification Number prefix")
    args = parser.parse_args()
    print(json.dumps(generate_card(args.issuer, args.iin), indent=2))
