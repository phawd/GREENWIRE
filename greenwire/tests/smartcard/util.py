"""Utility helpers mimicking smartcard.util functions."""


def toHexString(data):
    """Return a hex string representation of iterable byte data."""
    return ' '.join(f"{b:02X}" for b in data)


def toBytes(hexstring):
    """Convert a hex string to a list of bytes."""
    return [int(hexstring[i:i + 2], 16) for i in range(0, len(hexstring), 2)]
