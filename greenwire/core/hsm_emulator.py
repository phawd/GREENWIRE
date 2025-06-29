"""Simple HSM/ATM emulator for generating EMV applets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from .emv_generator import generate_card
from .crypto_engine import generate_rsa_key, rsa_sign


@dataclass
class EMVApplet:
    """Representation of a minimal EMV applet."""

    card: Dict[str, str]
    public_modulus: str
    signature: bytes


class HSMEmulator:
    """Lightweight emulator inspired by modern HSMs."""

    def __init__(self, issuer: str = "TEST BANK") -> None:
        self.issuer = issuer
        self._key = generate_rsa_key()

    def generate_e_applet(self) -> EMVApplet:
        """Generate EMV card data and sign it."""
        card = generate_card(self.issuer)
        data = f"{card['pan']}{card['expiry']}".encode()
        signature = rsa_sign(self._key, data)
        return EMVApplet(
            card=card,
            public_modulus=self._key.public_key().public_numbers().n.to_bytes(
                self._key.key_size // 8, "big"
            ).hex(),
            signature=signature,
        )
