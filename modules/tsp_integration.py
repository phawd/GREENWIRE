"""
TSP Integration — Visa VTS and Mastercard MDES Sandbox.

Handles token provisioning (FPAN → DPAN), LUK retrieval, and token
lifecycle management against sandbox environments for lab validation.

Production use requires:
  - Visa VTS: issuer agreement + mTLS cert from developer.visa.com
  - MC MDES:  issuer agreement + OAuth1.0a key from developer.mastercard.com

Sandbox credentials are free from the respective developer portals.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared data structures
# ---------------------------------------------------------------------------

@dataclass
class DeviceInfo:
    """Device binding info sent to TSP during provisioning."""
    device_id: str
    device_type: str = "MOBILE_PHONE"
    form_factor: str = "CARD"
    device_name: str = "GREENWIRE Lab Device"
    imei: Optional[str] = None
    language_code: str = "en"
    time_zone: str = "UTC"


@dataclass
class TokenRecord:
    """A provisioned payment token."""
    dpan: str                          # Device PAN (token)
    token_reference: str               # TSP's unique token ref
    scheme: str                        # "VISA" or "MASTERCARD"
    expiry: str                        # MMYY
    token_requestor_id: str
    luk_batch: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "ACTIVE"
    device_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dpan": self.dpan,
            "token_reference": self.token_reference,
            "scheme": self.scheme,
            "expiry": self.expiry,
            "status": self.status,
            "device_id": self.device_id,
            "luk_count": len(self.luk_batch),
        }


@dataclass
class LUKRecord:
    """A Limited Use Key for one batch of transactions."""
    key_index: int
    luk_hex: str                       # 16-byte key as hex
    atc_start: int
    atc_end: int
    use_limit: int = 10


# ---------------------------------------------------------------------------
# Visa VTS Sandbox
# ---------------------------------------------------------------------------

VTS_SANDBOX_BASE = "https://sandbox.api.visa.com"

# Well-known Visa test PANs for sandbox
VISA_TEST_PANS = {
    "visa_credit":    "4111111111111111",
    "visa_debit":     "4012888888881881",
    "visa_corporate": "4151500000000008",
    "visa_infinite":  "4988080000000000",
}

# Visa token BIN range (sandbox)
VISA_TOKEN_BIN = "489537"


class VTSSandboxClient:
    """
    Visa Token Service (VTS) sandbox client.

    Credentials from: https://developer.visa.com
    Sandbox requires mTLS cert + API key pair.

    For lab use without live credentials, use mock_mode=True which
    generates realistic DPAN/LUK values locally for equipment validation.
    """

    def __init__(
        self,
        api_key: str = "",
        api_secret: str = "",
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        mock_mode: bool = True,
    ) -> None:
        self.api_key = api_key
        self.api_secret = api_secret
        self.cert_path = cert_path
        self.key_path = key_path
        self.mock_mode = mock_mode or not api_key
        self.base_url = VTS_SANDBOX_BASE
        self._tokens: Dict[str, TokenRecord] = {}
        if self.mock_mode:
            logger.info("VTS client: mock mode — no live API calls (sandbox credentials not set)")

    # ------------------------------------------------------------------
    # Token provisioning
    # ------------------------------------------------------------------

    def provision_token(
        self,
        fpan: str,
        expiry: str,
        cvv2: str,
        device: DeviceInfo,
        token_requestor_id: str = "40010030273",  # Visa sandbox TRID
    ) -> TokenRecord:
        """
        Request a DPAN (device token) from VTS for a given FPAN.

        In mock_mode, generates a cryptographically realistic token locally.
        In live mode, calls POST /vts/v2/enrollments.
        """
        if self.mock_mode:
            return self._mock_provision(fpan, expiry, device, token_requestor_id)
        return self._live_provision(fpan, expiry, cvv2, device, token_requestor_id)

    def _mock_provision(
        self,
        fpan: str,
        expiry: str,
        device: DeviceInfo,
        token_requestor_id: str,
    ) -> TokenRecord:
        """Generate a realistic Visa sandbox token locally."""
        # DPAN: same length as PAN, different BIN (489537...)
        luhn_body = secrets.randbelow(10 ** 9)
        dpan_body = f"{VISA_TOKEN_BIN}{luhn_body:09d}"
        dpan = dpan_body + str(_luhn_check_digit(dpan_body))

        ref = "VTS-" + secrets.token_hex(8).upper()
        rec = TokenRecord(
            dpan=dpan,
            token_reference=ref,
            scheme="VISA",
            expiry=expiry,
            token_requestor_id=token_requestor_id,
            device_id=device.device_id,
        )
        # Provision initial LUK batch
        rec.luk_batch = self._generate_luk_batch(dpan, atc_start=1, batch_size=10)
        self._tokens[ref] = rec
        logger.info("VTS mock: provisioned DPAN %s (ref=%s)", _mask(dpan), ref)
        return rec

    def _live_provision(
        self,
        fpan: str,
        expiry: str,
        cvv2: str,
        device: DeviceInfo,
        token_requestor_id: str,
    ) -> TokenRecord:
        payload = {
            "enrollmentRequest": {
                "tokenizationAuthenticationValue": self._compute_tav(fpan, expiry, cvv2),
                "cardHolderVerification": {"cardSecurityCode": cvv2},
                "accountInfo": {
                    "primaryAccountNumber": fpan,
                    "panExpirationDate": expiry,
                },
                "tokenRequestorID": token_requestor_id,
                "tokenType": "DEVICE_TOKEN",
                "deviceInfo": {
                    "deviceID": device.device_id,
                    "deviceType": device.device_type,
                    "deviceName": device.device_name,
                },
            }
        }
        resp = self._post("/vts/v2/enrollments", payload)
        dpan = resp["enrollmentResponse"]["token"]["tokenNumber"]
        ref  = resp["enrollmentResponse"]["token"]["tokenUniqueReference"]
        return TokenRecord(
            dpan=dpan,
            token_reference=ref,
            scheme="VISA",
            expiry=resp["enrollmentResponse"]["token"]["tokenExpirationDate"],
            token_requestor_id=token_requestor_id,
            device_id=device.device_id,
        )

    # ------------------------------------------------------------------
    # LUK management
    # ------------------------------------------------------------------

    def replenish_luks(self, token_reference: str) -> List[LUKRecord]:
        """Request a fresh LUK batch for a token (mock: generate locally)."""
        rec = self._tokens.get(token_reference)
        if not rec:
            raise KeyError(f"Token {token_reference} not found")
        atc_start = (rec.luk_batch[-1]["atc_end"] + 1) if rec.luk_batch else 1
        batch = self._generate_luk_batch(rec.dpan, atc_start=atc_start, batch_size=10)
        rec.luk_batch.extend(batch)
        logger.info("VTS mock: replenished %d LUKs for %s", len(batch), token_reference)
        return [LUKRecord(**b) for b in batch]

    def get_current_luk(self, token_reference: str, atc: int) -> Optional[LUKRecord]:
        """Return the LUK covering the given ATC value."""
        rec = self._tokens.get(token_reference)
        if not rec:
            return None
        for b in rec.luk_batch:
            if b["atc_start"] <= atc <= b["atc_end"]:
                return LUKRecord(**b)
        return None

    # ------------------------------------------------------------------
    # Token lifecycle
    # ------------------------------------------------------------------

    def suspend_token(self, token_reference: str) -> None:
        rec = self._tokens.get(token_reference)
        if rec:
            rec.status = "SUSPENDED"
            logger.info("VTS mock: suspended %s", token_reference)

    def resume_token(self, token_reference: str) -> None:
        rec = self._tokens.get(token_reference)
        if rec:
            rec.status = "ACTIVE"

    def delete_token(self, token_reference: str) -> None:
        self._tokens.pop(token_reference, None)
        logger.info("VTS mock: deleted %s", token_reference)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _generate_luk_batch(
        self, dpan: str, atc_start: int, batch_size: int
    ) -> List[Dict[str, Any]]:
        """
        Generate LUK batch.  In production these come from the TSP HSM.
        Here we derive them deterministically from a mock IMK so that
        ARQC verification works end-to-end in the lab.
        """
        from modules.crypto.emv_crypto import EMVKeyDerivation
        imk = bytes.fromhex("404142434445464748494A4B4C4D4E4F")  # GP lab key as IMK
        icc_mk = EMVKeyDerivation.derive_icc_mk_a(imk, dpan, psn="00")
        batch = []
        for i in range(batch_size):
            atc = atc_start + i
            luk = _derive_session_key(icc_mk, atc)
            batch.append({
                "key_index": i,
                "luk_hex": luk.hex().upper(),
                "atc_start": atc,
                "atc_end": atc,
                "use_limit": 1,
            })
        return batch

    def _compute_tav(self, fpan: str, expiry: str, cvv2: str) -> str:
        """Compute Tokenization Authentication Value (sandbox stub)."""
        raw = f"{fpan}{expiry}{cvv2}"
        return base64.b64encode(hashlib.sha256(raw.encode()).digest()).decode()

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = self.base_url + path
        body = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {base64.b64encode(f'{self.api_key}:{self.api_secret}'.encode()).decode()}",
        }
        req = Request(url, data=body, headers=headers, method="POST")
        try:
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            raise RuntimeError(f"VTS API error {e.code}: {e.read()}") from e
        except URLError as e:
            raise RuntimeError(f"VTS network error: {e.reason}") from e


# ---------------------------------------------------------------------------
# Mastercard MDES Sandbox
# ---------------------------------------------------------------------------

MDES_SANDBOX_BASE = "https://sandbox.api.mastercard.com/mdes"

MC_TEST_PANS = {
    "mc_credit":    "5425233430109903",
    "mc_debit":     "2222420000001113",
    "mc_prepaid":   "5105105105105100",
}

MC_TOKEN_BIN = "535110"


class MDESSandboxClient:
    """
    Mastercard Digital Enablement Service (MDES) sandbox client.

    Credentials from: https://developer.mastercard.com
    Auth: OAuth 1.0a with RSA signing key.

    mock_mode=True (default) generates tokens locally for lab use.
    """

    def __init__(
        self,
        consumer_key: str = "",
        signing_key_path: Optional[str] = None,
        mock_mode: bool = True,
    ) -> None:
        self.consumer_key = consumer_key
        self.signing_key_path = signing_key_path
        self.mock_mode = mock_mode or not consumer_key
        self.base_url = MDES_SANDBOX_BASE
        self._tokens: Dict[str, TokenRecord] = {}
        if self.mock_mode:
            logger.info("MDES client: mock mode — sandbox credentials not set")

    def provision_token(
        self,
        fpan: str,
        expiry: str,
        device: DeviceInfo,
        token_requestor_id: str = "50110030273",  # MC sandbox TRID
    ) -> TokenRecord:
        if self.mock_mode:
            return self._mock_provision(fpan, expiry, device, token_requestor_id)
        return self._live_provision(fpan, expiry, device, token_requestor_id)

    def _mock_provision(
        self,
        fpan: str,
        expiry: str,
        device: DeviceInfo,
        token_requestor_id: str,
    ) -> TokenRecord:
        body = f"{MC_TOKEN_BIN}{secrets.randbelow(10**9):09d}"
        dpan = body + str(_luhn_check_digit(body))
        ref  = "MDES-" + secrets.token_hex(8).upper()
        rec  = TokenRecord(
            dpan=dpan,
            token_reference=ref,
            scheme="MASTERCARD",
            expiry=expiry,
            token_requestor_id=token_requestor_id,
            device_id=device.device_id,
        )
        rec.luk_batch = self._generate_luk_batch(dpan, atc_start=1, batch_size=10)
        self._tokens[ref] = rec
        logger.info("MDES mock: provisioned DPAN %s (ref=%s)", _mask(dpan), ref)
        return rec

    def _live_provision(
        self,
        fpan: str,
        expiry: str,
        device: DeviceInfo,
        token_requestor_id: str,
    ) -> TokenRecord:
        payload = {
            "responseHost": "site1.your-server.com",
            "requestId": secrets.token_hex(8),
            "tokenType": "CLOUD",
            "tokenRequestorId": token_requestor_id,
            "taskId": secrets.token_hex(4),
            "fundingAccountInfo": {
                "encryptedPayload": {
                    "encryptedData": {
                        "accountNumber": fpan,
                        "expiryMonth": expiry[:2],
                        "expiryYear": expiry[2:],
                    }
                }
            },
            "consumerLanguage": "en",
            "tokenizationAuthenticationValue": "",
        }
        resp = self._post("/cloud/1/0/tokenize", payload)
        dpan = resp["tokenDetail"]["encryptedTokenData"]["accountNumber"]
        ref  = resp["token"]["tokenUniqueReference"]
        return TokenRecord(
            dpan=dpan,
            token_reference=ref,
            scheme="MASTERCARD",
            expiry=expiry,
            token_requestor_id=token_requestor_id,
            device_id=device.device_id,
        )

    def get_current_luk(self, token_reference: str, atc: int) -> Optional[LUKRecord]:
        rec = self._tokens.get(token_reference)
        if not rec:
            return None
        for b in rec.luk_batch:
            if b["atc_start"] <= atc <= b["atc_end"]:
                return LUKRecord(**b)
        return None

    def _generate_luk_batch(
        self, dpan: str, atc_start: int, batch_size: int
    ) -> List[Dict[str, Any]]:
        from modules.crypto.emv_crypto import EMVKeyDerivation
        imk = bytes.fromhex("404142434445464748494A4B4C4D4E4F")
        icc_mk = EMVKeyDerivation.derive_icc_mk_a(imk, dpan, psn="00")
        batch = []
        for i in range(batch_size):
            atc = atc_start + i
            luk = _derive_session_key(icc_mk, atc)
            batch.append({
                "key_index": i,
                "luk_hex": luk.hex().upper(),
                "atc_start": atc,
                "atc_end": atc,
                "use_limit": 1,
            })
        return batch

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = self.base_url + path
        auth_header = self._oauth1_header("POST", url, payload)
        body = json.dumps(payload).encode()
        req = Request(url, data=body, headers={
            "Content-Type": "application/json",
            "Authorization": auth_header,
        }, method="POST")
        try:
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            raise RuntimeError(f"MDES API error {e.code}: {e.read()}") from e

    def _oauth1_header(self, method: str, url: str, body: dict) -> str:
        """Build OAuth 1.0a Authorization header (stub — full RSA impl needed for live)."""
        nonce = secrets.token_hex(16)
        ts = str(int(time.time()))
        params = {
            "oauth_consumer_key": self.consumer_key,
            "oauth_nonce": nonce,
            "oauth_signature_method": "RSA-SHA256",
            "oauth_timestamp": ts,
            "oauth_version": "1.0",
        }
        base = "&".join([
            method.upper(),
            urllib.parse.quote(url, safe=""),
            urllib.parse.quote("&".join(f"{k}={v}" for k, v in sorted(params.items())), safe=""),
        ])
        # Full RSA signing would load self.signing_key_path here
        params["oauth_signature"] = base64.b64encode(base.encode()).decode()
        return "OAuth " + ", ".join(f'{k}="{v}"' for k, v in params.items())


# ---------------------------------------------------------------------------
# Helper: unified TSP factory
# ---------------------------------------------------------------------------

def make_tsp_client(
    scheme: str = "visa",
    mock_mode: bool = True,
    **kwargs,
) -> VTSSandboxClient | MDESSandboxClient:
    """Return the correct TSP client for the given payment scheme."""
    if scheme.lower() in ("visa", "vts"):
        return VTSSandboxClient(mock_mode=mock_mode, **kwargs)
    elif scheme.lower() in ("mastercard", "mc", "mdes"):
        return MDESSandboxClient(mock_mode=mock_mode, **kwargs)
    raise ValueError(f"Unknown scheme: {scheme!r} — use 'visa' or 'mastercard'")


# ---------------------------------------------------------------------------
# Crypto utilities
# ---------------------------------------------------------------------------

def _derive_session_key(icc_mk: bytes, atc: int) -> bytes:
    """EMV common session key derivation from ICC master key + ATC."""
    from modules.crypto.primitives import encrypt_tdes_ecb
    atc_b = atc.to_bytes(2, "big")
    left  = encrypt_tdes_ecb(icc_mk, atc_b + b"\x00\x00" + atc_b + b"\x00\x00")[:8]
    right = encrypt_tdes_ecb(icc_mk, atc_b + b"\xFF\xFF" + atc_b + b"\xFF\xFF")[:8]
    return left + right


def _luhn_check_digit(pan_without_check: str) -> int:
    """Compute Luhn check digit for a PAN string (without final digit)."""
    digits = [int(d) for d in pan_without_check]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10


def _mask(pan: str) -> str:
    return pan[:6] + "******" + pan[-4:]


__all__ = [
    "VTSSandboxClient",
    "MDESSandboxClient",
    "DeviceInfo",
    "TokenRecord",
    "LUKRecord",
    "make_tsp_client",
    "VISA_TEST_PANS",
    "MC_TEST_PANS",
]
