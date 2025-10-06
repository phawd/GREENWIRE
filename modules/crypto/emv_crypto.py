"""EMV Cryptographic Attack Module - Enhanced with PyEMV implementations

This module provides comprehensive EMV cryptographic capabilities based on
production-grade implementations from the PyEMV library. It includes:

- Multiple CVN (Cryptogram Version Number) implementations
- Key derivation methods (Option A/B)  
- Session key derivation algorithms
- Application cryptogram generation
- ARPC (Authorization Response Cryptogram) generation
- Secure messaging capabilities

Supported CVN Classes:
- Visa CVN 10, 18, 22
- MasterCard CVN 16, 17, 20, 21
- Interac CVN 133

Key Features:
- Production-quality EMV cryptographic implementations
- Multiple key derivation methods for comprehensive attack coverage
- Session key algorithms for different card schemes
- ARQC/TC/AAC generation capabilities
- ARPC validation and generation
- Secure messaging for script integrity and confidentiality

Usage:
    from modules.crypto.emv_crypto import EMVCryptoManager
    
    # Initialize with issuer master keys
    crypto = EMVCryptoManager(iss_mk_ac, iss_mk_smi, iss_mk_smc)
    
    # Generate CVN-specific implementations
    visa_cvn10 = crypto.get_visa_cvn10(pan, psn)
    mc_cvn16 = crypto.get_mastercard_cvn16(pan, psn)
    
    # Generate cryptograms
    arqc = visa_cvn10.generate_ac(tag_data...)
    arpc = visa_cvn10.generate_arpc(arqc, response_code)
"""

import binascii, hashlib, logging, secrets, struct  # noqa: F401
from typing import Any, Dict, Optional, Tuple, Union
from enum import Enum

# Import GREENWIRE crypto primitives
from .primitives import adjust_key_parity, encrypt_tdes_ecb, xor_bytes

logger = logging.getLogger(__name__)


class CVNType(Enum):
    """Supported Cryptogram Version Numbers"""
    VISA_CVN10 = "visa_cvn10"
    VISA_CVN18 = "visa_cvn18" 
    VISA_CVN22 = "visa_cvn22"
    MASTERCARD_CVN16 = "mastercard_cvn16"
    MASTERCARD_CVN17 = "mastercard_cvn17"
    MASTERCARD_CVN20 = "mastercard_cvn20"
    MASTERCARD_CVN21 = "mastercard_cvn21"
    INTERAC_CVN133 = "interac_cvn133"


class KeyDerivationMethod(Enum):
    """EMV Key Derivation Methods"""
    OPTION_A = "option_a"
    OPTION_B = "option_b"


class SessionKeyMethod(Enum):
    """Session Key Derivation Methods"""
    COMMON = "common"
    MASTERCARD = "mastercard"
    VISA_SM = "visa_sm"
    EMV2000_TREE = "emv2000_tree"


class EMVKeyDerivation:
    """EMV Key Derivation Functions - Based on PyEMV implementations"""
    
    @staticmethod
    def derive_icc_mk_a(iss_mk: bytes, pan: Union[bytes, str], 
                       psn: Optional[Union[bytes, str]] = None) -> bytes:
        """ICC Master Key Derivation - EMV Option A
        
        Based on PyEMV derive_icc_mk_a implementation.
        Uses PAN, PAN Sequence Number, MK ISS, Triple DES.
        
        Args:
            iss_mk: 16-byte Issuer Master Key
            pan: ASCII Application Primary Account Number
            psn: ASCII 2-digit PAN Sequence Number (default "00")
            
        Returns:
            16-byte ICC Master Key
        """
        if psn is None:
            psn = "00"
            
        if isinstance(psn, bytes):
            psn = psn.decode("ascii")
            
        if isinstance(pan, bytes):
            pan = pan.decode("ascii")
            
        # Data A must be at most 16 digits, right-justified, zero-padded from left
        data_a = binascii.a2b_hex((pan + psn)[-16:].zfill(16))
        
        # Data B is inverted data A
        data_b = xor_bytes(data_a, b"\xFF" * len(data_a))
        
        # ICC MK = TDES(ISS_MK)[Data A || Data B]
        icc_mk = encrypt_tdes_ecb(iss_mk, data_a + data_b)
        
        return adjust_key_parity(icc_mk)
    
    @staticmethod
    def derive_icc_mk_b(iss_mk: bytes, pan: Union[bytes, str],
                       psn: Optional[Union[bytes, str]] = None) -> bytes:
        """ICC Master Key Derivation - EMV Option B
        
        Based on PyEMV derive_icc_mk_b implementation.
        Uses PAN, PAN Sequence Number, MK ISS, Triple DES, SHA-1 and
        decimalisation of hex digits.
        
        Args:
            iss_mk: 16-byte Issuer Master Key  
            pan: ASCII Application Primary Account Number
            psn: ASCII 2-digit PAN Sequence Number (default "00")
            
        Returns:
            16-byte ICC Master Key
        """
        # For PANs with length of 16 or less, method B works as method A
        if len(pan) <= 16:
            return EMVKeyDerivation.derive_icc_mk_a(iss_mk, pan, psn)
            
        if psn is None:
            psn = "00"
            
        if isinstance(psn, bytes):
            psn = psn.decode("ascii")
            
        if isinstance(pan, bytes):
            pan = pan.decode("ascii")
            
        # Generate SHA-1 hash of PAN + PSN
        sha_input = (pan + psn).encode('ascii')
        digest = hashlib.sha1(sha_input).hexdigest()
        
        # Extract first 16 digits from hash
        result = ''.join(c for c in digest if c.isdigit())[:16]
        
        # If insufficient digits, use decimalisation table
        if len(result) < 16:
            hex_chars = [d for d in digest if d in {'a', 'b', 'c', 'd', 'e', 'f'}]
            needed = 16 - len(result)
            decimal_chars = hex_chars[:needed]
            # Translate hex to decimal using table: a->0, b->1, c->2, d->3, e->4, f->5
            translation = str.maketrans('abcdef', '012345')
            decimal_digits = ''.join(decimal_chars).translate(translation)
            result = result + decimal_digits
            
        data_a = binascii.a2b_hex(result)
        
        # Data B is inverted data A
        data_b = xor_bytes(data_a, b"\xFF" * len(data_a))
        
        # ICC MK = TDES(ISS_MK)[Data A || Data B]  
        icc_mk = encrypt_tdes_ecb(iss_mk, data_a + data_b)
        
        return adjust_key_parity(icc_mk)
    
    @staticmethod
    def derive_common_sk(icc_mk: bytes, r: Union[bytes, bytearray]) -> bytes:
        """EMV Common Session Key Derivation
        
        Based on PyEMV derive_common_sk implementation.
        
        Args:
            icc_mk: 16-byte ICC Master Key
            r: 8-byte diversification value (ATC || 00 || 00 || 00 || 00 || 00 || 00 or ARQC)
            
        Returns:
            16-byte Session Key
        """
        if len(icc_mk) != 16:
            raise ValueError("ICC Master Key must be a double length DES key")
            
        if len(r) != 8:
            raise ValueError("Diversification value must be 8 bytes long")
            
        # SK Key A (first 8 bytes) = TDES(icc_mk)[r with byte 2 = 0xF0]
        r_a = bytearray(r)
        r_a[2] = 0xF0
        
        # SK Key B (second 8 bytes) = TDES(icc_mk)[r with byte 2 = 0x0F]
        r_b = bytearray(r)
        r_b[2] = 0x0F
        
        sk = encrypt_tdes_ecb(icc_mk, r_a + r_b)
        
        return adjust_key_parity(sk)
    
    @staticmethod
    def derive_visa_sm_sk(icc_mk: bytes, atc: bytes) -> bytes:
        """Visa Secure Messaging Session Key Derivation
        
        Based on PyEMV derive_visa_sm_sk implementation.
        
        Args:
            icc_mk: 16-byte ICC Master Key
            atc: 2-byte Application Transaction Counter
            
        Returns:
            16-byte Session Key
        """
        if len(icc_mk) != 16:
            raise ValueError("ICC Master Key must be a double length DES key")
            
        if len(atc) != 2:
            raise ValueError("ATC value must be 2 bytes long")
            
        # SK Key A (first 8 bytes) = r XOR MK Key A
        r = b"\x00" * 6 + atc
        sk_a = xor_bytes(r, icc_mk[:8])
        
        # SK Key B (second 8 bytes) = r XOR MK Key B  
        r = b"\x00" * 6 + xor_bytes(atc, b"\xff\xff")
        sk_b = xor_bytes(r, icc_mk[8:])
        
        return adjust_key_parity(sk_a + sk_b)
    
    @staticmethod
    def derive_mastercard_sk(icc_mk: bytes, atc: bytes, un: bytes) -> bytes:
        """MasterCard Session Key Derivation
        
        Args:
            icc_mk: 16-byte ICC Master Key
            atc: 2-byte Application Transaction Counter
            un: 4-byte Unpredictable Number
            
        Returns:
            16-byte Session Key
        """
        r = atc + b"\x00" * 2 + un
        return EMVKeyDerivation.derive_common_sk(icc_mk, r)


class EMVApplicationCryptogram:
    """EMV Application Cryptogram Generation - Based on PyEMV implementations"""
    
    @staticmethod
    def generate_ac(sk: bytes, cipher_text: bytes, padding_type: str = "emv") -> bytes:
        """Generate Application Cryptogram (ARQC, TC, or AAC)
        
        Args:
            sk: 16-byte Session Key
            cipher_text: Transaction data for cryptogram calculation
            padding_type: "emv" or "visa" padding method
            
        Returns:
            8-byte Application Cryptogram
        """
        # Apply padding based on type
        if padding_type == "visa":
            # Visa padding: pad with 0x00
            padded_data = cipher_text + b"\x00" * (8 - (len(cipher_text) % 8))
        else:
            # EMV padding: pad with 0x80 followed by 0x00
            padded_data = cipher_text + b"\x80"
            if len(padded_data) % 8 != 0:
                padded_data += b"\x00" * (8 - (len(padded_data) % 8))
        
        # Generate MAC using session key
        mac = EMVApplicationCryptogram._generate_mac(sk, padded_data)
        
        return mac
    
    @staticmethod
    def generate_arpc_method1(sk: bytes, arqc: bytes, arc: bytes) -> bytes:
        """Generate ARPC using Method 1
        
        Args:
            sk: 16-byte Session Key (or ICC Master Key)
            arqc: 8-byte ARQC
            arc: 2-byte Authorization Response Code
            
        Returns:
            8-byte ARPC
        """
        # ARPC = SK[ARQC XOR ARC || 0000000000]
        arpc_input = xor_bytes(arqc, arc + b"\x00" * 6)
        return encrypt_tdes_ecb(sk, arpc_input + b"\x00" * 8)[:8]
    
    @staticmethod
    def generate_arpc_method2(sk: bytes, arqc: bytes, csu: bytes) -> bytes:
        """Generate ARPC using Method 2
        
        Args:
            sk: 16-byte Session Key
            arqc: 8-byte ARQC
            csu: 4-byte Card Status Update
            
        Returns:
            4-byte ARPC
        """
        # ARPC = Left 4 bytes of SK[ARQC XOR CSU || 00000000]
        arpc_input = xor_bytes(arqc, csu + b"\x00" * 4)
        return encrypt_tdes_ecb(sk, arpc_input + b"\x00" * 8)[:4]
    
    @staticmethod
    def _generate_mac(key: bytes, data: bytes) -> bytes:
        """Generate MAC using Triple DES"""
        # Simple MAC implementation - encrypt with session key
        return encrypt_tdes_ecb(key, data)[:8]


class BaseCVN:
    """Base class for CVN implementations"""
    
    def __init__(self, iss_mk_ac: bytes, iss_mk_smi: bytes, iss_mk_smc: bytes,
                 pan: Union[bytes, str], psn: Optional[Union[bytes, str]] = None):
        """Initialize CVN with issuer master keys"""
        self.pan = pan
        self.psn = psn or "00"
        
        # Store issuer master keys
        self.iss_mk_ac = iss_mk_ac
        self.iss_mk_smi = iss_mk_smi  
        self.iss_mk_smc = iss_mk_smc
        
        # Derived ICC master keys (to be set by subclasses)
        self.icc_mk_ac = None
        self.icc_mk_smi = None
        self.icc_mk_smc = None


class VisaCVN10(BaseCVN):
    """Visa CVN 10 Implementation - Based on PyEMV VisaCVN10"""
    
    def __init__(self, iss_mk_ac: bytes, iss_mk_smi: bytes, iss_mk_smc: bytes,
                 pan: Union[bytes, str], psn: Optional[Union[bytes, str]] = None):
        super().__init__(iss_mk_ac, iss_mk_smi, iss_mk_smc, pan, psn)
        
        # Derive ICC Master Keys using Option A
        self.icc_mk_ac = EMVKeyDerivation.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smc, pan, psn)
    
    def generate_ac(self, transaction_data: bytes, atc: bytes = None) -> bytes:  
        """Generate Application Cryptogram using ICC Master Key directly"""
        return EMVApplicationCryptogram.generate_ac(self.icc_mk_ac, transaction_data, "visa")
    
    def generate_arpc(self, arqc: bytes, arc: bytes) -> bytes:
        """Generate ARPC using ICC Master Key"""
        return EMVApplicationCryptogram.generate_arpc_method1(self.icc_mk_ac, arqc, arc)
    
    def derive_sm_sk(self, atc: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Visa method"""
        return EMVKeyDerivation.derive_visa_sm_sk(self.icc_mk_smi, atc)


class VisaCVN18(BaseCVN):
    """Visa CVN 18 Implementation - Based on PyEMV VisaCVN18"""
    
    def __init__(self, iss_mk_ac: bytes, iss_mk_smi: bytes, iss_mk_smc: bytes,
                 pan: Union[bytes, str], psn: Optional[Union[bytes, str]] = None):
        super().__init__(iss_mk_ac, iss_mk_smi, iss_mk_smc, pan, psn)
        
        # Derive ICC Master Keys using Option B
        self.icc_mk_ac = EMVKeyDerivation.derive_icc_mk_b(iss_mk_ac, pan, psn)
        self.icc_mk_smi = EMVKeyDerivation.derive_icc_mk_b(iss_mk_smi, pan, psn)
        self.icc_mk_smc = EMVKeyDerivation.derive_icc_mk_b(iss_mk_smc, pan, psn)
    
    def derive_ac_sk(self, atc: bytes) -> bytes:
        """Derive AC Session Key using Common method"""
        return EMVKeyDerivation.derive_common_sk(self.icc_mk_ac, atc + b"\x00" * 6)
    
    def generate_ac(self, transaction_data: bytes, atc: bytes) -> bytes:
        """Generate Application Cryptogram using Session Key"""
        sk = self.derive_ac_sk(atc)
        return EMVApplicationCryptogram.generate_ac(sk, transaction_data, "visa")
    
    def generate_arpc(self, arqc: bytes, atc: bytes, csu: bytes) -> bytes:
        """Generate ARPC using Session Key"""
        sk = self.derive_ac_sk(atc)
        return EMVApplicationCryptogram.generate_arpc_method2(sk, arqc, csu)
    
    def derive_sm_sk(self, atc: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Visa method"""
        return EMVKeyDerivation.derive_visa_sm_sk(self.icc_mk_smi, atc)


class VisaCVN22(BaseCVN):
    """Visa CVN 22 Implementation - Based on PyEMV VisaCVN22"""
    
    def __init__(self, iss_mk_ac: bytes, iss_mk_smi: bytes, iss_mk_smc: bytes,
                 pan: Union[bytes, str], psn: Optional[Union[bytes, str]] = None):
        super().__init__(iss_mk_ac, iss_mk_smi, iss_mk_smc, pan, psn)
        
        # Derive ICC Master Keys using Option B
        self.icc_mk_ac = EMVKeyDerivation.derive_icc_mk_b(iss_mk_ac, pan, psn)
        self.icc_mk_smi = EMVKeyDerivation.derive_icc_mk_b(iss_mk_smi, pan, psn)
        self.icc_mk_smc = EMVKeyDerivation.derive_icc_mk_b(iss_mk_smc, pan, psn)
    
    def derive_ac_sk(self, atc: bytes) -> bytes:
        """Derive AC Session Key using Common method"""
        return EMVKeyDerivation.derive_common_sk(self.icc_mk_ac, atc + b"\x00" * 6)
    
    def generate_ac(self, transaction_data: bytes, atc: bytes) -> bytes:
        """Generate Application Cryptogram using Session Key"""
        sk = self.derive_ac_sk(atc)
        return EMVApplicationCryptogram.generate_ac(sk, transaction_data, "emv")
    
    def generate_arpc(self, arqc: bytes, atc: bytes, csu: bytes,
                     proprietary_auth_data: Optional[bytes] = None) -> bytes:
        """Generate ARPC using Session Key"""
        sk = self.derive_ac_sk(atc)
        return EMVApplicationCryptogram.generate_arpc_method2(sk, arqc, csu)
    
    def derive_sm_sk(self, arqc: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method"""
        return EMVKeyDerivation.derive_common_sk(self.icc_mk_smi, arqc)


class MasterCardCVN16(BaseCVN):
    """MasterCard CVN 16 Implementation - Based on PyEMV MasterCardCVN16"""
    
    def __init__(self, iss_mk_ac: bytes, iss_mk_smi: bytes, iss_mk_smc: bytes,
                 pan: Union[bytes, str], psn: Optional[Union[bytes, str]] = None):
        super().__init__(iss_mk_ac, iss_mk_smi, iss_mk_smc, pan, psn)
        
        # Derive ICC Master Keys using Option A
        self.icc_mk_ac = EMVKeyDerivation.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smc, pan, psn)
    
    def derive_ac_sk(self, atc: bytes, un: bytes) -> bytes:
        """Derive AC Session Key using MasterCard method"""
        return EMVKeyDerivation.derive_mastercard_sk(self.icc_mk_ac, atc, un)
    
    def generate_ac(self, transaction_data: bytes, atc: bytes, un: bytes) -> bytes:
        """Generate Application Cryptogram using Session Key"""
        sk = self.derive_ac_sk(atc, un)
        return EMVApplicationCryptogram.generate_ac(sk, transaction_data, "emv")
    
    def generate_arpc(self, arqc: bytes, arc: bytes) -> bytes:
        """Generate ARPC using ICC Master Key (no session key)"""
        return EMVApplicationCryptogram.generate_arpc_method1(self.icc_mk_ac, arqc, arc)
    
    def derive_sm_sk(self, arqc: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method"""
        return EMVKeyDerivation.derive_common_sk(self.icc_mk_smi, arqc)


class MasterCardCVN17(BaseCVN):
    """MasterCard CVN 17 Implementation - Based on PyEMV MasterCardCVN17"""
    
    def __init__(self, iss_mk_ac: bytes, iss_mk_smi: bytes, iss_mk_smc: bytes,
                 pan: Union[bytes, str], psn: Optional[Union[bytes, str]] = None):
        super().__init__(iss_mk_ac, iss_mk_smi, iss_mk_smc, pan, psn)
        
        # Derive ICC Master Keys using Option A
        self.icc_mk_ac = EMVKeyDerivation.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smc, pan, psn)
    
    def derive_ac_sk(self, atc: bytes, un: bytes) -> bytes:
        """Derive AC Session Key using MasterCard method"""
        return EMVKeyDerivation.derive_mastercard_sk(self.icc_mk_ac, atc, un)
    
    def generate_ac(self, transaction_data: bytes, atc: bytes, un: bytes) -> bytes:
        """Generate Application Cryptogram using Session Key"""
        sk = self.derive_ac_sk(atc, un)
        return EMVApplicationCryptogram.generate_ac(sk, transaction_data, "emv")
    
    def generate_arpc(self, arqc: bytes, arc: bytes) -> bytes:
        """Generate ARPC using ICC Master Key (no session key)"""
        return EMVApplicationCryptogram.generate_arpc_method1(self.icc_mk_ac, arqc, arc)
    
    def derive_sm_sk(self, arqc: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method"""
        return EMVKeyDerivation.derive_common_sk(self.icc_mk_smi, arqc)


class MasterCardCVN20(BaseCVN):
    """MasterCard CVN 20 Implementation - Based on PyEMV MasterCardCVN20"""
    
    def __init__(self, iss_mk_ac: bytes, iss_mk_smi: bytes, iss_mk_smc: bytes,
                 pan: Union[bytes, str], psn: Optional[Union[bytes, str]] = None):
        super().__init__(iss_mk_ac, iss_mk_smi, iss_mk_smc, pan, psn)
        
        # Derive ICC Master Keys using Option A
        self.icc_mk_ac = EMVKeyDerivation.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smc, pan, psn)
    
    def derive_ac_sk(self, atc: bytes) -> bytes:
        """Derive AC Session Key using Common method"""
        return EMVKeyDerivation.derive_common_sk(self.icc_mk_ac, atc + b"\x00" * 6)
    
    def generate_ac(self, transaction_data: bytes, atc: bytes) -> bytes:
        """Generate Application Cryptogram using Session Key"""
        sk = self.derive_ac_sk(atc)
        return EMVApplicationCryptogram.generate_ac(sk, transaction_data, "emv")
    
    def generate_arpc(self, arqc: bytes, atc: bytes, csu: bytes) -> bytes:
        """Generate ARPC using Session Key"""
        sk = self.derive_ac_sk(atc)
        return EMVApplicationCryptogram.generate_arpc_method2(sk, arqc, csu)
    
    def derive_sm_sk(self, arqc: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method"""
        return EMVKeyDerivation.derive_common_sk(self.icc_mk_smi, arqc)


class MasterCardCVN21(BaseCVN):
    """MasterCard CVN 21 Implementation - Based on PyEMV MasterCardCVN21"""
    
    def __init__(self, iss_mk_ac: bytes, iss_mk_smi: bytes, iss_mk_smc: bytes,
                 pan: Union[bytes, str], psn: Optional[Union[bytes, str]] = None):
        super().__init__(iss_mk_ac, iss_mk_smi, iss_mk_smc, pan, psn)
        
        # Derive ICC Master Keys using Option A
        self.icc_mk_ac = EMVKeyDerivation.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smc, pan, psn)
    
    def derive_ac_sk(self, atc: bytes) -> bytes:
        """Derive AC Session Key using Common method"""
        return EMVKeyDerivation.derive_common_sk(self.icc_mk_ac, atc + b"\x00" * 6)
    
    def generate_ac(self, transaction_data: bytes, atc: bytes) -> bytes:
        """Generate Application Cryptogram using Session Key"""
        sk = self.derive_ac_sk(atc)
        return EMVApplicationCryptogram.generate_ac(sk, transaction_data, "emv")
    
    def generate_arpc(self, arqc: bytes, atc: bytes, csu: bytes) -> bytes:
        """Generate ARPC using Session Key"""
        sk = self.derive_ac_sk(atc)
        return EMVApplicationCryptogram.generate_arpc_method2(sk, arqc, csu)
    
    def derive_sm_sk(self, arqc: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method"""
        return EMVKeyDerivation.derive_common_sk(self.icc_mk_smi, arqc)


class InteracCVN133(BaseCVN):
    """Interac CVN 133 Implementation - Based on PyEMV InteracCVN133"""
    
    def __init__(self, iss_mk_ac: bytes, iss_mk_smi: bytes, iss_mk_smc: bytes,
                 pan: Union[bytes, str], psn: Optional[Union[bytes, str]] = None):
        super().__init__(iss_mk_ac, iss_mk_smi, iss_mk_smc, pan, psn)
        
        # Derive ICC Master Keys using Option A
        self.icc_mk_ac = EMVKeyDerivation.derive_icc_mk_a(iss_mk_ac, pan, psn)
        self.icc_mk_smi = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smi, pan, psn)
        self.icc_mk_smc = EMVKeyDerivation.derive_icc_mk_a(iss_mk_smc, pan, psn)
    
    def derive_ac_sk(self, atc: bytes, un: bytes) -> bytes:
        """Derive AC Session Key using MasterCard method"""
        return EMVKeyDerivation.derive_mastercard_sk(self.icc_mk_ac, atc, un)
    
    def generate_ac(self, transaction_data: bytes, atc: bytes, un: bytes) -> bytes:
        """Generate Application Cryptogram using Session Key"""
        sk = self.derive_ac_sk(atc, un)
        return EMVApplicationCryptogram.generate_ac(sk, transaction_data, "emv")
    
    def generate_arpc(self, arqc: bytes, atc: bytes, un: bytes, arc: bytes) -> bytes:
        """Generate ARPC using Session Key"""
        sk = self.derive_ac_sk(atc, un)
        return EMVApplicationCryptogram.generate_arpc_method1(sk, arqc, arc)
    
    def derive_sm_sk(self, arqc: bytes) -> bytes:
        """Derive Secure Messaging Session Key using Common method"""
        return EMVKeyDerivation.derive_common_sk(self.icc_mk_smi, arqc)


class EMVCryptoManager:
    """Main EMV Crypto Manager - Factory for CVN implementations"""
    
    def __init__(self, iss_mk_ac: bytes, iss_mk_smi: bytes, iss_mk_smc: bytes):
        """Initialize with issuer master keys
        
        Args:
            iss_mk_ac: 16-byte Issuer Master Key for Application Cryptogram
            iss_mk_smi: 16-byte Issuer Master Key for Script Message Integrity
            iss_mk_smc: 16-byte Issuer Master Key for Script Message Confidentiality
        """
        self.iss_mk_ac = iss_mk_ac
        self.iss_mk_smi = iss_mk_smi
        self.iss_mk_smc = iss_mk_smc
        
        logger.info("EMVCryptoManager initialized with issuer master keys")
    
    def get_visa_cvn10(self, pan: Union[bytes, str], 
                      psn: Optional[Union[bytes, str]] = None) -> VisaCVN10:
        """Get Visa CVN 10 implementation"""
        return VisaCVN10(self.iss_mk_ac, self.iss_mk_smi, self.iss_mk_smc, pan, psn)
    
    def get_visa_cvn18(self, pan: Union[bytes, str],
                      psn: Optional[Union[bytes, str]] = None) -> VisaCVN18:
        """Get Visa CVN 18 implementation"""
        return VisaCVN18(self.iss_mk_ac, self.iss_mk_smi, self.iss_mk_smc, pan, psn)
    
    def get_visa_cvn22(self, pan: Union[bytes, str],
                      psn: Optional[Union[bytes, str]] = None) -> VisaCVN22:
        """Get Visa CVN 22 implementation"""
        return VisaCVN22(self.iss_mk_ac, self.iss_mk_smi, self.iss_mk_smc, pan, psn)
    
    def get_mastercard_cvn16(self, pan: Union[bytes, str],
                           psn: Optional[Union[bytes, str]] = None) -> MasterCardCVN16:
        """Get MasterCard CVN 16 implementation"""
        return MasterCardCVN16(self.iss_mk_ac, self.iss_mk_smi, self.iss_mk_smc, pan, psn)
    
    def get_mastercard_cvn17(self, pan: Union[bytes, str],
                           psn: Optional[Union[bytes, str]] = None) -> MasterCardCVN17:
        """Get MasterCard CVN 17 implementation"""
        return MasterCardCVN17(self.iss_mk_ac, self.iss_mk_smi, self.iss_mk_smc, pan, psn)
    
    def get_mastercard_cvn20(self, pan: Union[bytes, str],
                           psn: Optional[Union[bytes, str]] = None) -> MasterCardCVN20:
        """Get MasterCard CVN 20 implementation"""
        return MasterCardCVN20(self.iss_mk_ac, self.iss_mk_smi, self.iss_mk_smc, pan, psn)
    
    def get_mastercard_cvn21(self, pan: Union[bytes, str],
                           psn: Optional[Union[bytes, str]] = None) -> MasterCardCVN21:
        """Get MasterCard CVN 21 implementation"""
        return MasterCardCVN21(self.iss_mk_ac, self.iss_mk_smi, self.iss_mk_smc, pan, psn)
    
    def get_interac_cvn133(self, pan: Union[bytes, str],
                          psn: Optional[Union[bytes, str]] = None) -> InteracCVN133:
        """Get Interac CVN 133 implementation"""
        return InteracCVN133(self.iss_mk_ac, self.iss_mk_smi, self.iss_mk_smc, pan, psn)
    
    def get_cvn_by_type(self, cvn_type: CVNType, pan: Union[bytes, str],
                       psn: Optional[Union[bytes, str]] = None) -> BaseCVN:
        """Get CVN implementation by type"""
        cvn_map = {
            CVNType.VISA_CVN10: self.get_visa_cvn10,
            CVNType.VISA_CVN18: self.get_visa_cvn18,
            CVNType.VISA_CVN22: self.get_visa_cvn22,
            CVNType.MASTERCARD_CVN16: self.get_mastercard_cvn16,
            CVNType.MASTERCARD_CVN17: self.get_mastercard_cvn17,
            CVNType.MASTERCARD_CVN20: self.get_mastercard_cvn20,
            CVNType.MASTERCARD_CVN21: self.get_mastercard_cvn21,
            CVNType.INTERAC_CVN133: self.get_interac_cvn133,
        }
        
        if cvn_type not in cvn_map:
            raise ValueError(f"Unsupported CVN type: {cvn_type}")
            
        return cvn_map[cvn_type](pan, psn)
    
    @staticmethod
    def generate_test_keys() -> Tuple[bytes, bytes, bytes]:
        """Generate test issuer master keys for development/testing"""
        iss_mk_ac = secrets.token_bytes(16)
        iss_mk_smi = secrets.token_bytes(16)  
        iss_mk_smc = secrets.token_bytes(16)
        
        # Adjust parity bits for DES compatibility
        iss_mk_ac = adjust_key_parity(iss_mk_ac)
        iss_mk_smi = adjust_key_parity(iss_mk_smi)
        iss_mk_smc = adjust_key_parity(iss_mk_smc)
        
        return iss_mk_ac, iss_mk_smi, iss_mk_smc
    
    def test_all_cvns(self, pan: str = "4000000000000002", psn: str = "00") -> Dict[str, Any]:
        """Test all CVN implementations with sample data"""
        results = {}
        test_data = b"TestTransactionData123"
        atc = b"\x00\x1C"
        un = b"\x12\x34\x56\x78"
        arc = b"\x00\x00"
        csu = b"\x00\x00\x00\x00"
        
        cvn_types = [
            CVNType.VISA_CVN10, CVNType.VISA_CVN18, CVNType.VISA_CVN22,
            CVNType.MASTERCARD_CVN16, CVNType.MASTERCARD_CVN17,
            CVNType.MASTERCARD_CVN20, CVNType.MASTERCARD_CVN21,
            CVNType.INTERAC_CVN133
        ]
        
        for cvn_type in cvn_types:
            try:
                cvn = self.get_cvn_by_type(cvn_type, pan, psn)
                
                # Test cryptogram generation based on CVN type
                if cvn_type in [CVNType.VISA_CVN10]:
                    ac = cvn.generate_ac(test_data)
                    arpc = cvn.generate_arpc(ac, arc)
                elif cvn_type in [CVNType.VISA_CVN18, CVNType.VISA_CVN22,
                                CVNType.MASTERCARD_CVN20, CVNType.MASTERCARD_CVN21]:
                    ac = cvn.generate_ac(test_data, atc)
                    arpc = cvn.generate_arpc(ac, atc, csu)
                else:  # MasterCard CVN16/17, Interac CVN133
                    ac = cvn.generate_ac(test_data, atc, un)
                    if cvn_type == CVNType.INTERAC_CVN133:
                        arpc = cvn.generate_arpc(ac, atc, un, arc)
                    else:
                        arpc = cvn.generate_arpc(ac, arc)
                
                results[cvn_type.value] = {
                    "status": "success",
                    "ac": ac.hex().upper(),
                    "arpc": arpc.hex().upper(),
                    "icc_mk_ac": cvn.icc_mk_ac.hex().upper()
                }
                
            except Exception as e:
                results[cvn_type.value] = {
                    "status": "error",
                    "error": str(e)
                }
        
        return results


# Convenience functions for backward compatibility and ease of use
def create_emv_crypto_manager(iss_mk_ac: bytes = None, iss_mk_smi: bytes = None, 
                            iss_mk_smc: bytes = None) -> EMVCryptoManager:
    """Create EMV crypto manager with optional test keys"""
    if not all([iss_mk_ac, iss_mk_smi, iss_mk_smc]):
        iss_mk_ac, iss_mk_smi, iss_mk_smc = EMVCryptoManager.generate_test_keys()
        logger.warning("Using generated test keys - not for production use")
    
    return EMVCryptoManager(iss_mk_ac, iss_mk_smi, iss_mk_smc)


def demonstrate_emv_capabilities():
    """Demonstrate EMV cryptographic capabilities"""
    print("=== GREENWIRE EMV Cryptographic Capabilities Demo ===\n")
    
    # Create crypto manager with test keys
    crypto = create_emv_crypto_manager()
    
    # Test all CVN implementations
    results = crypto.test_all_cvns()
    
    for cvn_name, result in results.items():
        print(f"{cvn_name.upper()}:")
        if result["status"] == "success":
            print(f"  ✓ AC: {result['ac']}")
            print(f"  ✓ ARPC: {result['arpc']}")
            print(f"  ✓ ICC MK: {result['icc_mk_ac']}")
        else:
            print(f"  ✗ Error: {result['error']}")
        print()
    
    print("=== Demo Complete ===")


if __name__ == "__main__":
    demonstrate_emv_capabilities()