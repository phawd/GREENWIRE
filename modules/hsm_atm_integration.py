#!/usr/bin/env python3
"""
HSM/ATM Integration Module
Simulates HSM and ATM operations with bidirectional learning integration.

HSM Operations:
- PIN translation and validation
- CVV/CVV2 generation and verification
- MAC generation (CMAC, HMAC)
- Cryptogram processing (ARQC validation, ARPC generation)
- Key management operations

ATM Operations:
- Cash withdrawal testing
- Balance inquiry testing
- Card authentication
- PIN entry security
- Transaction logging

Bidirectional Learning:
- Cards → HSM/ATM: Report test results, vulnerabilities, timing patterns
- HSM/ATM → Cards: Updated test recommendations, merchant profiles, known exploits
- Shared knowledge base for ecosystem-wide intelligence
"""

import os
import json
import sqlite3
import hashlib
import hmac
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from enum import Enum

try:
    from Crypto.Cipher import DES3, AES
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import CMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARN] pycryptodome not available, using mocked cryptographic operations")


class HSMOperation(Enum):
    """HSM operation types."""
    PIN_TRANSLATE = "pin_translate"
    PIN_VERIFY = "pin_verify"
    CVV_GENERATE = "cvv_generate"
    CVV_VERIFY = "cvv_verify"
    MAC_GENERATE = "mac_generate"
    MAC_VERIFY = "mac_verify"
    ARQC_VALIDATE = "arqc_validate"
    ARPC_GENERATE = "arpc_generate"
    KEY_GENERATE = "key_generate"
    KEY_DISTRIBUTE = "key_distribute"


class ATMOperation(Enum):
    """ATM operation types."""
    WITHDRAW = "withdraw"
    BALANCE_INQUIRY = "balance_inquiry"
    CARD_AUTH = "card_authentication"
    PIN_ENTRY = "pin_entry"
    TRANSACTION_LOG = "transaction_log"


class HSMATMIntegration:
    """
    HSM/ATM integration with bidirectional learning.

    Simulates payment HSM and ATM operations while learning from card interactions
    and sharing intelligence back to cards.
    """

    def __init__(self, knowledge_base_path: str = "ai_learning_sessions/hsm_atm_knowledge.db"):
        """
        Initialize HSM/ATM integration.

        Args:
            knowledge_base_path: Path to shared knowledge base
        """
        self.knowledge_base_path = knowledge_base_path
        self._ensure_knowledge_base()

        # Mock HSM keys (in production, these would be hardware-backed)
        self.master_keys = {
            "pin_key": b"0123456789ABCDEF0123456789ABCDEF",  # TDES key
            "cvv_key": b"FEDCBA9876543210FEDCBA9876543210",  # TDES key
            "mac_key": b"ABCDEF0123456789ABCDEF0123456789",  # TDES key
            "data_key": b"DEADBEEFCAFEBABE" * 2               # AES-256 key
        }

        print("[HSM/ATM Integration] Initialized")

    def _ensure_knowledge_base(self):
        """Ensure shared knowledge base database exists."""
        os.makedirs(os.path.dirname(self.knowledge_base_path) or ".", exist_ok=True)

        conn = sqlite3.connect(self.knowledge_base_path)
        cursor = conn.cursor()

        # Merchant vulnerability profiles
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS merchant_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                merchant_id TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity REAL NOT NULL,
                discovered_by TEXT,
                discovery_date TEXT NOT NULL,
                attack_vector TEXT,
                exploit_success_rate REAL,
                UNIQUE(merchant_id, vulnerability_type)
            )
        """)

        # Test recommendations (HSM/ATM → Cards)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS test_recommendations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                merchant_id TEXT NOT NULL,
                test_id TEXT NOT NULL,
                priority REAL NOT NULL,
                reason TEXT,
                created_date TEXT NOT NULL
            )
        """)

        # Card reports (Cards → HSM/ATM)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS card_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_id TEXT NOT NULL,
                merchant_id TEXT NOT NULL,
                report_type TEXT NOT NULL,
                report_data TEXT,
                timestamp TEXT NOT NULL
            )
        """)

        # HSM operation logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hsm_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                card_id TEXT,
                merchant_id TEXT,
                success BOOLEAN,
                error_code TEXT,
                execution_time_ms INTEGER,
                timestamp TEXT NOT NULL
            )
        """)

        # ATM operation logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS atm_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                card_id TEXT NOT NULL,
                amount REAL,
                success BOOLEAN,
                error_code TEXT,
                execution_time_ms INTEGER,
                timestamp TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    # ========================================================================
    # HSM OPERATIONS
    # ========================================================================

    def hsm_pin_translate(
        self,
        card_id: str,
        encrypted_pin: bytes,
        source_key_id: str,
        dest_key_id: str
    ) -> Tuple[bool, Optional[bytes], str]:
        """
        Translate PIN from one encryption key to another.

        Used when routing PIN from acquirer network (encrypted with acquirer key)
        to issuer network (encrypted with issuer key).

        Args:
            card_id: Card identifier
            encrypted_pin: PIN encrypted with source key
            source_key_id: Source key identifier
            dest_key_id: Destination key identifier

        Returns:
            (success, re_encrypted_pin, message)
        """
        start_time = datetime.now()

        try:
            if not CRYPTO_AVAILABLE:
                # Mock operation
                result = (True, encrypted_pin, "PIN translated (mocked)")
            else:
                # Decrypt with source key
                source_key = self.master_keys.get("pin_key")
                cipher = DES3.new(source_key, DES3.MODE_ECB)
                plaintext_pin = cipher.decrypt(encrypted_pin)

                # Re-encrypt with destination key
                dest_key = self.master_keys.get("pin_key")  # In reality, different key
                cipher = DES3.new(dest_key, DES3.MODE_ECB)
                re_encrypted_pin = cipher.encrypt(plaintext_pin)

                result = (True, re_encrypted_pin, "PIN translated successfully")

            # Log operation
            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.PIN_TRANSLATE, card_id, None, True, None, exec_time)

            return result

        except Exception as e:
            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.PIN_TRANSLATE, card_id, None, False, str(e), exec_time)
            return (False, None, f"PIN translation failed: {e}")

    def hsm_pin_verify(
        self,
        card_id: str,
        encrypted_pin: bytes,
        pin_offset: bytes
    ) -> Tuple[bool, str]:
        """
        Verify PIN using PIN offset method.

        Args:
            card_id: Card identifier
            encrypted_pin: Encrypted PIN block
            pin_offset: PIN offset from card data

        Returns:
            (success, message)
        """
        start_time = datetime.now()

        try:
            # Mock verification
            # In production: decrypt PIN, apply offset, compare with account PAN
            success = True  # Mock success

            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.PIN_VERIFY, card_id, None, success, None, exec_time)

            return (success, "PIN verification successful" if success else "PIN verification failed")

        except Exception as e:
            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.PIN_VERIFY, card_id, None, False, str(e), exec_time)
            return (False, f"PIN verification error: {e}")

    def hsm_cvv_generate(
        self,
        pan: str,
        expiry_date: str,
        service_code: str
    ) -> Tuple[bool, Optional[str], str]:
        """
        Generate CVV/CVV2 value.

        Args:
            pan: Primary Account Number (PAN)
            expiry_date: Expiry date (YYMM)
            service_code: Service code (3 digits)

        Returns:
            (success, cvv, message)
        """
        start_time = datetime.now()

        try:
            if not CRYPTO_AVAILABLE:
                # Mock CVV
                cvv = "123"
                result = (True, cvv, "CVV generated (mocked)")
            else:
                # CVV generation algorithm (simplified)
                # Real: EMV CVV generation per EMV Book 2
                data = (pan + expiry_date + service_code).encode()

                key = self.master_keys.get("cvv_key")
                cipher = DES3.new(key, DES3.MODE_ECB)

                # Pad data
                padded = data + b'\x00' * (8 - len(data) % 8)
                encrypted = cipher.encrypt(padded[:8])

                # Extract 3 digits
                cvv = str(int.from_bytes(encrypted[:2], 'big') % 1000).zfill(3)

                result = (True, cvv, "CVV generated successfully")

            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.CVV_GENERATE, None, None, True, None, exec_time)

            return result

        except Exception as e:
            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.CVV_GENERATE, None, None, False, str(e), exec_time)
            return (False, None, f"CVV generation failed: {e}")

    def hsm_cvv_verify(
        self,
        pan: str,
        expiry_date: str,
        service_code: str,
        cvv_provided: str
    ) -> Tuple[bool, str]:
        """
        Verify CVV value.

        Args:
            pan: Primary Account Number
            expiry_date: Expiry date (YYMM)
            service_code: Service code
            cvv_provided: CVV to verify

        Returns:
            (success, message)
        """
        success, cvv_generated, msg = self.hsm_cvv_generate(pan, expiry_date, service_code)

        if not success:
            return (False, f"CVV verification failed: {msg}")

        if cvv_generated == cvv_provided:
            return (True, "CVV verified successfully")
        else:
            return (False, "CVV verification failed: mismatch")

    def hsm_mac_generate(
        self,
        data: bytes,
        algorithm: str = "CMAC"
    ) -> Tuple[bool, Optional[bytes], str]:
        """
        Generate MAC (Message Authentication Code).

        Args:
            data: Data to authenticate
            algorithm: MAC algorithm (CMAC, HMAC)

        Returns:
            (success, mac, message)
        """
        start_time = datetime.now()

        try:
            if not CRYPTO_AVAILABLE:
                # Mock MAC
                mac = hashlib.sha256(data).digest()[:8]
                result = (True, mac, "MAC generated (mocked)")
            else:
                key = self.master_keys.get("mac_key")

                if algorithm == "CMAC":
                    cobj = CMAC.new(key, ciphermod=DES3)
                    cobj.update(data)
                    mac = cobj.digest()
                else:  # HMAC
                    mac = hmac.new(key, data, hashlib.sha256).digest()[:8]

                result = (True, mac, "MAC generated successfully")

            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.MAC_GENERATE, None, None, True, None, exec_time)

            return result

        except Exception as e:
            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.MAC_GENERATE, None, None, False, str(e), exec_time)
            return (False, None, f"MAC generation failed: {e}")

    def hsm_arqc_validate(
        self,
        card_id: str,
        merchant_id: str,
        arqc: bytes,
        transaction_data: Dict
    ) -> Tuple[bool, str]:
        """
        Validate ARQC (Authorization Request Cryptogram).

        Args:
            card_id: Card identifier
            merchant_id: Merchant identifier
            arqc: ARQC bytes (8 bytes)
            transaction_data: Transaction data dict

        Returns:
            (success, message)
        """
        start_time = datetime.now()

        try:
            # Mock validation
            # In production: derive card key, generate ARQC, compare
            success = True  # Mock success

            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.ARQC_VALIDATE, card_id, merchant_id, success, None, exec_time)

            if success:
                return (True, "ARQC validated successfully")
            else:
                return (False, "ARQC validation failed")

        except Exception as e:
            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.ARQC_VALIDATE, card_id, merchant_id, False, str(e), exec_time)
            return (False, f"ARQC validation error: {e}")

    def hsm_arpc_generate(
        self,
        card_id: str,
        arqc: bytes,
        authorization_code: str
    ) -> Tuple[bool, Optional[bytes], str]:
        """
        Generate ARPC (Authorization Response Cryptogram).

        Args:
            card_id: Card identifier
            arqc: ARQC from card
            authorization_code: Authorization response code (2 bytes)

        Returns:
            (success, arpc, message)
        """
        start_time = datetime.now()

        try:
            if not CRYPTO_AVAILABLE:
                # Mock ARPC
                arpc = hashlib.sha256(arqc + authorization_code.encode()).digest()[:8]
                result = (True, arpc, "ARPC generated (mocked)")
            else:
                # ARPC generation (simplified)
                # Real: EMV ARPC generation per EMV Book 2
                key = self.master_keys.get("data_key")
                cipher = DES3.new(key[:24], DES3.MODE_ECB)

                data = arqc + authorization_code.encode() + b'\x00' * 6
                arpc = cipher.encrypt(data[:8])

                result = (True, arpc, "ARPC generated successfully")

            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.ARPC_GENERATE, card_id, None, True, None, exec_time)

            return result

        except Exception as e:
            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_hsm_operation(HSMOperation.ARPC_GENERATE, card_id, None, False, str(e), exec_time)
            return (False, None, f"ARPC generation failed: {e}")

    # ========================================================================
    # ATM OPERATIONS
    # ========================================================================

    def atm_withdraw(
        self,
        card_id: str,
        amount: float,
        pin: str
    ) -> Tuple[bool, str]:
        """
        Simulate ATM cash withdrawal.

        Args:
            card_id: Card identifier
            amount: Withdrawal amount
            pin: PIN entered

        Returns:
            (success, message)
        """
        start_time = datetime.now()

        try:
            # Validate amount
            if amount <= 0 or amount > 10000:
                result = (False, f"Invalid amount: {amount}")
            else:
                # Mock authorization
                success = True  # Mock success
                result = (success, f"Withdrawal of ${amount} approved" if success else "Withdrawal declined")

            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_atm_operation(ATMOperation.WITHDRAW, card_id, amount, result[0], None, exec_time)

            return result

        except Exception as e:
            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_atm_operation(ATMOperation.WITHDRAW, card_id, amount, False, str(e), exec_time)
            return (False, f"Withdrawal error: {e}")

    def atm_balance_inquiry(
        self,
        card_id: str,
        pin: str
    ) -> Tuple[bool, Optional[float], str]:
        """
        Simulate ATM balance inquiry.

        Args:
            card_id: Card identifier
            pin: PIN entered

        Returns:
            (success, balance, message)
        """
        start_time = datetime.now()

        try:
            # Mock balance
            balance = 5432.10
            result = (True, balance, "Balance inquiry successful")

            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_atm_operation(ATMOperation.BALANCE_INQUIRY, card_id, None, True, None, exec_time)

            return result

        except Exception as e:
            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_atm_operation(ATMOperation.BALANCE_INQUIRY, card_id, None, False, str(e), exec_time)
            return (False, None, f"Balance inquiry error: {e}")

    def atm_card_authenticate(
        self,
        card_id: str,
        atr: str
    ) -> Tuple[bool, str]:
        """
        Authenticate card at ATM.

        Args:
            card_id: Card identifier
            atr: ATR (Answer To Reset)

        Returns:
            (success, message)
        """
        start_time = datetime.now()

        try:
            # Mock authentication
            success = True  # Mock success
            result = (success, "Card authenticated successfully" if success else "Card authentication failed")

            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_atm_operation(ATMOperation.CARD_AUTH, card_id, None, success, None, exec_time)

            return result

        except Exception as e:
            exec_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_atm_operation(ATMOperation.CARD_AUTH, card_id, None, False, str(e), exec_time)
            return (False, f"Card authentication error: {e}")

    # ========================================================================
    # WRAPPER METHODS FOR INTELLIGENT_CARD_SYSTEM COMPATIBILITY
    # ========================================================================

    def generate_pin_key(self, card_id: str) -> bytes:
        """
        Generate PIN encryption key for a card (wrapper for intelligent_card_system).

        Args:
            card_id: Card identifier

        Returns:
            pin_key: 16-byte Triple-DES key
        """
        # Generate deterministic key based on card_id for consistency
        key_material = hashlib.sha256(f"PIN_KEY_{card_id}".encode()).digest()
        return key_material[:16]  # 16 bytes for 3DES

    def generate_cvv(self, card_number: str, expiry_date: str, service_code: str) -> str:
        """
        Generate CVV/CVV2 value (wrapper for intelligent_card_system).

        Args:
            card_number: Primary Account Number (PAN)
            expiry_date: Expiry date (YYMM or MMYY format)
            service_code: Service code (3 digits)

        Returns:
            cvv: 3-digit CVV string
        """
        success, cvv, message = self.hsm_cvv_generate(card_number, expiry_date, service_code)
        if success:
            return cvv
        else:
            # Fallback to deterministic mock CVV
            cvv_hash = hashlib.sha256(f"{card_number}{expiry_date}{service_code}".encode()).digest()
            return str(int.from_bytes(cvv_hash[:2], 'big') % 1000).zfill(3)

    def generate_mac(self, card_id: str, data: bytes) -> bytes:
        """
        Generate MAC for data (wrapper for intelligent_card_system).

        Args:
            card_id: Card identifier
            data: Data to authenticate

        Returns:
            mac: 8-byte MAC
        """
        success, mac, message = self.hsm_mac_generate(data, algorithm="CMAC")
        if success:
            return mac
        else:
            # Fallback to simple HMAC
            return hashlib.sha256(data).digest()[:8]

    def validate_arqc(self, card_id: str, arqc: bytes, transaction_data: Dict) -> Dict:
        """
        Validate ARQC cryptogram (wrapper for intelligent_card_system).

        Args:
            card_id: Card identifier
            arqc: ARQC bytes
            transaction_data: Transaction data dictionary

        Returns:
            validation_result: Dict with 'valid' bool and 'message' string
        """
        merchant_id = transaction_data.get("merchant_id", "UNKNOWN")
        success, message = self.hsm_arqc_validate(card_id, merchant_id, arqc, transaction_data)
        return {
            "valid": success,
            "message": message
        }

    # ========================================================================
    # BIDIRECTIONAL LEARNING
    # ========================================================================

    def receive_card_report(
        self,
        card_id: str,
        merchant_id: str,
        report_type: str,
        report_data: Dict
    ):
        """
        Receive intelligence report from card (Cards → HSM/ATM).

        Args:
            card_id: Card identifier
            merchant_id: Merchant identifier
            report_type: Report type (vulnerability, timing_anomaly, test_result)
            report_data: Report data dict
        """
        conn = sqlite3.connect(self.knowledge_base_path)
        cursor = conn.cursor()

        # Store report
        cursor.execute("""
            INSERT INTO card_reports (
                card_id,
                merchant_id,
                report_type,
                report_data,
                timestamp
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            card_id,
            merchant_id,
            report_type,
            json.dumps(report_data),
            datetime.now().isoformat()
        ))

        # If vulnerability report, update merchant vulnerabilities
        if report_type == "vulnerability":
            cursor.execute("""
                INSERT INTO merchant_vulnerabilities (
                    merchant_id,
                    vulnerability_type,
                    severity,
                    discovered_by,
                    discovery_date,
                    attack_vector,
                    exploit_success_rate
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(merchant_id, vulnerability_type) DO UPDATE SET
                    severity = MAX(severity, ?),
                    exploit_success_rate = (exploit_success_rate + ?) / 2.0
            """, (
                merchant_id,
                report_data.get("vulnerability_type"),
                report_data.get("severity", 0.5),
                card_id,
                datetime.now().isoformat(),
                report_data.get("attack_vector"),
                report_data.get("exploit_success_rate", 0.0),
                report_data.get("severity", 0.5),
                report_data.get("exploit_success_rate", 0.0)
            ))

        conn.commit()
        conn.close()

        print(f"[HSM/ATM] Received {report_type} report from card {card_id} for merchant {merchant_id}")

    def generate_test_recommendations(
        self,
        merchant_id: str,
        card_id: Optional[str] = None
    ) -> List[Dict]:
        """
        Generate test recommendations for cards (HSM/ATM → Cards).

        Based on ecosystem-wide intelligence from all cards.

        Args:
            merchant_id: Merchant identifier
            card_id: Optional card identifier for targeted recommendations

        Returns:
            List of test recommendation dicts
        """
        conn = sqlite3.connect(self.knowledge_base_path)
        cursor = conn.cursor()

        # Get merchant vulnerabilities
        cursor.execute("""
            SELECT vulnerability_type, severity, exploit_success_rate
            FROM merchant_vulnerabilities
            WHERE merchant_id = ?
            ORDER BY severity DESC, exploit_success_rate DESC
            LIMIT 10
        """, (merchant_id,))

        vulnerabilities = cursor.fetchall()

        recommendations = []

        # Generate recommendations based on vulnerabilities
        for vuln_type, severity, success_rate in vulnerabilities:
            # Map vulnerability type to test IDs (simplified mapping)
            test_mapping = {
                "CVM_downgrade": "T031_CVM_DOWNGRADE_ATTACK",
                "PIN_bypass": "T032_PIN_RETRY_LIMITS",
                "ARQC_weak": "T013_ARQC_VALIDATION",
                "DDA_failure": "T011_DDA_VALIDATION",
                "timing_leak": "T045_TIMING_ATTACK_RESISTANCE"
            }

            test_id = test_mapping.get(vuln_type, "T001_APPLICATION_SELECTION")

            recommendation = {
                "test_id": test_id,
                "priority": severity * 100,
                "reason": f"Known vulnerability: {vuln_type} (success rate: {success_rate:.1%})",
                "merchant_id": merchant_id
            }

            recommendations.append(recommendation)

            # Store recommendation
            cursor.execute("""
                INSERT INTO test_recommendations (
                    merchant_id,
                    test_id,
                    priority,
                    reason,
                    created_date
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                merchant_id,
                test_id,
                severity * 100,
                recommendation["reason"],
                datetime.now().isoformat()
            ))

        conn.commit()
        conn.close()

        print(f"[HSM/ATM] Generated {len(recommendations)} test recommendations for merchant {merchant_id}")

        return recommendations

    def get_merchant_intelligence(
        self,
        merchant_id: str
    ) -> Dict:
        """
        Get comprehensive intelligence about a merchant.

        Args:
            merchant_id: Merchant identifier

        Returns:
            Intelligence dict with vulnerabilities, recommendations, history
        """
        conn = sqlite3.connect(self.knowledge_base_path)
        cursor = conn.cursor()

        # Get vulnerabilities
        cursor.execute("""
            SELECT vulnerability_type, severity, attack_vector, exploit_success_rate
            FROM merchant_vulnerabilities
            WHERE merchant_id = ?
            ORDER BY severity DESC
        """, (merchant_id,))

        vulnerabilities = [
            {
                "type": row[0],
                "severity": row[1],
                "attack_vector": row[2],
                "exploit_success_rate": row[3]
            }
            for row in cursor.fetchall()
        ]

        # Get recent reports
        cursor.execute("""
            SELECT card_id, report_type, report_data, timestamp
            FROM card_reports
            WHERE merchant_id = ?
            ORDER BY timestamp DESC
            LIMIT 10
        """, (merchant_id,))

        recent_reports = [
            {
                "card_id": row[0],
                "report_type": row[1],
                "report_data": json.loads(row[2]),
                "timestamp": row[3]
            }
            for row in cursor.fetchall()
        ]

        conn.close()

        return {
            "merchant_id": merchant_id,
            "vulnerabilities": vulnerabilities,
            "recent_reports": recent_reports,
            "risk_score": sum(v["severity"] for v in vulnerabilities) / max(len(vulnerabilities), 1)
        }

    def _log_hsm_operation(
        self,
        operation_type: HSMOperation,
        card_id: Optional[str],
        merchant_id: Optional[str],
        success: bool,
        error_code: Optional[str],
        execution_time_ms: int
    ):
        """Log HSM operation to database."""
        conn = sqlite3.connect(self.knowledge_base_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO hsm_operations (
                operation_type,
                card_id,
                merchant_id,
                success,
                error_code,
                execution_time_ms,
                timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            operation_type.value,
            card_id,
            merchant_id,
            success,
            error_code,
            execution_time_ms,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

    def _log_atm_operation(
        self,
        operation_type: ATMOperation,
        card_id: str,
        amount: Optional[float],
        success: bool,
        error_code: Optional[str],
        execution_time_ms: int
    ):
        """Log ATM operation to database."""
        conn = sqlite3.connect(self.knowledge_base_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO atm_operations (
                operation_type,
                card_id,
                amount,
                success,
                error_code,
                execution_time_ms,
                timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            operation_type.value,
            card_id,
            amount,
            success,
            error_code,
            execution_time_ms,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()


if __name__ == "__main__":
    # Demo usage
    hsm_atm = HSMATMIntegration()

    print("=" * 70)
    print("HSM/ATM INTEGRATION DEMO")
    print("=" * 70)

    # HSM operations
    print("\n[HSM Operations]")

    success, cvv, msg = hsm_atm.hsm_cvv_generate("4532123456789012", "2512", "201")
    print(f"  CVV Generation: {msg} → CVV={cvv}")

    success, arpc, msg = hsm_atm.hsm_arpc_generate("CARD_001", b"12345678", "00")
    print(f"  ARPC Generation: {msg}")

    # ATM operations
    print("\n[ATM Operations]")

    success, msg = hsm_atm.atm_card_authenticate("CARD_001", "3B6E00FF80318066B0840101DEADBEEF")
    print(f"  Card Authentication: {msg}")

    success, balance, msg = hsm_atm.atm_balance_inquiry("CARD_001", "1234")
    print(f"  Balance Inquiry: {msg} → Balance=${balance}")

    success, msg = hsm_atm.atm_withdraw("CARD_001", 200.00, "1234")
    print(f"  Withdrawal: {msg}")

    # Bidirectional learning
    print("\n[Bidirectional Learning]")

    # Card reports vulnerability
    hsm_atm.receive_card_report(
        card_id="CARD_001",
        merchant_id="MERCHANT_001",
        report_type="vulnerability",
        report_data={
            "vulnerability_type": "CVM_downgrade",
            "severity": 0.9,
            "attack_vector": "Modified CVM list",
            "exploit_success_rate": 0.75
        }
    )

    # HSM/ATM generates recommendations
    recommendations = hsm_atm.generate_test_recommendations("MERCHANT_001")
    print(f"  Generated {len(recommendations)} test recommendations")

    # Get merchant intelligence
    intel = hsm_atm.get_merchant_intelligence("MERCHANT_001")
    print(f"  Merchant risk score: {intel['risk_score']:.2f}")
    print(f"  Known vulnerabilities: {len(intel['vulnerabilities'])}")
