#!/usr/bin/env python3
"""
Comprehensive Merchant/Terminal/ATM/HSM Test Library
Defines 50+ diverse security tests across 8 categories based on industry research.

Categories:
1. Protocol Compliance (EMV, ISO 7816, ISO 14443)
2. Cryptographic Validation (DDA, SDA, CDA, ARQC)
3. Transaction Flow Testing
4. Security Boundary Testing
5. Fault Injection & Error Handling
6. Timing & Side-Channel Analysis
7. Interface Security (NFC, contact, magstripe)
8. Risk Management & Authentication

References:
- PCI PTS POI v7.0
- EMVCo Contactless Specifications v2.10
- ISO/IEC 7816-4 (Smart Card APDU)
- ISO/IEC 14443 (Contactless Cards)
- Cambridge EMV Research (Murdoch, Anderson)
"""

from typing import Dict, List, Optional
from enum import Enum


class TestCategory(Enum):
    """Test category classifications."""
    PROTOCOL_COMPLIANCE = "protocol_compliance"
    CRYPTOGRAPHIC = "cryptographic"
    TRANSACTION_FLOW = "transaction_flow"
    SECURITY_BOUNDARY = "security_boundary"
    FAULT_INJECTION = "fault_injection"
    TIMING_ANALYSIS = "timing_analysis"
    INTERFACE_SECURITY = "interface_security"
    RISK_MANAGEMENT = "risk_management"


class TestSeverity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = 1.0  # Complete bypass, key extraction
    HIGH = 0.8      # Significant security weakness
    MEDIUM = 0.5    # Protocol deviation
    LOW = 0.3       # Minor non-compliance
    INFO = 0.1      # Informational


class MerchantTestLibrary:
    """
    Library of 50+ merchant/terminal/ATM/HSM security tests.

    Each test includes:
    - Unique ID and name
    - Category classification
    - APDUs or commands to execute
    - Expected responses
    - Vulnerability indicators
    - Severity rating
    - References to standards
    """

    def __init__(self):
        """Initialize test library."""
        self.tests = self._define_all_tests()

    def _define_all_tests(self) -> Dict[str, Dict]:
        """Define all 50+ security tests."""
        tests = {}

        # ===================================================================
        # CATEGORY 1: PROTOCOL COMPLIANCE (10 tests)
        # ===================================================================

        tests["T001_APPLICATION_SELECTION"] = {
            "name": "Application Selection Protocol",
            "category": TestCategory.PROTOCOL_COMPLIANCE,
            "severity": TestSeverity.HIGH,
            "description": "Validate proper SELECT command handling per ISO 7816-4",
            "apdu": [0x00, 0xA4, 0x04, 0x00],  # SELECT by AID
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Proper P1/P2 handling",
                "FCI (File Control Information) returned",
                "AID selection uniqueness"
            ],
            "vulnerabilities": [
                "Application selection manipulation",
                "Multi-app prioritization bypass"
            ],
            "reference": "EMVCo Book 1 Section 11.3"
        }

        tests["T002_GPO_PDOL_FORMAT"] = {
            "name": "GET PROCESSING OPTIONS PDOL Validation",
            "category": TestCategory.PROTOCOL_COMPLIANCE,
            "severity": TestSeverity.HIGH,
            "description": "Test PDOL (Processing Options Data Object List) handling",
            "apdu": [0x80, 0xA8, 0x00, 0x00],  # GPO command
            "expected_sw": [0x90, 0x00],
            "checks": [
                "PDOL format validation",
                "Missing tags rejected",
                "AIP+AFL response format"
            ],
            "vulnerabilities": [
                "Malformed PDOL acceptance",
                "Terminal capability manipulation"
            ],
            "reference": "EMVCo Book 3 Section 6.5.8"
        }

        tests["T003_READ_RECORD_VALIDATION"] = {
            "name": "READ RECORD SFI Validation",
            "category": TestCategory.PROTOCOL_COMPLIANCE,
            "severity": TestSeverity.MEDIUM,
            "description": "Validate SFI (Short File Identifier) and record handling",
            "apdu": [0x00, 0xB2, 0x01, 0x0C],  # READ RECORD
            "expected_sw": [0x90, 0x00],
            "checks": [
                "SFI range validation (1-10)",
                "Record number validation",
                "TLV data integrity"
            ],
            "vulnerabilities": [
                "Out-of-bounds record access",
                "Data leakage through sequential reads"
            ],
            "reference": "ISO/IEC 7816-4 Section 7.3"
        }

        tests["T004_VERIFY_PIN_FORMAT"] = {
            "name": "PIN Verification Format Check",
            "category": TestCategory.PROTOCOL_COMPLIANCE,
            "severity": TestSeverity.CRITICAL,
            "description": "Test PIN block format and retry counter handling",
            "apdu": [0x00, 0x20, 0x00, 0x80],  # VERIFY command
            "expected_sw": [0x63, 0xC0],  # Failed verification with retries
            "checks": [
                "PIN block format (ISO 9564)",
                "Retry counter decrement",
                "PIN length validation (4-12 digits)"
            ],
            "vulnerabilities": [
                "PIN bypass attacks",
                "Retry counter manipulation",
                "Offline PIN harvesting"
            ],
            "reference": "EMVCo Book 3 Section 6.5.10"
        }

        tests["T005_GENERATE_AC_CDOL"] = {
            "name": "GENERATE AC CDOL Validation",
            "category": TestCategory.PROTOCOL_COMPLIANCE,
            "severity": TestSeverity.CRITICAL,
            "description": "Test cryptogram request and CDOL handling",
            "apdu": [0x80, 0xAE, 0x80, 0x00],  # GENERATE AC (ARQC)
            "expected_sw": [0x90, 0x00],
            "checks": [
                "CDOL format compliance",
                "P1 byte interpretation (ARQC/TC/AAC)",
                "Cryptogram response format"
            ],
            "vulnerabilities": [
                "Cryptogram type downgrade",
                "TC instead of ARQC acceptance",
                "Missing CDOL data acceptance"
            ],
            "reference": "EMVCo Book 3 Section 6.5.5"
        }

        tests["T006_EXTERNAL_AUTHENTICATE"] = {
            "name": "External Authenticate Challenge",
            "category": TestCategory.PROTOCOL_COMPLIANCE,
            "severity": TestSeverity.HIGH,
            "description": "Validate terminal authentication process",
            "apdu": [0x00, 0x82, 0x00, 0x00],  # EXTERNAL AUTHENTICATE
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Challenge format validation",
                "Response cryptogram verification",
                "Key diversification"
            ],
            "vulnerabilities": [
                "Weak challenge generation",
                "Static response acceptance",
                "Authentication bypass"
            ],
            "reference": "ISO/IEC 7816-4 Section 7.5.8"
        }

        tests["T007_GET_DATA_TAGS"] = {
            "name": "GET DATA Tag Validation",
            "category": TestCategory.PROTOCOL_COMPLIANCE,
            "severity": TestSeverity.MEDIUM,
            "description": "Test access control for sensitive data tags",
            "apdu": [0x80, 0xCA, 0x9F, 0x36],  # GET DATA (ATC)
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Restricted tag access control",
                "Proper error codes (6A81, 6A88)",
                "Data format validation"
            ],
            "vulnerabilities": [
                "Unrestricted sensitive data access",
                "Key material exposure",
                "Transaction log extraction"
            ],
            "reference": "EMVCo Book 3 Section 6.5.7"
        }

        tests["T008_MULTI_AID_PRIORITY"] = {
            "name": "Multi-Application Selection Priority",
            "category": TestCategory.PROTOCOL_COMPLIANCE,
            "severity": TestSeverity.HIGH,
            "description": "Test application priority selection mechanism",
            "apdu": [0x00, 0xA4, 0x04, 0x00],  # SELECT (multiple AIDs)
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Priority indicator handling",
                "Mutual exclusivity enforcement",
                "Blocked application rejection"
            ],
            "vulnerabilities": [
                "Application selection override",
                "Priority bypass attack",
                "Debit-before-credit exploitation"
            ],
            "reference": "EMVCo Book 1 Section 12.3"
        }

        tests["T009_INTERNAL_AUTHENTICATE"] = {
            "name": "Internal Authenticate Validation",
            "category": TestCategory.PROTOCOL_COMPLIANCE,
            "severity": TestSeverity.HIGH,
            "description": "Test card authentication response",
            "apdu": [0x00, 0x88, 0x00, 0x00],  # INTERNAL AUTHENTICATE
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Challenge-response correctness",
                "Key selection validation",
                "Signature format"
            ],
            "vulnerabilities": [
                "Weak signature algorithm",
                "Static authentication data",
                "Key compromise indicators"
            ],
            "reference": "ISO/IEC 7816-8 Section 5.3"
        }

        tests["T010_PUT_DATA_SECURITY"] = {
            "name": "PUT DATA Security Validation",
            "category": TestCategory.PROTOCOL_COMPLIANCE,
            "severity": TestSeverity.CRITICAL,
            "description": "Test write protection and access control",
            "apdu": [0x04, 0xDA, 0x9F, 0x36],  # PUT DATA (should fail)
            "expected_sw": [0x6A, 0x82],  # File not found or not writable
            "checks": [
                "Write protection enforcement",
                "Unauthorized modification rejection",
                "Issuer script authentication"
            ],
            "vulnerabilities": [
                "Unauthorized data modification",
                "ATC manipulation",
                "Card personalization bypass"
            ],
            "reference": "ISO/IEC 7816-4 Section 7.4"
        }

        # ===================================================================
        # CATEGORY 2: CRYPTOGRAPHIC VALIDATION (10 tests)
        # ===================================================================

        tests["T011_DDA_VALIDATION"] = {
            "name": "Dynamic Data Authentication (DDA)",
            "category": TestCategory.CRYPTOGRAPHIC,
            "severity": TestSeverity.CRITICAL,
            "description": "Validate DDA cryptographic signature",
            "apdu": [0x00, 0x88, 0x00, 0x00],  # INTERNAL AUTHENTICATE for DDA
            "expected_sw": [0x90, 0x00],
            "checks": [
                "RSA signature verification",
                "Certificate chain validation",
                "Unpredictable number uniqueness"
            ],
            "vulnerabilities": [
                "Weak RSA key (< 1024 bits)",
                "Static DDA response (cloning)",
                "Certificate validation bypass"
            ],
            "reference": "EMVCo Book 2 Section 7.2"
        }

        tests["T012_CDA_COMBINED_AUTH"] = {
            "name": "Combined DDA/Application Cryptogram (CDA)",
            "category": TestCategory.CRYPTOGRAPHIC,
            "severity": TestSeverity.CRITICAL,
            "description": "Test combined cryptographic authentication",
            "apdu": [0x80, 0xAE, 0x90, 0x00],  # GENERATE AC with CDA
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Combined signature validation",
                "AC and DDA correlation",
                "Signed dynamic data integrity"
            ],
            "vulnerabilities": [
                "CDA fallback to DDA acceptance",
                "Signature replay attack",
                "AC/DDA mismatch acceptance"
            ],
            "reference": "EMVCo Book 2 Section 7.3"
        }

        tests["T013_ARQC_VALIDATION"] = {
            "name": "ARQC (Authorization Request Cryptogram) Validation",
            "category": TestCategory.CRYPTOGRAPHIC,
            "severity": TestSeverity.CRITICAL,
            "description": "Validate authorization cryptogram generation",
            "apdu": [0x80, 0xAE, 0x80, 0x00],  # GENERATE AC (ARQC)
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Cryptogram format (8 bytes)",
                "ATC (Application Transaction Counter) increment",
                "Unpredictable number inclusion"
            ],
            "vulnerabilities": [
                "ARQC prediction/replay",
                "ATC rollover exploitation",
                "Weak cryptographic algorithm"
            ],
            "reference": "EMVCo Book 2 Section 8.1"
        }

        tests["T014_TC_OFFLINE_AUTH"] = {
            "name": "TC (Transaction Certificate) Validation",
            "category": TestCategory.CRYPTOGRAPHIC,
            "severity": TestSeverity.HIGH,
            "description": "Test offline transaction approval",
            "apdu": [0x80, 0xAE, 0x40, 0x00],  # GENERATE AC (TC)
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Offline approval conditions",
                "TC vs ARQC decision logic",
                "Issuer authentication (ARPC) requirement"
            ],
            "vulnerabilities": [
                "Forced offline approval",
                "TC without proper risk checks",
                "Velocity limit bypass"
            ],
            "reference": "EMVCo Book 3 Section 10.6"
        }

        tests["T015_AAC_DECLINE"] = {
            "name": "AAC (Application Authentication Cryptogram) Decline",
            "category": TestCategory.CRYPTOGRAPHIC,
            "severity": TestSeverity.HIGH,
            "description": "Validate transaction decline cryptogram",
            "apdu": [0x80, 0xAE, 0x00, 0x00],  # GENERATE AC (AAC)
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Decline reason code",
                "AAC generation conditions",
                "Post-decline card state"
            ],
            "vulnerabilities": [
                "AAC to TC conversion",
                "Decline override",
                "Reason code manipulation"
            ],
            "reference": "EMVCo Book 3 Section 10.7"
        }

        tests["T016_PIN_ENCIPHERMENT"] = {
            "name": "PIN Block Encipherment Validation",
            "category": TestCategory.CRYPTOGRAPHIC,
            "severity": TestSeverity.CRITICAL,
            "description": "Test PIN encryption and transport",
            "apdu": [0x00, 0x20, 0x00, 0x80],  # VERIFY with encrypted PIN
            "expected_sw": [0x90, 0x00],
            "checks": [
                "PIN block format (ISO 9564)",
                "TDES/AES encryption validation",
                "Key management compliance"
            ],
            "vulnerabilities": [
                "Weak PIN encryption",
                "PIN block format oracle",
                "Plaintext PIN acceptance"
            ],
            "reference": "PCI PIN Security v3.0 Section 4.2"
        }

        tests["T017_CERTIFICATE_CHAIN"] = {
            "name": "Certificate Chain Validation",
            "category": TestCategory.CRYPTOGRAPHIC,
            "severity": TestSeverity.CRITICAL,
            "description": "Validate CA → Issuer → ICC certificate chain",
            "apdu": [0x00, 0xB2, 0x01, 0x0C],  # READ RECORD (certificates)
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Certificate hierarchy validation",
                "Expiration date checking",
                "Revocation status (if applicable)"
            ],
            "vulnerabilities": [
                "Expired certificate acceptance",
                "Missing certificate chain validation",
                "Self-signed certificate acceptance"
            ],
            "reference": "EMVCo Book 2 Section 6.3"
        }

        tests["T018_MAC_VALIDATION"] = {
            "name": "MAC (Message Authentication Code) Validation",
            "category": TestCategory.CRYPTOGRAPHIC,
            "severity": TestSeverity.HIGH,
            "description": "Test script MAC verification",
            "apdu": [0x04, 0x88, 0x00, 0x00],  # SCRIPT with MAC
            "expected_sw": [0x90, 0x00],
            "checks": [
                "MAC algorithm (CBC-MAC, CMAC)",
                "Key diversification",
                "MAC verification before execution"
            ],
            "vulnerabilities": [
                "Script execution without MAC",
                "MAC bypass attack",
                "Weak MAC algorithm"
            ],
            "reference": "EMVCo Book 3 Section 9.7"
        }

        tests["T019_CVV_CVV2_VALIDATION"] = {
            "name": "CVV/CVV2 Validation",
            "category": TestCategory.CRYPTOGRAPHIC,
            "severity": TestSeverity.HIGH,
            "description": "Test card verification value generation",
            "apdu": [0x80, 0xCA, 0x9F, 0x26],  # GET DATA (CVV)
            "expected_sw": [0x6A, 0x88],  # Referenced data not found (CVV should not be readable)
            "checks": [
                "CVV not exposed via APDUs",
                "CVV generation algorithm",
                "CVV2 for CNP transactions"
            ],
            "vulnerabilities": [
                "CVV exposure",
                "Weak CVV algorithm",
                "CVV predictability"
            ],
            "reference": "PCI DSS v4.0 Requirement 3.2"
        }

        tests["T020_SYMMETRIC_KEY_CRYPTO"] = {
            "name": "Symmetric Key Cryptography (TDES/AES)",
            "category": TestCategory.CRYPTOGRAPHIC,
            "severity": TestSeverity.CRITICAL,
            "description": "Validate symmetric encryption implementation",
            "apdu": [0x00, 0x20, 0x00, 0x80],  # Operation using symmetric crypto
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Algorithm selection (TDES deprecated, AES recommended)",
                "Key length validation (AES-128/256)",
                "Mode of operation (ECB forbidden, CBC/CTR allowed)"
            ],
            "vulnerabilities": [
                "Weak algorithm (DES, TDES)",
                "ECB mode usage",
                "Key length < 128 bits"
            ],
            "reference": "NIST SP 800-38A"
        }

        # ===================================================================
        # CATEGORY 3: TRANSACTION FLOW TESTING (10 tests)
        # ===================================================================

        tests["T021_ONLINE_FALLBACK"] = {
            "name": "Online Transaction Fallback",
            "category": TestCategory.TRANSACTION_FLOW,
            "severity": TestSeverity.HIGH,
            "description": "Test forced online transaction flow",
            "apdu": [0x80, 0xAE, 0x80, 0x00],  # GENERATE AC with online forced
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Online-only terminal capability respected",
                "ARQC generation forced",
                "TC rejection when online required"
            ],
            "vulnerabilities": [
                "Offline transaction force",
                "Online requirement bypass",
                "Network timeout exploitation"
            ],
            "reference": "EMVCo Book 3 Section 10.5"
        }

        tests["T022_OFFLINE_APPROVAL_LIMITS"] = {
            "name": "Offline Approval Amount Limits",
            "category": TestCategory.TRANSACTION_FLOW,
            "severity": TestSeverity.HIGH,
            "description": "Test offline transaction amount thresholds",
            "apdu": [0x80, 0xAE, 0x40, 0x00],  # GENERATE AC for large amount
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Transaction amount vs floor limit",
                "Cumulative offline amount tracking",
                "Consecutive offline transaction limit"
            ],
            "vulnerabilities": [
                "Floor limit bypass",
                "Velocity limit manipulation",
                "Amount splitting attack"
            ],
            "reference": "EMVCo Book 3 Section 10.6.1"
        }

        tests["T023_CURRENCY_CODE_VALIDATION"] = {
            "name": "Currency Code Validation",
            "category": TestCategory.TRANSACTION_FLOW,
            "severity": TestSeverity.MEDIUM,
            "description": "Test currency code handling (ISO 4217)",
            "apdu": [0x80, 0xA8, 0x00, 0x00],  # GPO with currency code
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Supported currency codes",
                "Currency mismatch handling",
                "Multi-currency card support"
            ],
            "vulnerabilities": [
                "Currency code substitution",
                "Exchange rate exploitation",
                "Unsupported currency acceptance"
            ],
            "reference": "ISO 4217, EMVCo Book 3 Tag 5F2A"
        }

        tests["T024_AMOUNT_AUTHORIZED_VALIDATION"] = {
            "name": "Amount Authorized vs Amount Other",
            "category": TestCategory.TRANSACTION_FLOW,
            "severity": TestSeverity.MEDIUM,
            "description": "Validate transaction amount fields",
            "apdu": [0x80, 0xAE, 0x80, 0x00],  # GENERATE AC with amounts
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Amount Authorized (9F02) validation",
                "Amount Other (9F03) for cashback",
                "Total amount calculation"
            ],
            "vulnerabilities": [
                "Amount field manipulation",
                "Cashback without authorization",
                "Negative amount acceptance"
            ],
            "reference": "EMVCo Book 3 Tags 9F02, 9F03"
        }

        tests["T025_TRANSACTION_TYPE_VALIDATION"] = {
            "name": "Transaction Type Code Validation",
            "category": TestCategory.TRANSACTION_FLOW,
            "severity": TestSeverity.HIGH,
            "description": "Test transaction type handling (purchase, cash, refund)",
            "apdu": [0x80, 0xA8, 0x00, 0x00],  # GPO with transaction type
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Transaction type code (9C): 00=purchase, 01=cash, 20=refund",
                "Type-specific authorization rules",
                "Refund without prior purchase rejection"
            ],
            "vulnerabilities": [
                "Transaction type downgrade (cash→purchase)",
                "Unauthorized refund",
                "Type code manipulation"
            ],
            "reference": "EMVCo Book 3 Tag 9C"
        }

        tests["T026_TERMINAL_COUNTRY_CODE"] = {
            "name": "Terminal Country Code Validation",
            "category": TestCategory.TRANSACTION_FLOW,
            "severity": TestSeverity.MEDIUM,
            "description": "Validate terminal country code handling",
            "apdu": [0x80, 0xA8, 0x00, 0x00],  # GPO with terminal country
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Country code format (ISO 3166-1)",
                "Domestic vs international transaction logic",
                "Country-specific velocity limits"
            ],
            "vulnerabilities": [
                "Country code substitution",
                "International fee bypass",
                "Geographic restriction circumvention"
            ],
            "reference": "EMVCo Book 3 Tag 9F1A"
        }

        tests["T027_TERMINAL_TYPE_VALIDATION"] = {
            "name": "Terminal Type Classification",
            "category": TestCategory.TRANSACTION_FLOW,
            "severity": TestSeverity.HIGH,
            "description": "Validate terminal type and capabilities",
            "apdu": [0x80, 0xA8, 0x00, 0x00],  # GPO with terminal type
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Terminal type (9F35): 11=Financial, 14=e-Commerce, 15=ATM, etc.",
                "Type-specific authorization logic",
                "ATM vs POS capability differences"
            ],
            "vulnerabilities": [
                "Terminal type spoofing",
                "ATM-only card on POS",
                "Capability downgrade"
            ],
            "reference": "EMVCo Book 3 Tag 9F35"
        }

        tests["T028_ISSUER_SCRIPT_PROCESSING"] = {
            "name": "Issuer Script Processing",
            "category": TestCategory.TRANSACTION_FLOW,
            "severity": TestSeverity.CRITICAL,
            "description": "Test issuer-to-card command processing",
            "apdu": [0x04, 0x88, 0x00, 0x00],  # SCRIPT command
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Script authentication (MAC)",
                "Script sequence control",
                "Before/after final GENERATE AC execution"
            ],
            "vulnerabilities": [
                "Unauthenticated script execution",
                "Script injection attack",
                "Card parameter manipulation"
            ],
            "reference": "EMVCo Book 3 Section 9.7"
        }

        tests["T029_TRANSACTION_SEQUENCE_COUNTER"] = {
            "name": "Transaction Sequence Counter (TSC)",
            "category": TestCategory.TRANSACTION_FLOW,
            "severity": TestSeverity.HIGH,
            "description": "Validate transaction counter increment",
            "apdu": [0x80, 0xCA, 0x9F, 0x36],  # GET DATA (ATC)
            "expected_sw": [0x90, 0x00],
            "checks": [
                "ATC (9F36) monotonic increment",
                "Counter overflow handling",
                "Transaction history consistency"
            ],
            "vulnerabilities": [
                "ATC rollback attack",
                "Transaction replay",
                "Counter manipulation"
            ],
            "reference": "EMVCo Book 3 Tag 9F36"
        }

        tests["T030_VELOCITY_CHECKING"] = {
            "name": "Transaction Velocity Checking",
            "category": TestCategory.TRANSACTION_FLOW,
            "severity": TestSeverity.HIGH,
            "description": "Test velocity limit enforcement",
            "apdu": [0x80, 0xAE, 0x40, 0x00],  # Multiple rapid transactions
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Consecutive offline transaction limit",
                "Time-based velocity (transactions/hour)",
                "Amount-based velocity (total amount/period)"
            ],
            "vulnerabilities": [
                "Velocity limit bypass",
                "Rapid transaction fraud",
                "Limit reset exploitation"
            ],
            "reference": "EMVCo Book 3 Section 10.6.2"
        }

        # ===================================================================
        # CATEGORY 4: SECURITY BOUNDARY TESTING (8 tests)
        # ===================================================================

        tests["T031_CVM_DOWNGRADE_ATTACK"] = {
            "name": "Cardholder Verification Method Downgrade",
            "category": TestCategory.SECURITY_BOUNDARY,
            "severity": TestSeverity.CRITICAL,
            "description": "Test CVM list manipulation resistance",
            "apdu": [0x80, 0xAE, 0x80, 0x00],  # GENERATE AC with CVM
            "expected_sw": [0x90, 0x00],
            "checks": [
                "CVM list integrity (not authenticated!)",
                "PIN-preferred to signature downgrade rejection",
                "No CVM acceptance threshold"
            ],
            "vulnerabilities": [
                "CVM list modification",
                "PIN bypass via signature",
                "No CVM forced acceptance"
            ],
            "reference": "Cambridge EMV Research (Murdoch 2010)"
        }

        tests["T032_PIN_RETRY_LIMITS"] = {
            "name": "PIN Retry Counter Enforcement",
            "category": TestCategory.SECURITY_BOUNDARY,
            "severity": TestSeverity.CRITICAL,
            "description": "Test PIN retry limit enforcement",
            "apdu": [0x00, 0x20, 0x00, 0x80],  # VERIFY (incorrect PIN)
            "expected_sw": [0x63, 0xC0],  # 0xC0 = remaining tries pattern (0 tries)
            "checks": [
                "Retry counter decrement",
                "Card block after 3 failures",
                "Counter reset conditions"
            ],
            "vulnerabilities": [
                "Infinite PIN tries",
                "Retry counter reset exploit",
                "Card unblock without issuer"
            ],
            "reference": "EMVCo Book 3 Section 10.5"
        }

        tests["T033_CONTACTLESS_LIMITS"] = {
            "name": "Contactless Transaction Limits",
            "category": TestCategory.SECURITY_BOUNDARY,
            "severity": TestSeverity.HIGH,
            "description": "Test contactless cumulative amount limits",
            "apdu": [0x80, 0xAE, 0x40, 0x00],  # Contactless GENERATE AC
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Contactless transaction limit (CTL)",
                "Cumulative total amount",
                "CVM required threshold"
            ],
            "vulnerabilities": [
                "Contactless limit bypass",
                "CVM skip exploitation",
                "Amount accumulation reset"
            ],
            "reference": "EMVCo Contactless v2.10 Book C-2"
        }

        tests["T034_MAGNETIC_STRIPE_FALLBACK"] = {
            "name": "Magstripe Fallback Security",
            "category": TestCategory.SECURITY_BOUNDARY,
            "severity": TestSeverity.CRITICAL,
            "description": "Test chip-to-magstripe fallback restrictions",
            "apdu": [0x80, 0xCA, 0x9F, 0x6B],  # GET DATA (Track 2 Equivalent)
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Fallback attempt tracking",
                "Consecutive fallback limits",
                "Service code restrictions"
            ],
            "vulnerabilities": [
                "Forced magstripe mode",
                "EMV downgrade attack",
                "Track data harvesting"
            ],
            "reference": "EMVCo Book 3 Annex B"
        }

        tests["T035_TERMINAL_RISK_MANAGEMENT"] = {
            "name": "Terminal Risk Management (TVR/TSI)",
            "category": TestCategory.SECURITY_BOUNDARY,
            "severity": TestSeverity.HIGH,
            "description": "Test Terminal Verification Results handling",
            "apdu": [0x80, 0xAE, 0x80, 0x00],  # GENERATE AC with TVR
            "expected_sw": [0x90, 0x00],
            "checks": [
                "TVR bit interpretation",
                "Terminal action codes (denial, online)",
                "TSI (Transaction Status Information)"
            ],
            "vulnerabilities": [
                "TVR bit manipulation",
                "Risk management bypass",
                "Action code override"
            ],
            "reference": "EMVCo Book 3 Tag 95, 9B"
        }

        tests["T036_APPLICATION_BLOCK"] = {
            "name": "Application Block Status",
            "category": TestCategory.SECURITY_BOUNDARY,
            "severity": TestSeverity.HIGH,
            "description": "Test blocked application rejection",
            "apdu": [0x00, 0xA4, 0x04, 0x00],  # SELECT blocked AID
            "expected_sw": [0x6A, 0x81],  # Function not supported
            "checks": [
                "Application block flag (AFL)",
                "Blocked app selection rejection",
                "Unblock authentication"
            ],
            "vulnerabilities": [
                "Blocked application use",
                "Block status bypass",
                "Unauthorized unblock"
            ],
            "reference": "EMVCo Book 1 Section 11.3.4"
        }

        tests["T037_CARD_BLOCK_STATUS"] = {
            "name": "Card-Level Block Status",
            "category": TestCategory.SECURITY_BOUNDARY,
            "severity": TestSeverity.CRITICAL,
            "description": "Test globally blocked card rejection",
            "apdu": [0x00, 0xA4, 0x04, 0x00],  # Any command to blocked card
            "expected_sw": [0x6A, 0x81],  # Function not supported
            "checks": [
                "Card permanent block",
                "Temporary block (wrong PIN)",
                "Issuer-initiated block"
            ],
            "vulnerabilities": [
                "Blocked card transactions",
                "Block status spoofing",
                "Unblock without issuer"
            ],
            "reference": "EMVCo Book 1 Section 5.5"
        }

        tests["T038_FLOOR_LIMIT_ENFORCEMENT"] = {
            "name": "Terminal Floor Limit Enforcement",
            "category": TestCategory.SECURITY_BOUNDARY,
            "severity": TestSeverity.HIGH,
            "description": "Test floor limit vs transaction amount",
            "apdu": [0x80, 0xAE, 0x40, 0x00],  # GENERATE AC above floor limit
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Floor limit comparison",
                "Online required for amounts above floor",
                "Zero floor limit handling"
            ],
            "vulnerabilities": [
                "Floor limit bypass",
                "Offline approval above limit",
                "Split transaction fraud"
            ],
            "reference": "EMVCo Book 3 Section 10.6.1"
        }

        # ===================================================================
        # CATEGORY 5: FAULT INJECTION & ERROR HANDLING (6 tests)
        # ===================================================================

        tests["T039_MALFORMED_APDU"] = {
            "name": "Malformed APDU Handling",
            "category": TestCategory.FAULT_INJECTION,
            "severity": TestSeverity.HIGH,
            "description": "Test response to malformed commands",
            "apdu": [0x00, 0xA4, 0x00, 0x00, 0x08, 0x00],  # Lc mismatch
            "expected_sw": [0x67, 0x00],  # Wrong length
            "checks": [
                "Length field validation",
                "Proper error codes (6700, 6A86)",
                "No partial execution"
            ],
            "vulnerabilities": [
                "Buffer overflow via malformed APDU",
                "Partial command execution",
                "Memory corruption"
            ],
            "reference": "ISO/IEC 7816-4 Section 5.1"
        }

        tests["T040_UNSUPPORTED_COMMAND"] = {
            "name": "Unsupported Command Rejection",
            "category": TestCategory.FAULT_INJECTION,
            "severity": TestSeverity.MEDIUM,
            "description": "Test unsupported INS byte handling",
            "apdu": [0x00, 0xFF, 0x00, 0x00],  # Invalid INS
            "expected_sw": [0x6D, 0x00],  # Instruction not supported
            "checks": [
                "Proper 6D00 response",
                "No command execution",
                "State preservation"
            ],
            "vulnerabilities": [
                "Vendor-specific command exposure",
                "Debug command leakage",
                "Backdoor access"
            ],
            "reference": "ISO/IEC 7816-4 Table 6"
        }

        tests["T041_INCORRECT_P1_P2"] = {
            "name": "Incorrect Parameter P1/P2 Handling",
            "category": TestCategory.FAULT_INJECTION,
            "severity": TestSeverity.MEDIUM,
            "description": "Test invalid parameter byte handling",
            "apdu": [0x00, 0xA4, 0xFF, 0xFF],  # Invalid P1/P2
            "expected_sw": [0x6A, 0x86],  # Incorrect P1/P2
            "checks": [
                "P1/P2 validation",
                "Proper error code 6A86",
                "No side effects"
            ],
            "vulnerabilities": [
                "Parameter bypass",
                "Undocumented parameter values",
                "Test mode activation"
            ],
            "reference": "ISO/IEC 7816-4 Table 6"
        }

        tests["T042_FILE_NOT_FOUND"] = {
            "name": "Non-existent File Access",
            "category": TestCategory.FAULT_INJECTION,
            "severity": TestSeverity.MEDIUM,
            "description": "Test access to non-existent files",
            "apdu": [0x00, 0xA4, 0x00, 0x00, 0x02, 0xFF, 0xFF],  # Non-existent FID
            "expected_sw": [0x6A, 0x82],  # File not found
            "checks": [
                "File existence validation",
                "Error code 6A82",
                "No information leakage"
            ],
            "vulnerabilities": [
                "File enumeration via error codes",
                "Hidden file exposure",
                "Directory traversal"
            ],
            "reference": "ISO/IEC 7816-4 Section 7.1"
        }

        tests["T043_SECURITY_STATUS_ERROR"] = {
            "name": "Security Status Not Satisfied",
            "category": TestCategory.FAULT_INJECTION,
            "severity": TestSeverity.HIGH,
            "description": "Test authentication requirement enforcement",
            "apdu": [0x00, 0x20, 0x00, 0x80],  # Protected operation without auth
            "expected_sw": [0x69, 0x82],  # Security status not satisfied
            "checks": [
                "Authentication enforcement",
                "Error code 6982",
                "Session state preservation"
            ],
            "vulnerabilities": [
                "Authentication bypass",
                "State confusion attack",
                "Protected operation exposure"
            ],
            "reference": "ISO/IEC 7816-4 Table 6"
        }

        tests["T044_COMMAND_NOT_ALLOWED"] = {
            "name": "Command Not Allowed in Current State",
            "category": TestCategory.FAULT_INJECTION,
            "severity": TestSeverity.HIGH,
            "description": "Test state machine enforcement",
            "apdu": [0x80, 0xAE, 0x80, 0x00],  # GENERATE AC without GPO
            "expected_sw": [0x69, 0x85],  # Conditions not satisfied
            "checks": [
                "State machine validation",
                "Command sequence enforcement",
                "Error code 6985"
            ],
            "vulnerabilities": [
                "State machine bypass",
                "Out-of-sequence command execution",
                "Transaction flow manipulation"
            ],
            "reference": "ISO/IEC 7816-4 Section 5.1"
        }

        # ===================================================================
        # CATEGORY 6: TIMING & SIDE-CHANNEL ANALYSIS (4 tests)
        # ===================================================================

        tests["T045_TIMING_ATTACK_RESISTANCE"] = {
            "name": "Timing Attack Resistance",
            "category": TestCategory.TIMING_ANALYSIS,
            "severity": TestSeverity.CRITICAL,
            "description": "Test constant-time cryptographic operations",
            "apdu": [0x00, 0x20, 0x00, 0x80],  # VERIFY with timing measurement
            "expected_sw": [0x63, 0xC0],
            "checks": [
                "Constant-time PIN verification",
                "No timing correlation with correctness",
                "Response time variation < 1ms"
            ],
            "vulnerabilities": [
                "Timing side-channel attack",
                "PIN digit-by-digit recovery",
                "Early rejection timing leak"
            ],
            "reference": "Cambridge Side-Channel Research"
        }

        tests["T046_POWER_ANALYSIS_INDICATORS"] = {
            "name": "Power Analysis Vulnerability Indicators",
            "category": TestCategory.TIMING_ANALYSIS,
            "severity": TestSeverity.CRITICAL,
            "description": "Detect power analysis susceptibility",
            "apdu": [0x80, 0xAE, 0x80, 0x00],  # Cryptographic operation
            "expected_sw": [0x90, 0x00],
            "checks": [
                "DPA countermeasures presence",
                "Random delay insertion",
                "Dummy operation execution"
            ],
            "vulnerabilities": [
                "Differential Power Analysis (DPA)",
                "Simple Power Analysis (SPA)",
                "Key extraction via power traces"
            ],
            "reference": "Kocher DPA Research"
        }

        tests["T047_TEMPLATE_ATTACK_RESISTANCE"] = {
            "name": "Template Attack Resistance",
            "category": TestCategory.TIMING_ANALYSIS,
            "severity": TestSeverity.HIGH,
            "description": "Test resistance to profiled side-channel attacks",
            "apdu": [0x00, 0x88, 0x00, 0x00],  # Repeated cryptographic op
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Response variation per invocation",
                "No deterministic power patterns",
                "Masking/hiding countermeasures"
            ],
            "vulnerabilities": [
                "Template attack profiling",
                "Deterministic power consumption",
                "Key bit leakage"
            ],
            "reference": "Template Attack Research (Chari 2002)"
        }

        tests["T048_CACHE_TIMING_LEAK"] = {
            "name": "Cache Timing Leak Detection",
            "category": TestCategory.TIMING_ANALYSIS,
            "severity": TestSeverity.MEDIUM,
            "description": "Test for cache-based timing side channels",
            "apdu": [0x00, 0xA4, 0x04, 0x00],  # File system cache timing
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Consistent SELECT timing",
                "No cache hit/miss timing difference",
                "Memory access obfuscation"
            ],
            "vulnerabilities": [
                "File existence via cache timing",
                "Key lookup timing leak",
                "Data structure probing"
            ],
            "reference": "Cache-Timing Attacks (Osvik 2006)"
        }

        # ===================================================================
        # CATEGORY 7: INTERFACE SECURITY (4 tests)
        # ===================================================================

        tests["T049_NFC_RELAY_ATTACK"] = {
            "name": "NFC Relay Attack Detection",
            "category": TestCategory.INTERFACE_SECURITY,
            "severity": TestSeverity.CRITICAL,
            "description": "Test relay attack countermeasures",
            "apdu": [0x80, 0xAE, 0x40, 0x00],  # Contactless transaction
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Time difference checking",
                "Relay attack prevention (RAP)",
                "Challenge-response timing"
            ],
            "vulnerabilities": [
                "Man-in-the-middle relay",
                "Distance bounding bypass",
                "Ghost transaction"
            ],
            "reference": "EMVCo Contactless Relay Resistance"
        }

        tests["T050_CONTACTLESS_COLLISION"] = {
            "name": "Contactless Collision Handling",
            "category": TestCategory.INTERFACE_SECURITY,
            "severity": TestSeverity.HIGH,
            "description": "Test multi-card collision resistance",
            "apdu": [0x00, 0xA4, 0x04, 0x00],  # SELECT with collision
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Anti-collision protocol",
                "UID uniqueness",
                "Single card selection"
            ],
            "vulnerabilities": [
                "Collision-based card substitution",
                "Transaction routing to wrong card",
                "Multi-card transaction"
            ],
            "reference": "ISO/IEC 14443-3 Anti-collision"
        }

        tests["T051_EAVESDROPPING_RESISTANCE"] = {
            "name": "Wireless Eavesdropping Resistance",
            "category": TestCategory.INTERFACE_SECURITY,
            "severity": TestSeverity.HIGH,
            "description": "Test data confidentiality over NFC",
            "apdu": [0x00, 0x20, 0x00, 0x80],  # Sensitive data over NFC
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Sensitive data encryption",
                "Secure messaging protocol",
                "RF shielding effectiveness"
            ],
            "vulnerabilities": [
                "Plaintext PIN over NFC",
                "Unencrypted sensitive data",
                "Extended read range exploitation"
            ],
            "reference": "ISO/IEC 14443-4 Security"
        }

        tests["T052_SKIMMING_DETECTION"] = {
            "name": "Card Skimming Detection",
            "category": TestCategory.INTERFACE_SECURITY,
            "severity": TestSeverity.CRITICAL,
            "description": "Test skimming device detection mechanisms",
            "apdu": [0x80, 0xCA, 0x9F, 0x6B],  # Track data request
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Track data access restrictions",
                "Service code validation",
                "Suspicious read pattern detection"
            ],
            "vulnerabilities": [
                "Track data harvesting",
                "Magnetic stripe data exposure",
                "Skimmer device undetected"
            ],
            "reference": "PCI PTS POI Skimming Protection"
        }

        # ===================================================================
        # CATEGORY 8: RISK MANAGEMENT & AUTHENTICATION (4 tests)
        # ===================================================================

        tests["T053_ISSUER_AUTHENTICATION"] = {
            "name": "Issuer Authentication (ARPC Validation)",
            "category": TestCategory.RISK_MANAGEMENT,
            "severity": TestSeverity.CRITICAL,
            "description": "Test issuer response validation",
            "apdu": [0x00, 0x88, 0x00, 0x00],  # Process ARPC
            "expected_sw": [0x90, 0x00],
            "checks": [
                "ARPC cryptogram validation",
                "Issuer script authentication",
                "Authorization response code"
            ],
            "vulnerabilities": [
                "ARPC bypass",
                "Fake authorization response",
                "Issuer authentication skip"
            ],
            "reference": "EMVCo Book 2 Section 8.2"
        }

        tests["T054_RISK_PARAMETERS"] = {
            "name": "Card Risk Management Parameters",
            "category": TestCategory.RISK_MANAGEMENT,
            "severity": TestSeverity.HIGH,
            "description": "Test card risk management data",
            "apdu": [0x80, 0xCA, 0xDF, 0x60],  # GET DATA (risk params)
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Lower/upper offline limits",
                "Random transaction selection",
                "Consecutive offline transaction limit"
            ],
            "vulnerabilities": [
                "Risk parameter manipulation",
                "Random selection bypass",
                "Limit enforcement evasion"
            ],
            "reference": "EMVCo Book 3 Section 10.6"
        }

        tests["T055_EXCEPTION_FILE_CHECK"] = {
            "name": "Exception File Checking",
            "category": TestCategory.RISK_MANAGEMENT,
            "severity": TestSeverity.HIGH,
            "description": "Test hotlist/exception file validation",
            "apdu": [0x00, 0xA4, 0x04, 0x00],  # Transaction with PAN check
            "expected_sw": [0x90, 0x00],
            "checks": [
                "PAN against exception file",
                "Card block list check",
                "Real-time hotlist query"
            ],
            "vulnerabilities": [
                "Exception file bypass",
                "Stolen card acceptance",
                "Hotlist outdated"
            ],
            "reference": "PCI DSS Exception File Requirements"
        }

        tests["T056_BIOMETRIC_AUTHENTICATION"] = {
            "name": "Biometric Authentication (if supported)",
            "category": TestCategory.RISK_MANAGEMENT,
            "severity": TestSeverity.HIGH,
            "description": "Test biometric CVM implementation",
            "apdu": [0x00, 0x21, 0x00, 0x00],  # Biometric VERIFY
            "expected_sw": [0x90, 0x00],
            "checks": [
                "Biometric template matching",
                "Liveness detection",
                "False acceptance rate (FAR) < 1:50,000"
            ],
            "vulnerabilities": [
                "Biometric spoof acceptance",
                "No liveness detection",
                "High false acceptance rate"
            ],
            "reference": "EMVCo Biometric Specification"
        }

        return tests

    def get_test(self, test_id: str) -> Optional[Dict]:
        """Get a specific test by ID."""
        return self.tests.get(test_id)

    def get_tests_by_category(self, category: TestCategory) -> List[Dict]:
        """Get all tests in a category."""
        return [
            {**test, "test_id": tid}
            for tid, test in self.tests.items()
            if test["category"] == category
        ]

    def get_tests_by_severity(self, min_severity: TestSeverity) -> List[Dict]:
        """Get tests above a severity threshold."""
        return [
            {**test, "test_id": tid}
            for tid, test in self.tests.items()
            if test["severity"].value >= min_severity.value
        ]

    def get_all_test_ids(self) -> List[str]:
        """Get list of all test IDs."""
        return list(self.tests.keys())

    def get_test_count(self) -> int:
        """Get total number of tests."""
        return len(self.tests)

    def get_category_distribution(self) -> Dict[str, int]:
        """Get number of tests per category."""
        distribution = {}
        for test in self.tests.values():
            cat = test["category"].value
            distribution[cat] = distribution.get(cat, 0) + 1
        return distribution


# Singleton instance
_test_library = None

def get_test_library() -> MerchantTestLibrary:
    """Get singleton instance of test library."""
    global _test_library
    if _test_library is None:
        _test_library = MerchantTestLibrary()
    return _test_library


if __name__ == "__main__":
    # Demo usage
    library = get_test_library()

    print("=" * 70)
    print("MERCHANT/TERMINAL/ATM/HSM TEST LIBRARY")
    print("=" * 70)

    print(f"\nTotal Tests: {library.get_test_count()}")
    print("\nTests by Category:")
    for cat, count in library.get_category_distribution().items():
        print(f"  {cat}: {count} tests")

    print("\n" + "=" * 70)
    print("CRITICAL SEVERITY TESTS")
    print("=" * 70)

    critical_tests = library.get_tests_by_severity(TestSeverity.CRITICAL)
    for test in critical_tests[:5]:
        print(f"\n[{test['test_id']}] {test['name']}")
        print(f"  Category: {test['category'].value}")
        print(f"  Description: {test['description']}")
        print(f"  Vulnerabilities: {', '.join(test['vulnerabilities'][:2])}")
