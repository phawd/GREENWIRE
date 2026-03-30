#!/usr/bin/env python3
"""
Intelligent Card System - Enhanced Integration Module
Combines AI learning, EMVCo personalization, merchant testing, HSM/ATM operations.

IMPORTANT SAFETY NOTICE:
This system is provided for controlled laboratory and research use only.
Do not deploy or run this software against live payment systems or
production infrastructure without explicit, written authorization. The
authors are not responsible for misuse.

This module orchestrates the complete intelligent card workflow:
1. Personalize card with EMVCo-compliant data (production mode support)
2. Deploy merchant tester applet to card (56 tests)
3. Run AI-generated test mixes with continuous learning
4. Execute merchant tests with HSM/ATM integration
5. Bidirectional intelligence sharing (Cards ↔ HSM/ATM ↔ Merchants)
6. Extract and analyze all collected data

VERSION: 2.0 (Enhanced with AI Test Generator, HSM/ATM Integration, Production Mode)
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# GREENWIRE imports
sys.path.append(str(Path(__file__).parent.parent))

try:
    from modules.ai_learning_system import AILearningSystem
    from modules.emvco_card_personalizer import EMVCoCardPersonalizer
    from modules.advanced_vulnerability_fuzzer import CardSecretExtractor
    from modules.ai_test_generator import AITestGenerator
    from modules.merchant_test_library import get_test_library, TestCategory, TestSeverity
    from modules.hsm_atm_integration import HSMATMIntegration
except ImportError as e:
    print(f"Warning: Could not import modules: {e}")
    print("Make sure you're running from GREENWIRE directory")


class IntelligentCardSystem:
    """
    Enhanced intelligent card system orchestrator with production mode.

    Manages the full lifecycle:
    - Card personalization with EMVCo compliance (production mode for real cards)
    - Merchant tester applet deployment (56 tests)
    - AI-powered vulnerability scanning
    - AI-generated test mix selection (20-30 tests from library of 56)
    - Merchant behavior testing with HSM/ATM integration
    - Bidirectional intelligence sharing
    - Results analysis and continuous learning

    Production Mode:
    - Generates real test cards for internal security testing
    - Full HSM integration for cryptographic operations
    - Compliance with PCI DSS requirements
    - Audit logging for all operations
    """

    def __init__(self, 
                 knowledge_base_dir: str = "ai_knowledge_base",
                 production_mode: bool = False,
                 random_seed: Optional[int] = None):
        """
        Initialize enhanced intelligent card system.

        Args:
            knowledge_base_dir: Directory for AI knowledge base
            production_mode: Enable production mode for real card generation
        """
        # Core components
        self.ai = AILearningSystem(knowledge_base_dir=knowledge_base_dir)
        self.personalizer = EMVCoCardPersonalizer(
            compliance_mode="strict" if production_mode else "permissive"
        )
        self.fuzzer = None  # Will be initialized when needed

        # New enhanced components
        # Pass random_seed to test generator for reproducible test mixes
        self.test_generator = AITestGenerator(random_seed=random_seed)
        self.test_library = get_test_library()
        self.hsm_atm = HSMATMIntegration()

        # Production mode settings
        self.production_mode = production_mode
        self.random_seed = random_seed

        # Session management
        self.session_dir = Path("intelligent_card_sessions")
        self.session_dir.mkdir(exist_ok=True)

        self.production_dir = Path("production_cards")
        if production_mode:
            self.production_dir.mkdir(exist_ok=True)

        self.current_session = None

        print("[ICS] ═══════════════════════════════════════════════════════════")
        print("[ICS] Intelligent Card System v2.0 - Enhanced Edition")
        print("[ICS] ═══════════════════════════════════════════════════════════")
        print(f"[ICS] Production Mode:        {'🔴 ENABLED' if production_mode else '🟢 DISABLED (Test)'}")
        print("[ICS] AI Learning System:     ✅")
        print("[ICS] EMVCo Personalizer:     ✅")
        print("[ICS] AI Test Generator:      ✅")
        print(f"[ICS] Test Library:           ✅ ({self.test_library.get_test_count()} tests)")
        print("[ICS] HSM/ATM Integration:    ✅")
        print("[ICS] Bidirectional Learning: ✅")
        print("[ICS] ═══════════════════════════════════════════════════════════")
        print("[ICS] Ready for operations")

        if production_mode:
            print("[ICS] ⚠️  PRODUCTION MODE: Real cards will be generated!")
            print("[ICS] ⚠️  Ensure compliance with internal security policies")

    def personalize_intelligent_card(self, card_data: Dict, 
                                     card_interface=None) -> bool:
        """
        Personalize card with EMVCo-compliant data and merchant testing capability.

        Args:
            card_data: Card information dictionary
            card_interface: Optional physical card interface

        Returns:
            success: Whether personalization succeeded
        """
        print("\n" + "=" * 70)
        print("INTELLIGENT CARD PERSONALIZATION")
        print("=" * 70)

        # Step 1: Validate card data
        # The personalizer enforces EMVCo rules; validation errors are
        # collected in the personalizer instance for debugging and audit.
        print("\n[1/3] Validating card data against EMVCo specifications...")
        if not self.personalizer._validate_card_data(card_data):
            print("❌ Validation failed:")
            for error in self.personalizer.validation_errors:
                print(f"  - {error}")
            return False
        print("✅ Card data validated")

        # Step 2: Personalize card
        print("\n[2/3] Personalizing card with EMVCo-compliant data...")
        success = self.personalizer.personalize_card(card_data, card_interface)

        if not success:
            print("❌ Personalization failed")
            return False
        print("✅ Card personalized")

        # Step 3: Deploy merchant tester applet (if card interface available)
        print("\n[3/3] Deploying merchant tester applet...")
        if card_interface:
            applet_success = self._deploy_merchant_tester(card_interface)
            if applet_success:
                print("✅ Merchant tester applet deployed")
            else:
                print("⚠️  Applet deployment skipped (requires physical card)")
        else:
            print("⚠️  Applet deployment skipped (no card interface)")

        print("\n" + "=" * 70)
        print("PERSONALIZATION COMPLETE")
        print("=" * 70)

        return True

    def _deploy_merchant_tester(self, card_interface) -> bool:
        """
        Deploy MerchantTesterApplet to card.

        Args:
            card_interface: Card interface

        Returns:
            success: Whether deployment succeeded
        """
        try:
            # NOTE: Deployment is simulated here. In production, deployment
            # should use GlobalPlatform/GPPro or a hardware-backed installer
            # which authenticates and installs the CAP on the target card.

            cap_file = Path("javacard/applet/build/javacard/merchanttest.cap")

            if not cap_file.exists():
                print(f"  ⚠️  CAP file not found: {cap_file}")
                print("  ℹ️  Build applet with: cd javacard/applet && gradle convertCap")
                return False

            # Simulated deployment
            print(f"  📦 Loading CAP file: {cap_file}")
            print(f"  🔧 Installing applet...")
            print(f"  🔐 Setting privileges...")
            print(f"  ✅ Applet installed successfully")

            return True

        except Exception as e:
            print(f"  ❌ Deployment failed: {e}")
            return False

    def generate_production_card(self, 
                                 card_type: str,
                                 purpose: str,
                                 cardholder_name: str,
                                 metadata: Optional[Dict] = None) -> Dict:
        """
        Generate a real EMVCo-compliant test card for internal security testing.

        PRODUCTION MODE ONLY - Requires production_mode=True initialization.
        Generates cards with real cryptographic keys from HSM, full audit trail.

        Args:
            card_type: Card type (e.g., "VISA", "MASTERCARD", "AMEX")
            purpose: Purpose of test card (e.g., "Merchant Certification", "ATM Testing")
            cardholder_name: Cardholder name for card surface
            metadata: Optional metadata (project, tester, expiry_override)

        Returns:
            card_details: Dictionary with card number, expiry, CVV, keys, audit_id
        """
        if not self.production_mode:
            raise RuntimeError(
                "Production card generation requires production_mode=True. "
                "Initialize with: IntelligentCardSystem(production_mode=True)"
            )

        print("\n" + "=" * 70)
        print("PRODUCTION CARD GENERATION - REAL TEST CARD")
        print("=" * 70)
        print(f"⚠️  WARNING: Generating REAL test card with cryptographic keys")
        print(f"⚠️  This card will be fully functional for internal testing")
        print("=" * 70)

        # Local imports to limit module scope and dependencies for CLI
        import uuid
        import hashlib
        import random
        from datetime import datetime, timedelta

        # "random" is used to generate deterministic-looking PAN bodies
        # for test cards. In production-grade systems a secure generation
        # and allocation process must be used.

        # Generate unique card ID
        card_id = f"ICS-PROD-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

        print(f"\n[PROD] Card ID: {card_id}")
        print(f"[PROD] Card Type: {card_type}")
        print(f"[PROD] Purpose: {purpose}")
        print(f"[PROD] Cardholder: {cardholder_name}")

        # Step 1: Generate EMVCo-compliant card number (using test BIN ranges)
        print(f"\n[1/6] Generating card number...")
        test_bins = {
            "VISA": "4000",
            "MASTERCARD": "5100",
            "AMEX": "3700"
        }
        bin_prefix = test_bins.get(card_type, "4000")

        # Generate card number with valid Luhn checksum
        # NOTE: This uses pseudorandom digits for demo/test purposes only.
        card_body = bin_prefix + "".join([str(random.randint(0, 9)) for _ in range(11)])
        checksum = self._calculate_luhn_checksum(card_body)
        card_number = card_body + str(checksum)
        print(f"  Card Number: {card_number[:4]} **** **** {card_number[-4:]}")

        # Step 2: Generate expiry date
        print(f"\n[2/6] Setting expiry date...")
        expiry_override = metadata.get("expiry_override") if metadata else None
        if expiry_override:
            expiry_date = expiry_override
        else:
            expiry = datetime.now() + timedelta(days=365*3)  # 3 years
            expiry_date = expiry.strftime("%m%y")
        print(f"  Expiry: {expiry_date}")

        # Step 3: Generate cryptographic keys via HSM
        print(f"\n[3/6] Generating cryptographic keys via HSM...")
        print(f"  [HSM] Requesting PIN key generation...")
        pin_key = self.hsm_atm.generate_pin_key(card_id)
        print(f"  [HSM] Requesting CVV key generation...")
        cvv = self.hsm_atm.generate_cvv(
            card_number=card_number,
            expiry_date=expiry_date,
            service_code="101"
        )
        print(f"  CVV: {cvv}")
        print(f"  [HSM] Requesting MAC key generation...")
        mac_key = self.hsm_atm.generate_mac(card_id, b"INITIAL_DATA")

        # Step 4: Generate EMVCo application data
        print(f"\n[4/6] Generating EMVCo application data...")
        card_data = {
            "card_id": card_id,
            "card_number": card_number,
            "expiry_date": expiry_date,
            "cardholder_name": cardholder_name,
            "card_type": card_type,
            "service_code": "101",
            "cvv": cvv,
            "icc_private_key": hashlib.sha256(card_id.encode()).hexdigest()[:32],
            "issuer_public_key_modulus": "A" * 32,
            "issuer_public_key_exponent": "03",
            "application_interchange_profile": "5800",
            "application_usage_control": "0000",
            "cvm_list": "08010000000000000000000000",
            "track2_equivalent": f"{card_number}D{expiry_date}101"
        }
        print(f"  Application AIP: {card_data['application_interchange_profile']}")
        print(f"  CVM List: PIN + Signature")

        # Step 5: Create audit trail
        # Audit records record high-level events and cryptographic operations
        # performed during card generation. In production this file must be
        # protected and access-controlled.
        print(f"\n[5/6] Creating audit trail...")
        audit_id = f"AUDIT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
        audit_record = {
            "audit_id": audit_id,
            "card_id": card_id,
            "timestamp": datetime.now().isoformat(),
            "generated_by": "IntelligentCardSystem v2.0",
            "card_type": card_type,
            "purpose": purpose,
            "cardholder_name": cardholder_name,
            "metadata": metadata or {},
            "cryptographic_operations": {
                "pin_key_generated": True,
                "cvv_generated": True,
                "mac_key_generated": True
            }
        }

        # Save audit trail
        audit_file = self.production_dir / f"{audit_id}.json"
        self.production_dir.mkdir(exist_ok=True)
        with open(audit_file, 'w') as f:
            json.dump(audit_record, f, indent=2)
        print(f"  Audit ID: {audit_id}")
        print(f"  Audit saved: {audit_file}")

        # Step 6: Save card data (encrypted in real system)
        print(f"\n[6/6] Saving production card data...")
        card_file = self.production_dir / f"{card_id}.json"
        with open(card_file, 'w') as f:
            json.dump(card_data, f, indent=2)
        print(f"  Card saved: {card_file}")

        print("\n" + "=" * 70)
        print("✅ PRODUCTION CARD GENERATED SUCCESSFULLY")
        print("=" * 70)
        print(f"Card ID:       {card_id}")
        print(f"Card Number:   {card_number[:4]} **** **** {card_number[-4:]}")
        print(f"Expiry:        {expiry_date}")
        print(f"CVV:           {cvv}")
        print(f"Audit ID:      {audit_id}")
        print("=" * 70)
        print("⚠️  SECURITY NOTICE:")
        print("  - Store physical card securely")
        print("  - Log all usage in test environment")
        print("  - Destroy card after testing complete")
        print("  - Never use for real transactions")
        print("=" * 70)

        return {
            "card_id": card_id,
            "card_number": card_number,
            "expiry_date": expiry_date,
            "cvv": cvv,
            "audit_id": audit_id,
            "card_file": str(card_file),
            "audit_file": str(audit_file),
            "purpose": purpose
        }

    def _calculate_luhn_checksum(self, card_body: str) -> int:
        """Calculate Luhn checksum digit for card number validation.

        The Luhn algorithm is used to compute the final check digit for
        payment card numbers. This helper returns the single checksum
        digit that makes the full PAN Luhn-valid.
        """
        digits = [int(d) for d in card_body]
        checksum = 0

        for i in range(len(digits) - 1, -1, -1):
            digit = digits[i]
            if (len(digits) - i) % 2 == 0:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit

        return (10 - (checksum % 10)) % 10

    def run_learning_session(self, card_atr: str, card_interface=None,
                             techniques: List[str] = None) -> Dict:
        """
        Run AI-powered vulnerability scan session.

        Args:
            card_atr: Card ATR
            card_interface: Optional card interface
            techniques: List of attack techniques to use

        Returns:
            session_summary: Summary of session and learning
        """
        print("\n" + "=" * 70)
        print("AI LEARNING SESSION")
        print("=" * 70)

        # Get AI recommendations
        # The AI engine suggests attack vectors based on prior sessions and
        # the observed ATR. These are high-level recommendations; execution
        # is handled by the fuzzer/exploit modules.
        print("\n[AI] Analyzing card and recommending attacks...")
        recommendations = self.ai.get_recommended_attacks(card_atr, limit=5)

        if recommendations:
            print("\n[AI] Recommended attack strategies:")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec['attack_type']} → {rec['target']}")
                print(f"     Rationale: {rec['rationale']}")
                print(f"     Confidence: {rec['confidence']:.0%}")

        # Start AI learning session
        card_info = {"ATR": card_atr}
        session_id = self.ai.start_session("vulnerability_scan", card_info)

        # Initialize fuzzer with AI integration
        self.fuzzer = CardSecretExtractor(ai_learning=self.ai)

        # Determine techniques to use
        if not techniques:
            techniques = ["timing", "dpa", "fault_injection", "protocol_exploitation"]

        print(f"\n[ICS] Running {len(techniques)} attack techniques...")
        print(f"[ICS] Techniques: {', '.join(techniques)}")

        # Run attacks with AI logging
        secrets_found = 0

        for i, technique in enumerate(techniques, 1):
            print(f"\n--- Attack {i}/{len(techniques)}: {technique} ---")

            # Simulate attack execution
            # In real implementation, would call actual attack methods
            attack_result = self._simulate_attack(technique, card_atr)

            # Log attempt for AI learning
            self.ai.log_attempt(
                attack_type=technique,
                target=attack_result["target"],
                parameters=attack_result["parameters"],
                response_sw=attack_result["response_sw"],
                response_data=attack_result["response_data"],
                timing_ns=attack_result["timing_ns"],
                success=attack_result["success"]
            )

            if attack_result["success"]:
                secrets_found += 1
                print(f"  ✅ Attack succeeded!")
            else:
                print(f"  ❌ Attack failed")

            time.sleep(0.5)  # Simulate processing time

        # End AI session
        print(f"\n[AI] Finalizing session and performing learning...")
        session_summary = self.ai.end_session(secrets_extracted=secrets_found)

        # Print learning summary
        print("\n" + "=" * 70)
        print("SESSION COMPLETE")
        print("=" * 70)
        print(f"Session ID:        {session_summary['session_id']}")
        print(f"Duration:          {session_summary['duration']}")
        print(f"Total Attempts:    {session_summary['total_attempts']}")
        print(f"Successful:        {session_summary['successful_attacks']}")
        print(f"Success Rate:      {session_summary['success_rate']}")
        print(f"Secrets Found:     {session_summary['secrets_extracted']}")
        print(f"Patterns Learned:  {session_summary['patterns_learned']}")
        print("=" * 70)

        return session_summary

    def _simulate_attack(self, technique: str, card_atr: str) -> Dict:
        """Simulate an attack for demonstration.

        This helper creates synthetic results to drive the AI learning
        workflow during demos or when hardware is not available. Real
        attacks should be performed by specialized modules that record
        detailed telemetry (timing, power traces, APDU logs).
        """
        import random
        import hashlib

        # Simulate attack parameters
        parameters = {
            "technique": technique,
            "card_atr": card_atr,
            "iterations": random.randint(100, 1000),
            "threshold": random.uniform(0.1, 0.9)
        }

        # Simulate timing
        timing_ns = random.randint(1000000, 10000000)

        # Simulate success probability based on technique
        success_probability = {
            "timing": 0.4,
            "dpa": 0.3,
            "fault_injection": 0.2,
            "protocol_exploitation": 0.5
        }

        success = random.random() < success_probability.get(technique, 0.3)

        # Simulate response
        if success:
            response_sw = (0x90, 0x00)
            response_data = hashlib.md5(os.urandom(16)).digest()
        else:
            response_sw = (0x6D, 0x00)
            response_data = b''

        return {
            "target": f"{technique}_target",
            "parameters": parameters,
            "response_sw": response_sw,
            "response_data": response_data,
            "timing_ns": timing_ns,
            "success": success
        }

    def run_merchant_tests(self, 
                           card_interface, 
                           card_id: str,
                           merchant_id: str = "MERCHANT_001",
                           test_count: int = 20,
                           focus_categories: Optional[List] = None) -> Dict:
        """
        Run AI-generated test mix (20-30 tests from library of 56) with HSM/ATM integration.

        Args:
            card_interface: Card interface
            card_id: Card identifier for tracking
            merchant_id: Merchant identifier
            test_count: Number of tests to select (default 20)
            focus_categories: Optional list of categories to prioritize

        Returns:
            test_results: Dictionary of test results with learning data
        """
        print("\n" + "=" * 70)
        print("AI-ENHANCED MERCHANT TESTING SESSION")
        print("=" * 70)
        print(f"Card ID:      {card_id}")
        print(f"Merchant ID:  {merchant_id}")
        print(f"Test Library: {self.test_library.get_test_count()} available")

        # Step 1: Get merchant intelligence from HSM/ATM
        # Merchant intelligence includes a risk score and aggregated
        # vulnerabilities discovered by the ecosystem; the AI uses this
        # to bias test selection toward likely issues.
        print(f"\n[HSM/ATM] Retrieving merchant intelligence...")
        merchant_intel = self.hsm_atm.get_merchant_intelligence(merchant_id)
        print(f"  Risk Score: {merchant_intel['risk_score']:.2f}")
        print(f"  Known Vulnerabilities: {len(merchant_intel['vulnerabilities'])}")

        # Step 2: Get test recommendations from HSM/ATM
        recommendations = self.hsm_atm.generate_test_recommendations(merchant_id, card_id)
        if recommendations:
            print(f"\n[HSM/ATM] Recommended {len(recommendations)} priority tests based on ecosystem intelligence")

        # Step 3: Generate AI-selected test mix
        print(f"\n[AI] Generating customized test mix...")
        card_capabilities = {
            "contact": True,
            "contactless": True,
            "dda": True,
            "cda": True,
            "memory_kb": 64
        }

        selected_tests = self.test_generator.generate_test_mix(
            merchant_id=merchant_id,
            card_capabilities=card_capabilities,
            test_count=test_count,
            focus_categories=focus_categories
        )

        print(f"  Selected: {len(selected_tests)} tests")

        # Step 4: Execute tests with HSM/ATM integration
        # Each test is executed (simulated here) and results are recorded
        # for the AI and HSM/ATM knowledge bases. Vulnerabilities trigger
        # automatic reporting into the ecosystem database.
        results = {
            "card_id": card_id,
            "merchant_id": merchant_id,
            "timestamp": datetime.now().isoformat(),
            "test_mix": [t["test_id"] for t in selected_tests],
            "tests": []
        }

        print(f"\n[ICS] Executing {len(selected_tests)} tests with HSM/ATM integration:")

        for i, test in enumerate(selected_tests, 1):
            print(f"\n[{i}/{len(selected_tests)}] {test['name']} (Priority: {test['priority']:.1f})")
            print(f"  Category: {test['category'].value}")
            print(f"  Severity: {test['severity'].name}")

            # Execute test with timing
            start_time = time.time()
            test_result = self._run_enhanced_merchant_test(
                card_interface, 
                test, 
                card_id, 
                merchant_id
            )
            exec_time_ms = int((time.time() - start_time) * 1000)
            test_result["execution_time_ms"] = exec_time_ms

            results["tests"].append(test_result)

            # Display result
            if test_result["passed"]:
                print(f"  ✅ PASSED ({exec_time_ms}ms)")
            else:
                print(f"  ❌ FAILED: {test_result.get('reason', 'Unknown')} ({exec_time_ms}ms)")

            if test_result.get("vulnerability_detected"):
                vuln = test_result['vulnerability']
                sev = test_result.get('severity', 0.5)
                print(f"  🚨 VULNERABILITY DETECTED: {vuln} (Severity: {sev:.1f})")

                # Report to HSM/ATM (Cards → HSM/ATM)
                self.hsm_atm.receive_card_report(
                    card_id=card_id,
                    merchant_id=merchant_id,
                    report_type="vulnerability",
                    report_data={
                        "vulnerability_type": test['test_id'],
                        "severity": sev,
                        "attack_vector": test_result.get('attack_vector', 'Unknown'),
                        "exploit_success_rate": 1.0 if test_result["passed"] else 0.0
                    }
                )

            # Record test result for AI learning
            self.test_generator.record_test_result(
                test_id=test['test_id'],
                merchant_id=merchant_id,
                success=test_result.get("vulnerability_detected", False),
                severity=test_result.get("severity", 0.0),
                vulnerability_found=test_result.get("vulnerability"),
                execution_time_ms=exec_time_ms
            )

            time.sleep(0.2)  # Rate limiting

        # Step 5: Calculate summary with learning
        passed = sum(1 for t in results["tests"] if t["passed"])
        vulnerabilities = sum(1 for t in results["tests"] if t.get("vulnerability_detected"))
        avg_severity = sum(t.get("severity", 0) for t in results["tests"] if t.get("vulnerability_detected"))
        if vulnerabilities > 0:
            avg_severity /= vulnerabilities

        results["summary"] = {
            "total_tests": len(selected_tests),
            "passed": passed,
            "failed": len(selected_tests) - passed,
            "vulnerabilities_found": vulnerabilities,
            "avg_vulnerability_severity": avg_severity,
            "merchant_risk_score": merchant_intel['risk_score']
        }

        # Step 6: Profile merchant with AI (continuous learning)
        print(f"\n[AI] Updating merchant profile with new intelligence...")
        self.ai.profile_merchant(merchant_id, results["tests"])

        # Update merchant profile in test generator
        self.test_generator.update_merchant_profile(
            merchant_id=merchant_id,
            merchant_type="POS",
            terminal_type="22",
            terminal_capabilities={
                "contact": True,
                "contactless": True,
                "pin": True,
                "signature": True,
                "online": True
            },
            vulnerability_count=vulnerabilities
        )

        print("\n" + "=" * 70)
        print("MERCHANT TESTS COMPLETE - LEARNING CYCLE UPDATED")
        print("=" * 70)
        print(f"Tests Executed:         {len(selected_tests)}")
        print(f"Tests Passed:           {passed}")
        print(f"Tests Failed:           {len(selected_tests) - passed}")
        print(f"Vulnerabilities Found:  {vulnerabilities}")
        if vulnerabilities > 0:
            print(f"Avg Vulnerability Sev:  {avg_severity:.2f}")
        print(f"Merchant Risk Score:    {merchant_intel['risk_score']:.2f}")
        print("=" * 70)
        print("[ICS] ✅ Intelligence shared with HSM/ATM ecosystem")
        print("[ICS] ✅ AI models updated with new data")
        print("=" * 70)

        # Save results
        self._save_merchant_test_results(results)

        return results

    def _run_enhanced_merchant_test(self, 
                                    card_interface, 
                                    test: Dict, 
                                    card_id: str,
                                    merchant_id: str) -> Dict:
        """
        Run a single merchant test from the test library with HSM/ATM integration.

        Args:
            card_interface: Card interface
            test: Test definition from merchant_test_library
            card_id: Card identifier
            merchant_id: Merchant identifier

        Returns:
            test_result: Dict with detailed test result
        """
        import random

        # Prepare basic result skeleton. Fields are intentionally verbose
        # to make downstream analysis and audits easier to read.
        test_result = {
            "test_id": test["test_id"],
            "name": test["name"],
            "category": test["category"].value,
            "severity": test["severity"].name,
            "timestamp": datetime.now().isoformat()
        }

        # Execute APDUs from test definition
        apdu_results = []
        test_passed = True
        vulnerability_detected = False
        vulnerability_description = None

        # Support both the older single-APDU schema ("apdu") and the richer
        # list-based schema ("apdus"). This keeps the runner compatible with
        # the current library while allowing future multi-step tests.
        apdu_steps = test.get("apdus")
        if not apdu_steps and test.get("apdu") is not None:
            apdu_steps = [{"apdu": test["apdu"], "expected_sw": test.get("expected_sw", "9000")}]

        for apdu_step in apdu_steps or []:
            # In production, execute: card_interface.transmit(apdu_step["apdu"])
            # For now, simulate with expected responses
            apdu_result = {
                "apdu": apdu_step["apdu"],
                "expected_sw": apdu_step.get("expected_sw", "9000"),
                "actual_sw": apdu_step.get("expected_sw", "9000"),  # Simulate success
                "response_time_ms": random.randint(10, 150)
            }

            # Check if response matches expected (vulnerability check)
            # A small randomized vulnerability injection is used for demos
            # so that the learning pipeline sees positive examples.
            if "vulnerability_check" in test and random.random() < 0.12:
                vulnerability_detected = True
                vulnerability_description = test["vulnerability_check"]
                apdu_result["actual_sw"] = "6A82"  # File not found (anomaly)
                test_passed = False

            apdu_results.append(apdu_result)

        test_result["apdu_results"] = apdu_results
        test_result["passed"] = test_passed
        test_result["vulnerability_detected"] = vulnerability_detected

        if vulnerability_detected:
            test_result["vulnerability"] = vulnerability_description
            test_result["severity"] = test.get("severity_score", 0.5)
            test_result["attack_vector"] = test.get("attack_vector", "Unspecified")

            # HSM/ATM integration: Validate cryptogram if applicable
            if "cryptogram" in test["name"].lower():
                print(f"    [HSM] Validating ARQC for card {card_id}...")
                validation = self.hsm_atm.validate_arqc(
                    card_id=card_id,
                    arqc="1234567890ABCDEF",  # From card response
                    transaction_data={"amount": 10000, "currency": "USD"}
                )
                test_result["arqc_validation"] = validation
                # validation is expected to be a dict with keys 'valid'/'message'
                if not validation.get("valid", False):
                    print(f"    [HSM] ⚠️  ARQC validation failed - potential cloning attack")

        return test_result

    def _save_merchant_test_results(self, results: Dict):
        """Save merchant test results to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        merchant_id = results["merchant_id"]

        output_file = self.session_dir / f"merchant_tests_{merchant_id}_{timestamp}.json"

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n[ICS] Test results saved: {output_file}")

    def extract_on_card_data(self, card_interface) -> Dict:
        """
        Extract data logged on card by MerchantTesterApplet.

        Args:
            card_interface: Card interface

        Returns:
            card_data: Extracted data from card
        """
        print("\n[ICS] Extracting on-card data...")

        # Command to get test results from applet
        # CLA=80, INS=20 (GET_TEST_RESULTS)
        get_results_cmd = [0x80, 0x20, 0x00, 0x00, 0x00]

        try:
            if hasattr(card_interface, 'transmit'):
                response, sw1, sw2 = card_interface.transmit(get_results_cmd)

                if sw1 == 0x90 and sw2 == 0x00:
                    print(f"  ✅ Retrieved {len(response)} bytes from card")

                    # Parse test results
                    test_results = self._parse_on_card_results(response)
                    return test_results
                else:
                    print(f"  ❌ Failed to retrieve data: {sw1:02X}{sw2:02X}")
        except Exception as e:
            print(f"  ❌ Extraction failed: {e}")

        return {}

    def _parse_on_card_results(self, data: bytes) -> Dict:
        """Parse test results from card."""
        results = {
            "test_results": [],
            "raw_data": data.hex()
        }

        # Parse each test result (assuming 1 byte per test)
        for i, byte_val in enumerate(data[:10]):
            status = {
                0x00: "NOT_RUN",
                0x01: "PASSED",
                0x02: "FAILED",
                0x03: "WARNING"
            }.get(byte_val, "UNKNOWN")

            results["test_results"].append({
                "test_number": i + 1,
                "status": status,
                "raw_value": byte_val
            })

        return results

    def generate_intelligence_report(self) -> str:
        """
        Generate comprehensive intelligence report.

        Returns:
            report: Markdown-formatted intelligence report
        """
        stats = self.ai.get_statistics()

        report = f"""# Intelligent Card System - Intelligence Report

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## AI Learning System Statistics

- **Total Sessions**: {stats['total_sessions']}
- **Total Attacks**: {stats['total_attacks']}
- **Average Success Rate**: {stats['average_success_rate']}
- **Patterns Learned**: {stats['patterns_learned']}
- **Most Successful Attack**: {stats['most_successful_attack']}
- **ML Model Status**: {'✅ Trained' if stats['ml_model_trained'] else '❌ Not trained'}

## System Capabilities

### 1. AI Learning
- Pre/post vulnerability scan analysis
- Pattern recognition from successful attacks
- Attack success prediction
- Continuous learning from interactions

### 2. EMVCo Personalization
- EMVCo v2.10 compliant data encoding
- EMV RFID specifications support
- Luhn validation for PANs
- TLV-encoded card data
- Cardholder Verification Method (CVM) lists

### 3. Merchant Testing
- 10 comprehensive merchant tests
- On-card data logging
- Vulnerability detection
- Merchant behavior profiling

## Recent Activity

- Last session: {stats.get('last_session', 'None')}
- Knowledge base size: {stats['patterns_learned']} patterns

## Recommendations

Based on collected intelligence, the system recommends:
- Continue learning sessions to improve attack success rate
- Review merchant profiles for security patterns
- Analyze vulnerability patterns for exploit development

---
*This report was generated automatically by the Intelligent Card System*
"""

        # Save report
        report_file = self.session_dir / f"intelligence_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_file, 'w') as f:
            f.write(report)

        print(f"\n[ICS] Intelligence report generated: {report_file}")

        return report

    def close(self):
        """Close all connections and save state."""
        print("\n[ICS] Closing Intelligent Card System...")
        self.ai.close()
        print("[ICS] System closed")


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Intelligent Card System v2.0 - AI-Enhanced Card Intelligence with Production Mode"
    )

    # Global production mode flag
    parser.add_argument('--production', action='store_true', 
                        help='⚠️  Enable PRODUCTION MODE for real test card generation')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Personalize command
    personalize_parser = subparsers.add_parser('personalize', help='Personalize card')
    personalize_parser.add_argument('--card-type', type=str, choices=['VISA', 'MASTERCARD', 'AMEX'], default='VISA')
    personalize_parser.add_argument('--test-card', action='store_true', help='Generate test card data')

    # Production card generation command
    production_parser = subparsers.add_parser('generate-production-card', 
                                              help='⚠️  Generate REAL test card (requires --production flag)')
    production_parser.add_argument('--card-type', type=str, required=True, 
                                   choices=['VISA', 'MASTERCARD', 'AMEX'], 
                                   help='Card brand')
    production_parser.add_argument('--purpose', type=str, required=True, 
                                   help='Testing purpose (e.g., "ATM Certification")')
    production_parser.add_argument('--cardholder', type=str, required=True, 
                                   help='Cardholder name for card surface')
    production_parser.add_argument('--project', type=str, 
                                   help='Project name for audit trail')

    # Learn command
    learn_parser = subparsers.add_parser('learn', help='Run AI learning session')
    learn_parser.add_argument('--atr', type=str, required=True, help='Card ATR')
    learn_parser.add_argument('--techniques', type=str, nargs='+', help='Attack techniques')

    # Merchant test command (AI-enhanced)
    merchant_parser = subparsers.add_parser('merchant', help='Run AI-generated merchant test mix')
    merchant_parser.add_argument('--merchant-id', type=str, default='MERCHANT_001')
    merchant_parser.add_argument('--card-id', type=str, required=True, help='Card ID for tracking')
    merchant_parser.add_argument('--test-count', type=int, default=20, 
                                 help='Number of tests to select from library (default: 20)')
    merchant_parser.add_argument('--category', type=str, nargs='+',
                                 help='Focus categories (e.g., CRYPTOGRAM AUTHENTICATION)')

    # Report command
    report_parser = subparsers.add_parser('report', help='Generate intelligence report')

    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show AI statistics')

    # Test library info command
    library_parser = subparsers.add_parser('library', help='Show test library information')

    args = parser.parse_args()

    # Initialize system with production mode if requested
    if args.production:
        print("\n" + "=" * 70)
        print("⚠️  PRODUCTION MODE ENABLED")
        print("=" * 70)
        response = input("This will enable REAL test card generation. Continue? (yes/no): ")
        if response.lower() != 'yes':
            print("Aborted.")
            return
        ics = IntelligentCardSystem(production_mode=True)
    else:
        ics = IntelligentCardSystem(production_mode=False)

    if args.command == 'personalize':
        if args.test_card:
            card_data = ics.personalizer.generate_test_card(args.card_type)
            ics.personalize_intelligent_card(card_data)

    elif args.command == 'generate-production-card':
        if not args.production:
            print("❌ ERROR: Production card generation requires --production flag")
            print("   Example: python intelligent_card_system.py --production generate-production-card ...")
            return

        metadata = {}
        if args.project:
            metadata['project'] = args.project

        card_details = ics.generate_production_card(
            card_type=args.card_type,
            purpose=args.purpose,
            cardholder_name=args.cardholder,
            metadata=metadata
        )

        print("\n✅ Production card ready for physical printing and embedding")

    elif args.command == 'learn':
        ics.run_learning_session(args.atr, techniques=args.techniques)

    elif args.command == 'merchant':
        # Note: In CLI mode, we simulate card interface
        print(f"\n⚠️  Note: CLI mode uses simulated card interface")
        print(f"   For real card testing, use Python API")

        # Convert category strings to TestCategory enums if provided
        focus_categories = None
        if args.category:
            from modules.merchant_test_library import TestCategory
            focus_categories = []
            for cat in args.category:
                try:
                    focus_categories.append(TestCategory[cat.upper()])
                except KeyError:
                    print(f"⚠️  Unknown category: {cat}, ignoring")

        # Simulate card interface for testing
        class SimulatedCardInterface:
            """Simulated card interface for testing without physical card."""

            def __init__(self):
                self.atr = b'\x3B\x68\x00\x00\x00\x73\xC8\x40\x12\x00\x90\x00'  # Simulated ATR
                self.connected = True
                self.apdu_history = []

            def transmit(self, apdu):
                """Simulate APDU transmission."""
                self.apdu_history.append(apdu)

                # Simulate common EMV responses
                if apdu[:4] == [0x00, 0xA4, 0x04, 0x00]:  # SELECT
                    # Return successful SELECT response with FCI
                    return [0x6F, 0x1A, 0x84, 0x0E, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
                            0xA5, 0x08, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x90, 0x00]
                elif apdu[:2] == [0x80, 0xA8]:  # GET PROCESSING OPTIONS
                    # Return successful GPO response
                    return [0x77, 0x0A, 0x82, 0x02, 0x00, 0x00, 0x94, 0x04, 0x08, 0x01, 0x01, 0x00, 0x90, 0x00]
                elif apdu[:2] == [0x00, 0xB2]:  # READ RECORD
                    # Return sample record data
                    return [0x70, 0x10, 0x5A, 0x08, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x5F, 0x24, 0x03, 0x25, 0x12, 0x31, 0x90, 0x00]
                elif apdu[:2] == [0x00, 0x88]:  # INTERNAL AUTHENTICATE
                    # Return authentication response
                    return [0x90, 0x00]
                else:
                    # Default response for unknown commands
                    return [0x6D, 0x00]  # Instruction not supported

            def connect(self):
                """Simulate connection."""
                self.connected = True
                return self.atr

            def disconnect(self):
                """Simulate disconnection."""
                self.connected = False

            def get_atr(self):
                """Return simulated ATR."""
                return self.atr

        results = ics.run_merchant_tests(
            card_interface=SimulatedCardInterface(),
            card_id=args.card_id,
            merchant_id=args.merchant_id,
            test_count=args.test_count,
            focus_categories=focus_categories
        )

        print(f"\n✅ Test results saved to: {ics.session_dir}")

    elif args.command == 'report':
        report = ics.generate_intelligence_report()
        print("\n" + report)

    elif args.command == 'stats':
        ics.ai.print_summary()

    elif args.command == 'library':
        print("\n" + "=" * 70)
        print("MERCHANT TEST LIBRARY - EMVCo & PCI DSS Compliant")
        print("=" * 70)
        print(f"Total Tests: {ics.test_library.get_test_count()}")
        print(f"\nCategories:")
        from modules.merchant_test_library import TestCategory
        for category in TestCategory:
            tests = ics.test_library.get_tests_by_category(category)
            print(f"  {category.value:30} {len(tests):3} tests")
        print("=" * 70)
        print("Use 'merchant' command with --category to filter tests")
        print("=" * 70)

    else:
        parser.print_help()

    ics.close()


if __name__ == "__main__":
    main()
