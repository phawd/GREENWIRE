#!/usr/bin/env python3
"""
AI Test Generator for Intelligent Card System
Generates customized test mixes based on learned patterns, merchant profiles, and card capabilities.

Uses Machine Learning to:
- Select optimal tests per merchant
- Prioritize based on vulnerability history
- Adapt test mix based on success patterns
- Learn from ecosystem-wide intelligence (cards ↔ HSM/ATM ↔ merchants)

Model: Gradient Boosting for multi-class test priority prediction
Features: merchant_type, terminal_capabilities, vulnerability_history, time_of_day, transaction_amount
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import random

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[WARN] scikit-learn not available, using rule-based fallback")

from modules.merchant_test_library import get_test_library, TestCategory, TestSeverity


class AITestGenerator:
    """
    AI-driven test generator using ML to select optimal test mixes.

    Workflow:
    1. Analyze merchant profile (type, capabilities, vulnerability history)
    2. Analyze card capabilities (contact/contactless, crypto, memory)
    3. Query learned patterns from AI learning database
    4. Use ML model to predict test priorities
    5. Generate customized test mix (15-30 tests from library of 56)
    6. Return priority-ranked test list
    """

    def __init__(self, db_path: str = "ai_learning_sessions/learning.db"):
        """
        Initialize AI test generator.

        Args:
            db_path: Path to AI learning database
        """
        self.db_path = db_path
        self.test_library = get_test_library()
        self.model = None
        self.scaler = None
        self.is_trained = False

        # Ensure database exists
        self._ensure_database()

        # Load or train model
        if ML_AVAILABLE:
            self._load_or_train_model()

    def _ensure_database(self):
        """Ensure AI learning database exists with test_effectiveness table."""
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create test_effectiveness table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS test_effectiveness (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_id TEXT NOT NULL,
                merchant_id TEXT NOT NULL,
                merchant_type TEXT,
                terminal_capabilities TEXT,
                success_rate REAL DEFAULT 0.0,
                avg_severity REAL DEFAULT 0.0,
                execution_count INTEGER DEFAULT 0,
                last_execution TEXT,
                vulnerabilities_found TEXT,
                UNIQUE(test_id, merchant_id)
            )
        """)

        # Create merchant_profiles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS merchant_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                merchant_id TEXT UNIQUE NOT NULL,
                merchant_type TEXT,
                terminal_type TEXT,
                terminal_capabilities TEXT,
                vulnerability_count INTEGER DEFAULT 0,
                last_tested TEXT,
                risk_score REAL DEFAULT 0.5
            )
        """)

        # Create test_history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS test_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_id TEXT NOT NULL,
                merchant_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                success BOOLEAN,
                severity REAL,
                vulnerability_found TEXT,
                execution_time_ms INTEGER
            )
        """)

        conn.commit()
        conn.close()

    def _load_or_train_model(self):
        """Load existing model or train new one."""
        model_path = "ai_learning_sessions/test_generator_model.json"

        if os.path.exists(model_path):
            try:
                with open(model_path, "r") as f:
                    model_data = json.load(f)
                    # Model serialization would go here
                    # For now, retrain on startup
                    self._train_model()
            except Exception as e:
                print(f"[WARN] Failed to load model: {e}, retraining...")
                self._train_model()
        else:
            self._train_model()

    def _train_model(self):
        """Train ML model on historical test effectiveness data."""
        if not ML_AVAILABLE:
            print("[INFO] ML not available, using rule-based generator")
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Fetch training data
        cursor.execute("""
            SELECT 
                test_id,
                merchant_type,
                terminal_capabilities,
                success_rate,
                avg_severity,
                execution_count
            FROM test_effectiveness
            WHERE execution_count > 0
        """)

        rows = cursor.fetchall()
        conn.close()

        if len(rows) < 10:
            print(f"[INFO] Insufficient training data ({len(rows)} samples), using rule-based generator")
            self.is_trained = False
            return

        # Prepare features and labels
        X = []
        y = []

        for row in rows:
            test_id, merchant_type, terminal_caps, success_rate, avg_severity, exec_count = row

            # Feature engineering
            features = self._extract_features(
                merchant_type or "unknown",
                terminal_caps or "{}",
                0,  # transaction_amount (not available in training)
                datetime.now().hour  # time_of_day
            )

            X.append(features)

            # Label: Priority score (0-100)
            priority = (success_rate * 50) + (avg_severity * 50)
            y.append(priority)

        X = np.array(X)
        y = np.array(y)

        # Train model
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        )

        # Convert continuous labels to classes for classification
        y_classes = np.digitize(y, bins=[0, 25, 50, 75, 100]) - 1

        self.model.fit(X_scaled, y_classes)
        self.is_trained = True

        print(f"[INFO] Model trained on {len(rows)} samples")

    def _extract_features(
        self,
        merchant_type: str,
        terminal_capabilities: str,
        transaction_amount: float,
        time_of_day: int
    ) -> List[float]:
        """
        Extract feature vector for ML model.

        Features:
        1. Merchant type (one-hot: ATM, POS, e-commerce, mPOS)
        2. Terminal capabilities (bitfield: contact, contactless, PIN, signature)
        3. Transaction amount (normalized)
        4. Time of day (hour, normalized)
        5. Terminal country (domestic=0, international=1)
        """
        features = []

        # Merchant type (one-hot)
        merchant_types = ["ATM", "POS", "e-commerce", "mPOS", "unknown"]
        for mt in merchant_types:
            features.append(1.0 if merchant_type == mt else 0.0)

        # Terminal capabilities
        try:
            caps = json.loads(terminal_capabilities) if isinstance(terminal_capabilities, str) else terminal_capabilities
        except:
            caps = {}

        features.append(1.0 if caps.get("contact") else 0.0)
        features.append(1.0 if caps.get("contactless") else 0.0)
        features.append(1.0 if caps.get("pin") else 0.0)
        features.append(1.0 if caps.get("signature") else 0.0)
        features.append(1.0 if caps.get("online") else 0.0)

        # Transaction amount (log-normalized)
        features.append(np.log1p(transaction_amount) / 10.0 if transaction_amount > 0 else 0.0)

        # Time of day (sin/cos encoding for cyclical nature)
        features.append(np.sin(2 * np.pi * time_of_day / 24))
        features.append(np.cos(2 * np.pi * time_of_day / 24))

        return features

    def generate_test_mix(
        self,
        merchant_id: str,
        card_capabilities: Dict,
        test_count: int = 20,
        focus_categories: Optional[List[TestCategory]] = None
    ) -> List[Dict]:
        """
        Generate AI-selected test mix for a merchant.

        Args:
            merchant_id: Unique merchant identifier
            card_capabilities: Dict with card capabilities (contact, contactless, crypto, memory)
            test_count: Number of tests to select (default 20)
            focus_categories: Optional list of categories to prioritize

        Returns:
            List of test dicts with priority scores, sorted by priority (highest first)
        """
        print(f"\n[AI Test Generator] Generating test mix for merchant {merchant_id}")

        # Get merchant profile
        merchant_profile = self._get_merchant_profile(merchant_id)

        # Get all available tests
        all_tests = []
        for test_id in self.test_library.get_all_test_ids():
            test = self.test_library.get_test(test_id)
            all_tests.append({**test, "test_id": test_id})

        # Filter by card capabilities
        compatible_tests = self._filter_by_capabilities(all_tests, card_capabilities)

        print(f"  Compatible tests: {len(compatible_tests)}/{len(all_tests)}")

        # Calculate priority for each test
        prioritized_tests = []

        for test in compatible_tests:
            if self.is_trained and ML_AVAILABLE:
                # ML-based priority
                priority = self._calculate_ml_priority(
                    test,
                    merchant_profile,
                    card_capabilities
                )
            else:
                # Rule-based priority (fallback)
                priority = self._calculate_rule_based_priority(
                    test,
                    merchant_profile,
                    card_capabilities,
                    focus_categories
                )

            prioritized_tests.append({
                **test,
                "priority": priority
            })

        # Sort by priority (highest first)
        prioritized_tests.sort(key=lambda x: x["priority"], reverse=True)

        # Select top N tests
        selected_tests = prioritized_tests[:test_count]

        print(f"  Selected {len(selected_tests)} tests:")
        for i, test in enumerate(selected_tests[:5], 1):
            print(f"    {i}. [{test['test_id']}] {test['name']} (priority: {test['priority']:.2f})")
        if len(selected_tests) > 5:
            print(f"    ... and {len(selected_tests) - 5} more")

        return selected_tests

    def _get_merchant_profile(self, merchant_id: str) -> Dict:
        """Retrieve merchant profile from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                merchant_type,
                terminal_type,
                terminal_capabilities,
                vulnerability_count,
                risk_score
            FROM merchant_profiles
            WHERE merchant_id = ?
        """, (merchant_id,))

        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "merchant_type": row[0] or "POS",
                "terminal_type": row[1] or "22",  # 22 = POS
                "terminal_capabilities": json.loads(row[2]) if row[2] else {},
                "vulnerability_count": row[3] or 0,
                "risk_score": row[4] or 0.5
            }
        else:
            # Default profile for new merchant
            return {
                "merchant_type": "POS",
                "terminal_type": "22",
                "terminal_capabilities": {
                    "contact": True,
                    "contactless": True,
                    "pin": True,
                    "signature": True,
                    "online": True
                },
                "vulnerability_count": 0,
                "risk_score": 0.5
            }

    def _filter_by_capabilities(self, tests: List[Dict], card_capabilities: Dict) -> List[Dict]:
        """Filter tests based on card and terminal capabilities."""
        compatible = []

        for test in tests:
            # Check if test is compatible with card
            # For now, accept all tests (future: add capability requirements to test definitions)
            compatible.append(test)

        return compatible

    def _calculate_ml_priority(
        self,
        test: Dict,
        merchant_profile: Dict,
        card_capabilities: Dict
    ) -> float:
        """Calculate test priority using ML model."""
        if not self.is_trained or not ML_AVAILABLE:
            return self._calculate_rule_based_priority(test, merchant_profile, card_capabilities, None)

        # Extract features
        features = self._extract_features(
            merchant_profile["merchant_type"],
            json.dumps(merchant_profile["terminal_capabilities"]),
            0,  # transaction_amount (not available)
            datetime.now().hour
        )

        # Predict priority class
        X = np.array([features])
        X_scaled = self.scaler.transform(X)

        priority_class = self.model.predict(X_scaled)[0]
        priority_proba = self.model.predict_proba(X_scaled)[0]

        # Convert class to score (0-100)
        priority = (priority_class * 25) + (priority_proba[priority_class] * 25)

        # Boost priority based on severity
        severity_boost = test["severity"].value * 20
        priority += severity_boost

        # Boost priority based on merchant vulnerability history
        if merchant_profile["vulnerability_count"] > 0:
            priority += min(merchant_profile["vulnerability_count"] * 2, 20)

        return min(priority, 100.0)

    def _calculate_rule_based_priority(
        self,
        test: Dict,
        merchant_profile: Dict,
        card_capabilities: Dict,
        focus_categories: Optional[List[TestCategory]]
    ) -> float:
        """
        Calculate test priority using rule-based heuristics (fallback).

        Priority factors:
        1. Test severity (40%)
        2. Merchant vulnerability history (30%)
        3. Category focus (20%)
        4. Randomness for exploration (10%)
        """
        priority = 0.0

        # 1. Severity (40%)
        priority += test["severity"].value * 40

        # 2. Merchant vulnerability history (30%)
        if merchant_profile["vulnerability_count"] > 0:
            history_bonus = min(merchant_profile["vulnerability_count"] * 3, 30)
            priority += history_bonus

        # 3. Category focus (20%)
        if focus_categories and test["category"] in focus_categories:
            priority += 20

        # 4. Randomness (10%)
        priority += random.uniform(0, 10)

        # 5. Boost critical security tests
        critical_keywords = ["PIN", "CVM", "cryptogram", "authentication", "ARQC"]
        if any(kw.lower() in test["name"].lower() for kw in critical_keywords):
            priority += 10

        return min(priority, 100.0)

    def record_test_result(
        self,
        test_id: str,
        merchant_id: str,
        success: bool,
        severity: float,
        vulnerability_found: Optional[str] = None,
        execution_time_ms: int = 0
    ):
        """
        Record test execution result for future learning.

        Args:
            test_id: Test identifier
            merchant_id: Merchant identifier
            success: Whether test found vulnerability
            severity: Vulnerability severity (0-1)
            vulnerability_found: Description of vulnerability
            execution_time_ms: Execution time in milliseconds
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Insert into test_history
        cursor.execute("""
            INSERT INTO test_history (
                test_id,
                merchant_id,
                timestamp,
                success,
                severity,
                vulnerability_found,
                execution_time_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            test_id,
            merchant_id,
            datetime.now().isoformat(),
            success,
            severity,
            vulnerability_found,
            execution_time_ms
        ))

        # Update test_effectiveness (running average)
        cursor.execute("""
            INSERT INTO test_effectiveness (
                test_id,
                merchant_id,
                merchant_type,
                terminal_capabilities,
                success_rate,
                avg_severity,
                execution_count,
                last_execution,
                vulnerabilities_found
            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(test_id, merchant_id) DO UPDATE SET
                success_rate = (success_rate * execution_count + ?) / (execution_count + 1),
                avg_severity = (avg_severity * execution_count + ?) / (execution_count + 1),
                execution_count = execution_count + 1,
                last_execution = ?,
                vulnerabilities_found = CASE 
                    WHEN ? THEN vulnerabilities_found || ',' || ?
                    ELSE vulnerabilities_found
                END
        """, (
            test_id,
            merchant_id,
            "unknown",  # merchant_type (fetch from profile if needed)
            "{}",       # terminal_capabilities
            severity,
            1.0 if success else 0.0,
            datetime.now().isoformat(),
            vulnerability_found or "",
            1.0 if success else 0.0,
            severity,
            datetime.now().isoformat(),
            success,
            vulnerability_found or ""
        ))

        conn.commit()
        conn.close()

    def update_merchant_profile(
        self,
        merchant_id: str,
        merchant_type: str,
        terminal_type: str,
        terminal_capabilities: Dict,
        vulnerability_count: int = None
    ):
        """Update merchant profile in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if vulnerability_count is not None:
            cursor.execute("""
                INSERT INTO merchant_profiles (
                    merchant_id,
                    merchant_type,
                    terminal_type,
                    terminal_capabilities,
                    vulnerability_count,
                    last_tested
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(merchant_id) DO UPDATE SET
                    merchant_type = ?,
                    terminal_type = ?,
                    terminal_capabilities = ?,
                    vulnerability_count = vulnerability_count + ?,
                    last_tested = ?
            """, (
                merchant_id,
                merchant_type,
                terminal_type,
                json.dumps(terminal_capabilities),
                vulnerability_count,
                datetime.now().isoformat(),
                merchant_type,
                terminal_type,
                json.dumps(terminal_capabilities),
                vulnerability_count,
                datetime.now().isoformat()
            ))
        else:
            cursor.execute("""
                INSERT INTO merchant_profiles (
                    merchant_id,
                    merchant_type,
                    terminal_type,
                    terminal_capabilities,
                    last_tested
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(merchant_id) DO UPDATE SET
                    merchant_type = ?,
                    terminal_type = ?,
                    terminal_capabilities = ?,
                    last_tested = ?
            """, (
                merchant_id,
                merchant_type,
                terminal_type,
                json.dumps(terminal_capabilities),
                datetime.now().isoformat(),
                merchant_type,
                terminal_type,
                json.dumps(terminal_capabilities),
                datetime.now().isoformat()
            ))

        conn.commit()
        conn.close()

    def get_statistics(self) -> Dict:
        """Get test generation statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM test_history")
        total_executions = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT merchant_id) FROM merchant_profiles")
        total_merchants = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(success_rate) FROM test_effectiveness WHERE execution_count > 0")
        avg_success_rate = cursor.fetchone()[0] or 0.0

        cursor.execute("SELECT AVG(avg_severity) FROM test_effectiveness WHERE execution_count > 0")
        avg_severity = cursor.fetchone()[0] or 0.0

        conn.close()

        return {
            "total_executions": total_executions,
            "total_merchants": total_merchants,
            "avg_success_rate": avg_success_rate,
            "avg_severity": avg_severity,
            "ml_model_trained": self.is_trained,
            "total_tests_available": self.test_library.get_test_count()
        }


if __name__ == "__main__":
    # Demo usage
    generator = AITestGenerator()

    print("=" * 70)
    print("AI TEST GENERATOR DEMO")
    print("=" * 70)

    # Update merchant profile
    generator.update_merchant_profile(
        merchant_id="MERCHANT_001",
        merchant_type="POS",
        terminal_type="22",
        terminal_capabilities={
            "contact": True,
            "contactless": True,
            "pin": True,
            "signature": True,
            "online": True
        }
    )

    # Generate test mix
    card_caps = {
        "contact": True,
        "contactless": True,
        "dda": True,
        "cda": True,
        "memory_kb": 64
    }

    test_mix = generator.generate_test_mix(
        merchant_id="MERCHANT_001",
        card_capabilities=card_caps,
        test_count=15,
        focus_categories=[TestCategory.CRYPTOGRAPHIC, TestCategory.SECURITY_BOUNDARY]
    )

    print("\n" + "=" * 70)
    print("STATISTICS")
    print("=" * 70)
    stats = generator.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
