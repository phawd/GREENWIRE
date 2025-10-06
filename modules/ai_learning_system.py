#!/usr/bin/env python3
"""
AI Learning System for GREENWIRE
Continuously learns from vulnerability scan sessions, merchant interactions, and card behaviors.

Features:
- Session-based learning from before/after scan data
- Pattern recognition in successful attacks
- Adaptive fuzzing strategy evolution
- Merchant behavior profiling
- Card response prediction
- Knowledge base accumulation
"""

import os
import sys
import json
import sqlite3
import hashlib
import pickle
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict, Counter

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    HAS_ML = True
except ImportError:
    HAS_ML = False
    print("Warning: scikit-learn not available. Install with: pip install scikit-learn")


class AILearningSystem:
    """
    AI-powered learning system that improves from every interaction.

    Learns from:
    - Vulnerability scan sessions (before/after comparisons)
    - Successful attack patterns
    - Merchant responses to different card behaviors
    - Card compatibility and failure patterns
    - Timing characteristics across different scenarios
    """

    def __init__(self, knowledge_base_dir: str = "ai_knowledge_base"):
        """Initialize AI learning system."""
        self.kb_dir = Path(knowledge_base_dir)
        self.kb_dir.mkdir(exist_ok=True)

        # Database for structured learning
        self.db_path = self.kb_dir / "learning.db"
        self.conn = sqlite3.connect(self.db_path)
        self._init_database()

        # ML models
        self.attack_classifier = None
        self.behavior_clusterer = None
        self.scaler = StandardScaler()

        # Knowledge caches
        self.attack_patterns = defaultdict(list)
        self.merchant_profiles = {}
        self.card_signatures = {}
        self.successful_exploits = []
        self.failed_attempts = []

        # Session tracking
        self.current_session = None
        self.session_history = []

        # Load existing knowledge
        self._load_knowledge()

        print(f"[AI] Learning system initialized: {self.kb_dir}")
        print(f"[AI] Knowledge base size: {len(self.attack_patterns)} attack patterns")

    def _init_database(self):
        """Initialize SQLite database for structured learning."""
        cursor = self.conn.cursor()

        # Vulnerability scan sessions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                start_time TEXT,
                end_time TEXT,
                card_atr TEXT,
                techniques_used TEXT,
                secrets_extracted INTEGER,
                success_rate REAL,
                metadata TEXT
            )
        ''')

        # Attack attempts (for pattern learning)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                attack_type TEXT,
                target TEXT,
                parameters TEXT,
                response_sw TEXT,
                response_data TEXT,
                timing_ns INTEGER,
                success BOOLEAN,
                timestamp TEXT,
                FOREIGN KEY(session_id) REFERENCES scan_sessions(session_id)
            )
        ''')

        # Merchant profiles
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS merchant_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                merchant_id TEXT UNIQUE,
                merchant_name TEXT,
                terminal_capabilities TEXT,
                observed_behaviors TEXT,
                vulnerability_score REAL,
                test_results TEXT,
                last_updated TEXT
            )
        ''')

        # Card signatures (behavioral fingerprints)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS card_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_hash TEXT UNIQUE,
                atr TEXT,
                aid_list TEXT,
                timing_profile TEXT,
                vulnerability_profile TEXT,
                successful_attacks TEXT,
                last_seen TEXT
            )
        ''')

        # Knowledge patterns (learned behaviors)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS knowledge_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT,
                pattern_signature TEXT,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                confidence REAL,
                description TEXT,
                created_at TEXT,
                last_used TEXT
            )
        ''')

        self.conn.commit()

    def start_session(self, session_type: str = "vulnerability_scan", 
                      card_info: Dict = None) -> str:
        """
        Start a new learning session.

        Args:
            session_type: Type of session (vulnerability_scan, merchant_test, personalization)
            card_info: Information about the card being tested

        Returns:
            session_id: Unique identifier for this session
        """
        session_id = f"{session_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(os.urandom(16)).hexdigest()[:8]}"

        self.current_session = {
            "session_id": session_id,
            "type": session_type,
            "start_time": datetime.now().isoformat(),
            "card_info": card_info or {},
            "attempts": [],
            "successes": [],
            "failures": [],
            "learned_patterns": [],
            "metrics": {
                "total_attempts": 0,
                "successful_attacks": 0,
                "timing_samples": [],
                "secrets_extracted": 0
            }
        }

        # Store in database
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO scan_sessions (session_id, start_time, card_atr, metadata)
            VALUES (?, ?, ?, ?)
        ''', (
            session_id,
            self.current_session["start_time"],
            card_info.get("ATR", "") if card_info else "",
            json.dumps({"type": session_type})
        ))
        self.conn.commit()

        print(f"\n[AI] Session started: {session_id}")
        print(f"[AI] Session type: {session_type}")

        return session_id

    def log_attempt(self, attack_type: str, target: str, parameters: Dict,
                    response_sw: Tuple[int, int], response_data: bytes,
                    timing_ns: int, success: bool):
        """
        Log an attack attempt for learning.

        Args:
            attack_type: Type of attack (timing, dpa, fault_injection, protocol_exploit)
            target: Target of attack (pin_verification, cryptogram, memory_dump)
            parameters: Attack parameters
            response_sw: Status word (sw1, sw2)
            response_data: Response data
            timing_ns: Execution time in nanoseconds
            success: Whether attack succeeded
        """
        if not self.current_session:
            print("[AI] Warning: No active session. Call start_session() first.")
            return

        attempt = {
            "attack_type": attack_type,
            "target": target,
            "parameters": parameters,
            "response_sw": response_sw,
            "response_data": response_data.hex() if response_data else "",
            "timing_ns": timing_ns,
            "success": success,
            "timestamp": datetime.now().isoformat()
        }

        self.current_session["attempts"].append(attempt)
        self.current_session["metrics"]["total_attempts"] += 1

        if success:
            self.current_session["successes"].append(attempt)
            self.current_session["metrics"]["successful_attacks"] += 1
            self.successful_exploits.append(attempt)
        else:
            self.current_session["failures"].append(attempt)
            self.failed_attempts.append(attempt)

        self.current_session["metrics"]["timing_samples"].append(timing_ns)

        # Store in database
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO attack_attempts 
            (session_id, attack_type, target, parameters, response_sw, 
             response_data, timing_ns, success, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            self.current_session["session_id"],
            attack_type,
            target,
            json.dumps(parameters),
            f"{response_sw[0]:02X}{response_sw[1]:02X}",
            attempt["response_data"],
            timing_ns,
            success,
            attempt["timestamp"]
        ))
        self.conn.commit()

    def end_session(self, secrets_extracted: int = 0) -> Dict:
        """
        End current session and perform learning.

        Args:
            secrets_extracted: Number of secrets successfully extracted

        Returns:
            session_summary: Summary of what was learned
        """
        if not self.current_session:
            print("[AI] Warning: No active session to end.")
            return {}

        self.current_session["end_time"] = datetime.now().isoformat()
        self.current_session["metrics"]["secrets_extracted"] = secrets_extracted

        # Calculate success rate
        total = self.current_session["metrics"]["total_attempts"]
        successful = self.current_session["metrics"]["successful_attacks"]
        success_rate = (successful / total * 100) if total > 0 else 0

        # Update database
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE scan_sessions 
            SET end_time = ?, secrets_extracted = ?, success_rate = ?,
                techniques_used = ?, metadata = ?
            WHERE session_id = ?
        ''', (
            self.current_session["end_time"],
            secrets_extracted,
            success_rate,
            json.dumps([a["attack_type"] for a in self.current_session["successes"]]),
            json.dumps(self.current_session["metrics"]),
            self.current_session["session_id"]
        ))
        self.conn.commit()

        # Perform learning
        learned_patterns = self._learn_from_session()

        # Save session to history
        self.session_history.append(self.current_session)

        # Generate summary
        summary = {
            "session_id": self.current_session["session_id"],
            "duration": self._calculate_duration(
                self.current_session["start_time"],
                self.current_session["end_time"]
            ),
            "total_attempts": total,
            "successful_attacks": successful,
            "success_rate": f"{success_rate:.1f}%",
            "secrets_extracted": secrets_extracted,
            "patterns_learned": len(learned_patterns),
            "new_knowledge": learned_patterns
        }

        print(f"\n[AI] Session ended: {self.current_session['session_id']}")
        print(f"[AI] Success rate: {success_rate:.1f}%")
        print(f"[AI] New patterns learned: {len(learned_patterns)}")

        # Save knowledge
        self._save_knowledge()

        # Reset current session
        self.current_session = None

        return summary

    def _learn_from_session(self) -> List[Dict]:
        """
        Perform machine learning on session data.

        Returns:
            learned_patterns: List of newly discovered patterns
        """
        learned_patterns = []

        if not self.current_session["successes"]:
            return learned_patterns

        # Pattern 1: Successful attack sequences
        success_sequence = self._identify_attack_sequence_patterns()
        if success_sequence:
            learned_patterns.append({
                "type": "attack_sequence",
                "pattern": success_sequence,
                "confidence": 0.9
            })

        # Pattern 2: Timing-based vulnerabilities
        timing_patterns = self._identify_timing_patterns()
        if timing_patterns:
            learned_patterns.extend(timing_patterns)

        # Pattern 3: Parameter combinations that work
        param_patterns = self._identify_parameter_patterns()
        if param_patterns:
            learned_patterns.extend(param_patterns)

        # Pattern 4: Response patterns that indicate vulnerability
        response_patterns = self._identify_response_patterns()
        if response_patterns:
            learned_patterns.extend(response_patterns)

        # Store patterns in knowledge base
        for pattern in learned_patterns:
            self._store_pattern(pattern)
            self.attack_patterns[pattern["type"]].append(pattern)

        # Train ML models if we have enough data
        if len(self.successful_exploits) >= 10 and HAS_ML:
            self._train_attack_predictor()

        return learned_patterns

    def _identify_attack_sequence_patterns(self) -> Optional[Dict]:
        """Identify successful attack sequences."""
        successes = self.current_session["successes"]

        # Look for sequences of attacks that led to success
        sequence = []
        for attack in successes:
            sequence.append({
                "type": attack["attack_type"],
                "target": attack["target"],
                "timing_range": (
                    attack["timing_ns"] * 0.9,
                    attack["timing_ns"] * 1.1
                )
            })

        if len(sequence) >= 2:
            return {
                "sequence": sequence,
                "success_count": 1
            }

        return None

    def _identify_timing_patterns(self) -> List[Dict]:
        """Identify timing-based vulnerability patterns."""
        patterns = []

        # Group by attack type and analyze timing
        timing_by_type = defaultdict(list)
        for attempt in self.current_session["attempts"]:
            timing_by_type[attempt["attack_type"]].append({
                "timing": attempt["timing_ns"],
                "success": attempt["success"]
            })

        for attack_type, timings in timing_by_type.items():
            if len(timings) < 5:
                continue

            # Separate successful and failed timings
            success_timings = [t["timing"] for t in timings if t["success"]]
            failed_timings = [t["timing"] for t in timings if not t["success"]]

            if success_timings and failed_timings:
                avg_success = np.mean(success_timings)
                avg_failed = np.mean(failed_timings)

                # If there's a significant difference, it's a pattern
                if abs(avg_success - avg_failed) > avg_success * 0.2:
                    patterns.append({
                        "type": "timing_differential",
                        "attack_type": attack_type,
                        "success_timing_avg": int(avg_success),
                        "failed_timing_avg": int(avg_failed),
                        "differential": abs(avg_success - avg_failed),
                        "confidence": 0.85
                    })

        return patterns

    def _identify_parameter_patterns(self) -> List[Dict]:
        """Identify parameter combinations that work."""
        patterns = []

        # Analyze successful parameter combinations
        for success in self.current_session["successes"]:
            params = success["parameters"]

            # Hash parameters for pattern matching
            param_sig = hashlib.md5(
                json.dumps(params, sort_keys=True).encode()
            ).hexdigest()[:16]

            patterns.append({
                "type": "parameter_combination",
                "attack_type": success["attack_type"],
                "target": success["target"],
                "parameters": params,
                "signature": param_sig,
                "confidence": 0.75
            })

        return patterns

    def _identify_response_patterns(self) -> List[Dict]:
        """Identify response patterns that indicate vulnerability."""
        patterns = []

        # Analyze response status words
        sw_success = Counter()
        sw_failed = Counter()

        for attempt in self.current_session["attempts"]:
            sw = f"{attempt['response_sw'][0]:02X}{attempt['response_sw'][1]:02X}"
            if attempt["success"]:
                sw_success[sw] += 1
            else:
                sw_failed[sw] += 1

        # Find status words that strongly correlate with success
        for sw, count in sw_success.items():
            if count >= 3 and sw not in sw_failed:
                patterns.append({
                    "type": "response_indicator",
                    "status_word": sw,
                    "indicates": "vulnerability",
                    "observed_count": count,
                    "confidence": 0.8
                })

        return patterns

    def _train_attack_predictor(self):
        """Train ML model to predict attack success."""
        if not HAS_ML:
            return

        # Prepare training data
        X = []
        y = []

        all_attempts = self.successful_exploits + self.failed_attempts[-100:]

        for attempt in all_attempts:
            # Feature vector
            features = [
                hash(attempt["attack_type"]) % 1000,
                hash(attempt["target"]) % 1000,
                attempt["timing_ns"] / 1e9,  # Convert to seconds
                attempt["response_sw"][0],
                attempt["response_sw"][1],
                len(attempt["response_data"]) if attempt["response_data"] else 0
            ]
            X.append(features)
            y.append(1 if attempt["success"] else 0)

        if len(X) < 10:
            return

        # Train model
        X_scaled = self.scaler.fit_transform(X)
        self.attack_classifier = RandomForestClassifier(n_estimators=50, random_state=42)
        self.attack_classifier.fit(X_scaled, y)

        print(f"[AI] Attack predictor trained on {len(X)} samples")

    def predict_attack_success(self, attack_type: str, target: str,
                               timing_estimate: int) -> Tuple[bool, float]:
        """
        Predict whether an attack will succeed.

        Args:
            attack_type: Type of attack
            target: Attack target
            timing_estimate: Estimated timing in nanoseconds

        Returns:
            (prediction, confidence): Whether attack will succeed and confidence
        """
        if not self.attack_classifier or not HAS_ML:
            return (False, 0.0)

        features = [
            hash(attack_type) % 1000,
            hash(target) % 1000,
            timing_estimate / 1e9,
            0, 0, 0  # Placeholders for response data
        ]

        X = self.scaler.transform([features])
        prediction = self.attack_classifier.predict(X)[0]
        confidence = self.attack_classifier.predict_proba(X)[0][prediction]

        return (bool(prediction), float(confidence))

    def get_recommended_attacks(self, card_atr: str, limit: int = 5) -> List[Dict]:
        """
        Get recommended attacks based on learned patterns.

        Args:
            card_atr: Card ATR
            limit: Maximum number of recommendations

        Returns:
            recommendations: List of recommended attacks with rationale
        """
        recommendations = []

        # Check if we've seen this card before
        card_hash = hashlib.md5(card_atr.encode()).hexdigest()

        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT successful_attacks, vulnerability_profile
            FROM card_signatures
            WHERE card_hash = ?
        ''', (card_hash,))

        result = cursor.fetchone()

        if result:
            # We've seen this card before
            successful_attacks = json.loads(result[0]) if result[0] else []

            for attack in successful_attacks[:limit]:
                recommendations.append({
                    "attack_type": attack["type"],
                    "target": attack["target"],
                    "rationale": "Previously successful on this card type",
                    "confidence": 0.9
                })
        else:
            # New card - recommend based on general patterns
            cursor.execute('''
                SELECT pattern_type, pattern_signature, confidence, description
                FROM knowledge_patterns
                WHERE success_count > failure_count
                ORDER BY confidence DESC
                LIMIT ?
            ''', (limit,))

            for row in cursor.fetchall():
                pattern = json.loads(row[1])
                recommendations.append({
                    "attack_type": pattern.get("attack_type", "unknown"),
                    "target": pattern.get("target", "general"),
                    "rationale": row[3] or "High success rate in previous sessions",
                    "confidence": row[2]
                })

        return recommendations

    def profile_merchant(self, merchant_id: str, test_results: List[Dict]):
        """
        Profile merchant based on test results.

        Args:
            merchant_id: Merchant identifier
            test_results: Results from merchant tests
        """
        vulnerability_score = 0.0
        behaviors = []

        for result in test_results:
            if result.get("vulnerability_detected"):
                vulnerability_score += result.get("severity", 0.5)
            behaviors.append(result.get("behavior", "normal"))

        vulnerability_score = min(vulnerability_score / len(test_results), 1.0) if test_results else 0.0

        # Store profile
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO merchant_profiles
            (merchant_id, merchant_name, observed_behaviors, vulnerability_score, 
             test_results, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            merchant_id,
            test_results[0].get("merchant_name", "Unknown") if test_results else "Unknown",
            json.dumps(behaviors),
            vulnerability_score,
            json.dumps(test_results),
            datetime.now().isoformat()
        ))
        self.conn.commit()

        print(f"[AI] Merchant profiled: {merchant_id}")
        print(f"[AI] Vulnerability score: {vulnerability_score:.2f}")

    def _store_pattern(self, pattern: Dict):
        """Store learned pattern in database."""
        cursor = self.conn.cursor()

        pattern_sig = json.dumps(pattern, sort_keys=True)
        pattern_hash = hashlib.md5(pattern_sig.encode()).hexdigest()

        cursor.execute('''
            INSERT OR IGNORE INTO knowledge_patterns
            (pattern_type, pattern_signature, success_count, confidence, 
             description, created_at, last_used)
            VALUES (?, ?, 1, ?, ?, ?, ?)
        ''', (
            pattern["type"],
            pattern_sig,
            pattern.get("confidence", 0.5),
            pattern.get("description", f"{pattern['type']} pattern"),
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        self.conn.commit()

    def _save_knowledge(self):
        """Save knowledge caches to disk."""
        knowledge_file = self.kb_dir / "knowledge_cache.pkl"

        knowledge = {
            "attack_patterns": dict(self.attack_patterns),
            "merchant_profiles": self.merchant_profiles,
            "card_signatures": self.card_signatures,
            "successful_exploits": self.successful_exploits[-100:],
            "failed_attempts": self.failed_attempts[-100:]
        }

        with open(knowledge_file, 'wb') as f:
            pickle.dump(knowledge, f)

        # Save ML models if trained
        if self.attack_classifier and HAS_ML:
            model_file = self.kb_dir / "attack_predictor.pkl"
            with open(model_file, 'wb') as f:
                pickle.dump({
                    "classifier": self.attack_classifier,
                    "scaler": self.scaler
                }, f)

    def _load_knowledge(self):
        """Load existing knowledge from disk."""
        knowledge_file = self.kb_dir / "knowledge_cache.pkl"

        if knowledge_file.exists():
            try:
                with open(knowledge_file, 'rb') as f:
                    knowledge = pickle.load(f)

                self.attack_patterns = defaultdict(list, knowledge.get("attack_patterns", {}))
                self.merchant_profiles = knowledge.get("merchant_profiles", {})
                self.card_signatures = knowledge.get("card_signatures", {})
                self.successful_exploits = knowledge.get("successful_exploits", [])
                self.failed_attempts = knowledge.get("failed_attempts", [])

                print(f"[AI] Loaded existing knowledge base")
            except Exception as e:
                print(f"[AI] Warning: Could not load knowledge: {e}")

        # Load ML models
        model_file = self.kb_dir / "attack_predictor.pkl"
        if model_file.exists() and HAS_ML:
            try:
                with open(model_file, 'rb') as f:
                    models = pickle.load(f)
                self.attack_classifier = models["classifier"]
                self.scaler = models["scaler"]
                print(f"[AI] Loaded ML models")
            except Exception as e:
                print(f"[AI] Warning: Could not load ML models: {e}")

    def _calculate_duration(self, start: str, end: str) -> str:
        """Calculate duration between two ISO timestamps."""
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end)
        delta = end_dt - start_dt

        minutes = delta.seconds // 60
        seconds = delta.seconds % 60

        return f"{minutes}m {seconds}s"

    def get_statistics(self) -> Dict:
        """Get overall learning statistics."""
        cursor = self.conn.cursor()

        # Total sessions
        cursor.execute('SELECT COUNT(*) FROM scan_sessions')
        total_sessions = cursor.fetchone()[0]

        # Total attacks
        cursor.execute('SELECT COUNT(*) FROM attack_attempts')
        total_attacks = cursor.fetchone()[0]

        # Success rate
        cursor.execute('SELECT AVG(success_rate) FROM scan_sessions WHERE success_rate IS NOT NULL')
        avg_success_rate = cursor.fetchone()[0] or 0.0

        # Patterns learned
        cursor.execute('SELECT COUNT(*) FROM knowledge_patterns')
        patterns_learned = cursor.fetchone()[0]

        # Most successful attack type
        cursor.execute('''
            SELECT attack_type, COUNT(*) as count
            FROM attack_attempts
            WHERE success = 1
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 1
        ''')
        result = cursor.fetchone()
        most_successful_attack = result[0] if result else "None"

        return {
            "total_sessions": total_sessions,
            "total_attacks": total_attacks,
            "average_success_rate": f"{avg_success_rate:.1f}%",
            "patterns_learned": patterns_learned,
            "most_successful_attack": most_successful_attack,
            "ml_model_trained": self.attack_classifier is not None
        }

    def print_summary(self):
        """Print learning system summary."""
        stats = self.get_statistics()

        print("\n" + "=" * 60)
        print("AI LEARNING SYSTEM SUMMARY")
        print("=" * 60)
        print(f"Total Sessions:        {stats['total_sessions']}")
        print(f"Total Attacks:         {stats['total_attacks']}")
        print(f"Average Success Rate:  {stats['average_success_rate']}")
        print(f"Patterns Learned:      {stats['patterns_learned']}")
        print(f"Most Successful:       {stats['most_successful_attack']}")
        print(f"ML Model:              {'✅ Trained' if stats['ml_model_trained'] else '❌ Not trained'}")
        print("=" * 60 + "\n")

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="AI Learning System - View learning statistics and knowledge base"
    )
    parser.add_argument("--stats", action="store_true", help="Show learning statistics")
    parser.add_argument("--recommend", type=str, help="Get attack recommendations for ATR")
    parser.add_argument("--knowledge-dir", type=str, default="ai_knowledge_base",
                        help="Knowledge base directory")

    args = parser.parse_args()

    # Initialize system
    ai = AILearningSystem(knowledge_base_dir=args.knowledge_dir)

    if args.stats:
        ai.print_summary()

    if args.recommend:
        recommendations = ai.get_recommended_attacks(args.recommend)
        print(f"\nRecommended attacks for ATR: {args.recommend}")
        print("=" * 60)
        for i, rec in enumerate(recommendations, 1):
            print(f"\n{i}. {rec['attack_type']} → {rec['target']}")
            print(f"   Rationale: {rec['rationale']}")
            print(f"   Confidence: {rec['confidence']:.0%}")

    ai.close()


if __name__ == "__main__":
    main()
