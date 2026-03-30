from __future__ import annotations

from modules.ai_test_generator import AITestGenerator
from modules.merchant_test_library import TestCategory, TestSeverity


def test_capability_filter_keeps_only_compatible_tests(tmp_path) -> None:
    generator = AITestGenerator(db_path=str(tmp_path / "learning.db"), random_seed=7)

    tests = [
        {"test_id": "T1", "name": "generic", "severity": TestSeverity.LOW, "category": TestCategory.PROTOCOL_COMPLIANCE},
        {
            "test_id": "T2",
            "name": "contactless only",
            "severity": TestSeverity.HIGH,
            "category": TestCategory.INTERFACE_SECURITY,
            "required_capabilities": {"contactless": True},
        },
        {
            "test_id": "T3",
            "name": "biometric only",
            "severity": TestSeverity.HIGH,
            "category": TestCategory.RISK_MANAGEMENT,
            "required_capabilities": {"biometric": True},
        },
    ]

    compatible = generator._filter_by_capabilities(tests, {"contactless": True})

    assert [item["test_id"] for item in compatible] == ["T1", "T2"]


def test_rule_based_priority_is_reproducible_with_seed(tmp_path) -> None:
    merchant_profile = {
        "merchant_type": "POS",
        "terminal_capabilities": {"contact": True, "contactless": True},
        "vulnerability_count": 2,
        "risk_score": 0.5,
    }
    card_capabilities = {"contact": True, "contactless": True}
    test = {
        "test_id": "T001",
        "name": "PIN Cryptogram Validation",
        "severity": TestSeverity.HIGH,
        "category": TestCategory.CRYPTOGRAPHIC,
    }

    generator_a = AITestGenerator(db_path=str(tmp_path / "a.db"), random_seed=123)
    generator_b = AITestGenerator(db_path=str(tmp_path / "b.db"), random_seed=123)

    priority_a = generator_a._calculate_rule_based_priority(test, merchant_profile, card_capabilities, None)
    priority_b = generator_b._calculate_rule_based_priority(test, merchant_profile, card_capabilities, None)

    assert priority_a == priority_b
    assert 0.0 <= priority_a <= 100.0
