from __future__ import annotations

from core.ai_vuln_testing import run_ai_vuln_session
from core.emv_kernel_registry import build_kernel_seed_corpus, infer_kernel_from_aid, infer_kernel_from_scheme


def test_scheme_to_kernel_mapping_uses_public_profiles() -> None:
    assert infer_kernel_from_scheme("visa").kernel_id == 3
    assert infer_kernel_from_scheme("mastercard").kernel_id == 2
    assert infer_kernel_from_scheme("discover").kernel_id == 6
    assert infer_kernel_from_scheme("generic").kernel_id == 8


def test_aid_to_kernel_mapping_prefers_matching_rid() -> None:
    assert infer_kernel_from_aid("A0000000031010").kernel_id == 3
    assert infer_kernel_from_aid("A0000000041010").kernel_id == 2
    assert infer_kernel_from_aid("A0000000250000").kernel_id == 4


def test_kernel_seed_corpus_is_scheme_focused() -> None:
    seeds = build_kernel_seed_corpus(3)
    assert seeds[0] == "00A4040007A0000000031010"
    assert "80A80000028300" in seeds


def test_ai_vuln_session_reports_kernel_profile() -> None:
    result = run_ai_vuln_session(iterations=3, kernel=3, random_seed=1)
    assert result["meta"]["params"]["kernel_profile"]["kernel_id"] == 3
    assert result["meta"]["params"]["seed_count"] >= 3
