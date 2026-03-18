from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def test_greenwire_legacy_version_flag_smoke() -> None:
    result = _run("greenwire.py", "--version")
    assert result.returncode == 0
    assert "GREENWIRE" in result.stdout


def test_greenwire_modern_list_commands_smoke() -> None:
    result = _run("greenwire_modern.py", "list", "commands")
    assert result.returncode == 0
    assert "Found" in result.stdout


def test_greenwire_modern_gp_session_profiles_smoke() -> None:
    result = _run("greenwire_modern.py", "gp-test-session", "profiles", "--format", "json")
    assert result.returncode == 0
    assert '"profiles"' in result.stdout


def test_greenwire_modern_wireless_kernel_examples_smoke() -> None:
    result = _run("greenwire_modern.py", "wireless-kernel", "examples", "--format", "json")
    assert result.returncode == 0
    assert '"examples"' in result.stdout


def test_greenwire_modern_mutant_card_dry_run_smoke() -> None:
    result = _run("greenwire_modern.py", "mutant-card", "create", "--dry-run", "--format", "json")
    assert result.returncode == 0
    assert '"mutation_profile"' in result.stdout


def test_greenwire_modern_card_issue_smoke() -> None:
    result = _run(
        "greenwire_modern.py",
        "card-issue",
        "--",
        "--pan",
        "4111111111111111",
        "--timeout",
        "10",
        "--format",
        "json",
        timeout=120,
    )
    assert result.returncode == 0
    assert '"Card issued and transaction completed"' in result.stdout


def test_verify_java_static_setup_smoke() -> None:
    result = _run("tools/verify_java_static_setup.py")
    assert result.returncode == 0
    assert "static Java audit" in result.stdout


def test_emv_nfc_verify_json_smoke() -> None:
    result = _run("emv_nfc_verify.py", "--json")
    assert result.returncode == 0
    assert '"nfc_available"' in result.stdout


def test_repo_consistency_audit_smoke() -> None:
    result = _run("tools/review_repo_consistency.py")
    assert result.returncode == 0
    assert "[audit] markdown=" in result.stdout


def test_full_distribution_audit_smoke() -> None:
    result = _run("tools/full_distribution_audit.py", timeout=180)
    assert result.returncode == 0
    assert "[full-audit] docs=" in result.stdout
