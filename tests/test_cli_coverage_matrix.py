from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Python 3.14 on Windows has a known subprocess handle inheritance bug
# (OSError: [WinError 50] The request is not supported) when using
# capture_output=True. Skip this test module on affected versions.
if sys.platform == "win32" and sys.version_info >= (3, 14):
    pytest.skip(
        "Skipping CLI coverage matrix on Python 3.14+ Windows (WinError 50 subprocess bug)",
        allow_module_level=True,
    )


def _run(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
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


def _extract_json(text: str) -> dict:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise AssertionError(f"No JSON payload found in output: {text[:200]}")
    return json.loads(text[start : end + 1])


def test_help_covers_all_registered_commands() -> None:
    listing = _run("greenwire_modern.py", "list", "commands", "--format", "json")
    assert listing.returncode == 0
    payload = _extract_json(listing.stdout)
    commands = payload["data"]["commands"]
    names = sorted({entry["name"] for entry in commands})
    assert names

    failed = []
    for name in names:
        result = _run("greenwire_modern.py", "help", name, "--format", "json")
        if result.returncode != 0:
            failed.append({"command": name, "returncode": result.returncode, "stderr": result.stderr[-300:]})
            continue
        help_payload = _extract_json(result.stdout)
        if help_payload.get("success") is not True:
            failed.append({"command": name, "message": help_payload.get("message", "")})
    assert failed == []
