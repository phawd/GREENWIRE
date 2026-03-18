from __future__ import annotations

from pathlib import Path

from core.pan_registry import acquire_unique_pan, is_registered, register_pan


def test_register_pan_and_detect_registration(tmp_path: Path) -> None:
    registry = tmp_path / "pans.json"
    assert is_registered("4003123412341234", path=registry) is False
    assert register_pan("4003123412341234", source="unit-test", path=registry) is True
    assert is_registered("4003123412341234", path=registry) is True
    assert register_pan("4003123412341234", source="unit-test", path=registry) is False
    assert register_pan("4003123412341234", source="unit-test", allow_existing=True, path=registry) is True


def test_acquire_unique_pan_skips_existing_values(tmp_path: Path) -> None:
    registry = tmp_path / "pans.json"
    register_pan("4003123412341234", source="setup", path=registry)
    sequence = iter(["4003123412341234", "4118421099999993"])
    pan = acquire_unique_pan(lambda: next(sequence), source="unit-test", reserve=True, path=registry)
    assert pan == "4118421099999993"
    assert is_registered("4118421099999993", path=registry) is True
