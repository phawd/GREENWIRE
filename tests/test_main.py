"""Tests for the greenwire package."""

import importlib

import pytest


def test_version_string():
    """The package exposes a non-empty version string."""
    import greenwire

    assert isinstance(greenwire.__version__, str)
    assert greenwire.__version__


def test_run_prints(capsys):
    """run() prints the expected banner."""
    from greenwire.main import run

    run()
    captured = capsys.readouterr()
    assert "GREENWIRE" in captured.out


def test_package_importable():
    """The greenwire package can be imported without errors."""
    mod = importlib.import_module("greenwire")
    assert mod is not None
