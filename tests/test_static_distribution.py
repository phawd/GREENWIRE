"""Unit tests for the static distribution helper."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.static_distribution import CapMetadata, StaticDistribution


def _write_dummy_module(root: Path, relative_path: str, content: str = "# stub\n") -> None:
    module_path = root / relative_path
    module_path.parent.mkdir(parents=True, exist_ok=True)
    module_path.write_text(content)


def test_prepare_python_bundle(tmp_path: Path) -> None:
    _write_dummy_module(tmp_path, "modules/android_nfc.py")
    _write_dummy_module(tmp_path, "modules/emulation.py")
    _write_dummy_module(tmp_path, "modules/greenwire_crypto_fuzzer.py")
    _write_dummy_module(tmp_path, "modules/greenwire_emv_compliance.py")
    _write_dummy_module(tmp_path, "hsm/thales_emulator.py")

    dist = StaticDistribution(tmp_path)

    # Initially the mirror is empty and should be reported as missing.
    python_missing = dist.check_python_bundle()
    assert {issue.name for issue in python_missing} == {
        "android_nfc.py",
        "emulation.py",
        "greenwire_crypto_fuzzer.py",
        "greenwire_emv_compliance.py",
        "thales_emulator.py",
    }

    dist.prepare_python_bundle()

    # After mirroring nothing should be missing.
    python_missing_after = dist.check_python_bundle()
    assert python_missing_after == []

    for filename in (
        "android_nfc.py",
        "emulation.py",
        "greenwire_crypto_fuzzer.py",
        "greenwire_emv_compliance.py",
        "thales_emulator.py",
        "__init__.py",
    ):
        assert (tmp_path / "static" / "lib" / filename).exists()


def test_generate_report_includes_cap_metadata(tmp_path: Path) -> None:
    _write_dummy_module(tmp_path, "modules/android_nfc.py")
    _write_dummy_module(tmp_path, "modules/emulation.py")
    _write_dummy_module(tmp_path, "modules/greenwire_crypto_fuzzer.py")
    _write_dummy_module(tmp_path, "modules/greenwire_emv_compliance.py")
    _write_dummy_module(tmp_path, "hsm/thales_emulator.py")

    cap_root = tmp_path / "javacard" / "applet" / "src"
    cap_root.mkdir(parents=True)
    sample_cap = cap_root / "SampleApplet.java"
    sample_cap.write_text(
        "package com.sample;\n"
        "import javacard.framework.*;\n"
        "public class SampleApplet extends Applet {\n"
        "  private static final byte INS_TEST = (byte) 0x01;\n"
        "  public static void install(byte[] b, short o, byte l) { new SampleApplet().register(); }\n"
        "  public void process(APDU apdu) throws ISOException { }\n"
        "}\n"
    )

    dist = StaticDistribution(tmp_path)
    dist.prepare_python_bundle()

    report = dist.generate_report()
    assert report["python_missing"] == []
    assert any(entry["class_name"] == "SampleApplet" for entry in report["cap_metadata"])


def test_cap_metadata_parser_flags_missing_sections(tmp_path: Path) -> None:
    cap_file = tmp_path / "Stub.java"
    cap_file.write_text("public class Stub extends Applet { }\n")

    metadata = CapMetadata.from_source(cap_file)
    assert "process() implementation not found" in metadata.notes
    assert "install() method not present" in metadata.notes
    assert "No INS constants detected" in metadata.notes


def test_cli_check_reports_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_dummy_module(tmp_path, "modules/android_nfc.py")
    _write_dummy_module(tmp_path, "modules/emulation.py")
    _write_dummy_module(tmp_path, "modules/greenwire_crypto_fuzzer.py")
    _write_dummy_module(tmp_path, "modules/greenwire_emv_compliance.py")
    _write_dummy_module(tmp_path, "hsm/thales_emulator.py")

    dist = StaticDistribution(tmp_path)
    dist.prepare_python_bundle()

    # Manually invoke the CLI helper
    exit_code = StaticDistribution(tmp_path).generate_report()
    assert isinstance(exit_code, dict)

    # Use the CLI to print JSON and confirm it is parseable.
    from tools.static_distribution import main as static_main

    cli_exit = static_main(["--root", str(tmp_path), "check"])
    captured = capsys.readouterr()
    assert cli_exit != 0  # Java artefacts are intentionally missing
    json.loads(captured.out)


def test_inventory_command_writes_markdown(tmp_path: Path) -> None:
    _write_dummy_module(tmp_path, "modules/android_nfc.py")
    _write_dummy_module(tmp_path, "modules/emulation.py")
    _write_dummy_module(tmp_path, "modules/greenwire_crypto_fuzzer.py")
    _write_dummy_module(tmp_path, "modules/greenwire_emv_compliance.py")
    _write_dummy_module(tmp_path, "hsm/thales_emulator.py")

    dist = StaticDistribution(tmp_path)
    dist.prepare_python_bundle()

    inventory = dist.build_inventory()
    assert any(entry["path"].endswith("thales_emulator.py") for entry in inventory)

    markdown = dist.render_inventory_markdown(inventory)
    assert "| static/lib/thales_emulator.py" in markdown

    output_path = tmp_path / "inventory.md"
    from tools.static_distribution import main as static_main

    exit_code = static_main(
        ["--root", str(tmp_path), "inventory", "--output", str(output_path)]
    )
    assert exit_code == 0
    assert output_path.exists()
