from __future__ import annotations

from pathlib import Path

from core.globalplatform_reference import gp_jar_candidates, resolve_gp_jar


def test_gp_jar_candidates_are_repo_relative() -> None:
    root = Path("F:/repo/GREENWIRE")
    candidates = gp_jar_candidates(root)
    assert candidates[0] == root / "static" / "java" / "gp.jar"
    assert all("d:/repo/globalplatformpro" not in str(candidate).lower() for candidate in candidates)


def test_resolve_gp_jar_prefers_static_java(tmp_path: Path) -> None:
    static_gp = tmp_path / "static" / "java" / "gp.jar"
    static_gp.parent.mkdir(parents=True)
    static_gp.write_bytes(b"jar")

    lib_gp = tmp_path / "lib" / "GlobalPlatformPro.jar"
    lib_gp.parent.mkdir(parents=True)
    lib_gp.write_bytes(b"jar2")

    assert resolve_gp_jar(tmp_path) == static_gp
