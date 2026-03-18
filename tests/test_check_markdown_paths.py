from __future__ import annotations

from pathlib import Path

from tools.check_markdown_paths import main


def test_checker_accepts_valid_markdown_links_and_static_paths(tmp_path: Path) -> None:
    docs_dir = tmp_path / "docs"
    static_dir = tmp_path / "static" / "lib"
    docs_dir.mkdir(parents=True)
    static_dir.mkdir(parents=True)

    (tmp_path / "README.md").write_text("[Guide](docs/guide.md)\n`static/lib/helper.py`\n")
    (docs_dir / "guide.md").write_text("[Home](../README.md)\n")
    (static_dir / "helper.py").write_text("# stub\n")

    assert main(["--root", str(tmp_path)]) == 0


def test_checker_reports_broken_markdown_links(tmp_path: Path, capsys) -> None:
    (tmp_path / "README.md").write_text("[Guide](docs/missing.md)\n")

    assert main(["--root", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "broken link" in captured.out


def test_checker_reports_missing_static_refs(tmp_path: Path, capsys) -> None:
    (tmp_path / "README.md").write_text("Use `static/lib/helper.py` for fallback imports.\n")

    assert main(["--root", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "missing static path" in captured.out
