#!/usr/bin/env python3
"""Validate local Markdown links and static file references."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
STATIC_REF_RE = re.compile(r"(?<![A-Za-z0-9_./-])(static/[A-Za-z0-9_./-]+)")
URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
IGNORED_MARKDOWN_FILES = {"STATIC_DISTRIBUTION_INVENTORY.md"}


def _iter_markdown_files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*.md") if path.name not in IGNORED_MARKDOWN_FILES
    )


def _is_ignored_relative_target(target: str) -> bool:
    return (
        not target
        or target.startswith("#")
        or URL_RE.match(target) is not None
        or target.startswith("mailto:")
    )


def _check_markdown_links(root: Path) -> list[str]:
    issues: list[str] = []
    for markdown_file in _iter_markdown_files(root):
        text = markdown_file.read_text(encoding="utf-8", errors="ignore")
        for match in MARKDOWN_LINK_RE.finditer(text):
            raw_target = match.group(1).strip()
            if _is_ignored_relative_target(raw_target):
                continue
            target = raw_target.split("#", 1)[0].strip()
            if not target:
                continue
            resolved = (markdown_file.parent / target).resolve()
            if not resolved.exists():
                rel_file = markdown_file.relative_to(root).as_posix()
                issues.append(f"{rel_file}: broken link -> {raw_target}")
    return issues


def _check_static_refs(root: Path) -> list[str]:
    issues: list[str] = []
    for markdown_file in _iter_markdown_files(root):
        text = markdown_file.read_text(encoding="utf-8", errors="ignore")
        for match in STATIC_REF_RE.finditer(text):
            target = match.group(1).rstrip("`.,:;)]")
            resolved = root / Path(target)
            if not resolved.exists():
                rel_file = markdown_file.relative_to(root).as_posix()
                issues.append(f"{rel_file}: missing static path -> {target}")
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check Markdown local links and static/ path references."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root to scan.",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    issues = _check_markdown_links(root)
    issues.extend(_check_static_refs(root))

    if issues:
        for issue in issues:
            print(issue)
        print(f"\nFound {len(issues)} Markdown path issue(s).")
        return 1

    print("Markdown path checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
