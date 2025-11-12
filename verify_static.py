#!/usr/bin/env python3
"""Verify GREENWIRE static build completeness."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from tools.static_distribution import StaticDistribution


def _print_section(title: str) -> None:
    print(title)
    print("-" * len(title))


def _render_issues(label: str, issues: list[dict[str, str]]) -> int:
    if not issues:
        print(f"[OK] {label}")
        return 0

    print(f"[ERROR] {label}:")
    for entry in issues:
        path = entry.get("path", "<unknown>")
        instructions = entry.get("instructions")
        print(f"  - {entry.get('name', path)} :: {path}")
        if instructions:
            print(f"      -> {instructions}")
    return len(issues)


def main() -> int:
    print("GREENWIRE Static Build Verification")
    print("=" * 40)

    dist = StaticDistribution(Path.cwd())
    report = dist.generate_report()

    issue_total = 0

    _print_section("Directory structure")
    issue_total += _render_issues("Required directories", report["directory_issues"])
    print()

    _print_section("Python module mirror")
    issue_total += _render_issues("Mirrored modules", report["python_missing"])
    print()

    _print_section("Java static artefacts")
    issue_total += _render_issues("Java dependencies", report["java_missing"])
    print()

    _print_section("CAP source health")
    cap_issues = report["cap_issues"]
    if cap_issues:
        print("[WARNING] CAP source anomalies detected:")
        for entry in cap_issues:
            print(f"  - {entry['name']} :: {entry['path']}")
            print(f"      -> {entry.get('instructions', 'Review source implementation')}")
    else:
        print("[OK] CAP sources expose install/process hooks and INS metadata")

    print()
    _print_section("CAP feature summary")
    print(json.dumps(report["cap_metadata"], indent=2))

    if issue_total == 0:
        print("\n[SUCCESS] GREENWIRE static artefacts located. Run build_static.bat or your Linux equivalent to assemble the offline bundle.")
        return 0

    print(
        f"\n[WARNING] {issue_total} blocking issue(s) detected. Run `python -m tools.static_distribution check` after addressing the notes above."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())