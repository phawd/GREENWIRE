#!/usr/bin/env python3
"""Quick audit for GREENWIRE Java static dependencies.

Ensures we can build CAP files without downloading external artifacts at build
time by verifying that mandatory jars are present inside the repository.
"""
from __future__ import annotations

import shutil
from pathlib import Path
import sys


REQUIRED_ITEMS = [
    ("lib/GlobalPlatformPro.jar", "GlobalPlatformPro jar (martinpaljak releases)"),
    ("static/java/gp.jar", "GlobalPlatformPro lightweight gp.jar"),
    ("static/java/ant-javacard.jar", "ant-javacard build helper"),
]

OPTIONAL_ITEMS = [
    ("sdk/javacard/lib/api_classic-3.0.5.jar", "JavaCard API 3.0.5 (Oracle/Thales SDK)"),
    ("sdk/javacard/lib/tools.jar", "JavaCard converter tools.jar (SDK)"),
]


def status(path: Path) -> str:
    return "✅" if path.exists() else "❌"


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    print(f"📦 GREENWIRE static Java audit\nRoot: {root}\n")

    ok = True
    print("Mandatory items:")
    for rel, hint in REQUIRED_ITEMS:
        p = root / rel
        good = p.exists()
        print(f"  {status(p)} {rel}")
        if not good:
            ok = False
            print(f"     → missing: {hint}")

    print("\nOptional (recommended for full offline cap conversion):")
    for rel, hint in OPTIONAL_ITEMS:
        p = root / rel
        print(f"  {status(p)} {rel}")
        if not p.exists():
            print(f"     → suggestion: {hint}")

    print()
    java = shutil.which("java")
    print(f"java in PATH: {java if java else '❌ not found'}")

    if ok:
        print("\n✅ Static Java toolchain looks ready.")
        return 0
    print("\n⚠️  Static Java toolchain incomplete. Populate missing files and rerun.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
