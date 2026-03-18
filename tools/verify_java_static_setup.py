#!/usr/bin/env python3
"""Quick audit for GREENWIRE Java static dependencies.

Ensures we can build CAP files without downloading external artifacts at build
time by verifying that mandatory jars are present inside the repository.
"""
from __future__ import annotations  # noqa: F401

import shutil
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from core.windows_compat import configure_windows_console


REQUIRED_ITEMS = [
    ("lib/GlobalPlatformPro.jar", "GlobalPlatformPro jar (martinpaljak releases)"),
    ("static/java/gp.jar", "GlobalPlatformPro lightweight gp.jar"),
    ("static/java/ant-javacard.jar", "ant-javacard build helper"),
]

# Optional groups: at least one of the patterns in each group should exist
OPTIONAL_API_CANDIDATES = [
    "sdk/javacard/lib/api_classic-3.0.5.jar",
    "sdk/javacard/lib/api_classic.jar",
    "sdk/javacard/lib/javacard_framework.jar",
]
OPTIONAL_ITEMS = [
    (OPTIONAL_API_CANDIDATES, "JavaCard API (e.g., api_classic.jar or versioned variant)"),
    (["sdk/javacard/lib/tools.jar"], "JavaCard converter tools.jar (SDK)"),
]


def status(path: Path) -> str:
    return "✅" if path.exists() else "❌"


def main() -> int:
    configure_windows_console()
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
    for rels, hint in OPTIONAL_ITEMS:
        # rels can be a list of candidates (any satisfies)
        candidates = [root / r for r in rels]
        exists_any = any(p.exists() for p in candidates)
        if exists_any:
            # show the first that exists
            present = next(p for p in candidates if p.exists())
            print(f"  ✅ {present.relative_to(root)}")
        else:
            # show primary suggestion
            primary = candidates[0]
            print(f"  ❌ {primary.relative_to(root)}")
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
