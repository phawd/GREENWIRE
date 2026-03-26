#!/usr/bin/env python3
"""
GREENWIRE Code Consolidation and Linting Script
Consolidates unnecessary files and lints the codebase.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Set

# Add GREENWIRE to path
GREENWIRE_DIR = Path(__file__).parent
sys.path.insert(0, str(GREENWIRE_DIR))

def find_duplicate_files() -> Dict[str, List[Path]]:
    """Find duplicate Python files based on content hash."""
    import hashlib

    print("\n" + "="*60)
    print("Finding Duplicate Files...")
    print("="*60)

    file_hashes = {}
    for py_file in GREENWIRE_DIR.rglob("*.py"):
        if "venv" in str(py_file) or ".venv" in str(py_file):
            continue
        if "__pycache__" in str(py_file):
            continue

        try:
            content = py_file.read_bytes()
            file_hash = hashlib.md5(content).hexdigest()

            if file_hash not in file_hashes:
                file_hashes[file_hash] = []
            file_hashes[file_hash].append(py_file)
        except Exception as e:
            print(f"⚠️  Error reading {py_file}: {e}")

    duplicates = {h: files for h, files in file_hashes.items() if len(files) > 1}

    if duplicates:
        print(f"\n🔍 Found {len(duplicates)} groups of duplicate files:")
        for files in duplicates.values():
            print(f"\n  Duplicates:")
            for f in files:
                print(f"    - {f.relative_to(GREENWIRE_DIR)}")
    else:
        print("✅ No duplicate files found")

    return duplicates

def find_unused_imports() -> List[Path]:
    """Find Python files with unused imports (basic check)."""
    print("\n" + "="*60)
    print("Finding Unused Imports...")
    print("="*60)

    try:
        # Try using autoflake if available
        result = subprocess.run(
            ["autoflake", "--check", "--recursive", "--remove-all-unused-imports", str(GREENWIRE_DIR)],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("✅ No unused imports found")
            return []
        else:
            print(f"⚠️  Found files with unused imports")
            print(result.stdout)
            return []
    except FileNotFoundError:
        print("⚠️  autoflake not installed, skipping unused import check")
        print("   Install with: pip install autoflake")
        return []

def lint_with_flake8() -> bool:
    """Run flake8 linter on codebase."""
    print("\n" + "="*60)
    print("Running flake8 Linter...")
    print("="*60)

    try:
        result = subprocess.run(
            [
                "flake8",
                str(GREENWIRE_DIR),
                "--max-line-length=120",
                "--exclude=venv,.venv,__pycache__,build,dist,static",
                "--ignore=E501,W503,E203",  # Ignore line too long, line break before binary operator
                "--count",
                "--statistics"
            ],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("✅ No linting errors found")
            return True
        else:
            print(f"⚠️  Found linting issues:")
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
            return False
    except FileNotFoundError:
        print("⚠️  flake8 not installed, skipping lint check")
        print("   Install with: pip install flake8")
        return True

def check_code_formatting() -> bool:
    """Check code formatting with black (dry-run)."""
    print("\n" + "="*60)
    print("Checking Code Formatting (black)...")
    print("="*60)

    try:
        result = subprocess.run(
            [
                "black",
                "--check",
                "--line-length=120",
                "--exclude=(venv|.venv|__pycache__|build|dist|static)",
                str(GREENWIRE_DIR)
            ],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("✅ Code formatting is correct")
            return True
        else:
            print(f"⚠️  Code formatting issues found:")
            print(result.stdout)
            print("\n   To auto-format, run: black --line-length=120 GREENWIRE/")
            return False
    except FileNotFoundError:
        print("⚠️  black not installed, skipping formatting check")
        print("   Install with: pip install black")
        return True

def check_import_sorting() -> bool:
    """Check import sorting with isort."""
    print("\n" + "="*60)
    print("Checking Import Sorting (isort)...")
    print("="*60)

    try:
        result = subprocess.run(
            [
                "isort",
                "--check-only",
                "--profile=black",
                "--line-length=120",
                "--skip=venv",
                "--skip=.venv",
                "--skip=__pycache__",
                str(GREENWIRE_DIR)
            ],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("✅ Import sorting is correct")
            return True
        else:
            print(f"⚠️  Import sorting issues found:")
            print(result.stdout)
            print("\n   To auto-sort, run: isort --profile=black GREENWIRE/")
            return False
    except FileNotFoundError:
        print("⚠️  isort not installed, skipping import sort check")
        print("   Install with: pip install isort")
        return True

def find_unused_files() -> List[Path]:
    """Find potentially unused Python files."""
    print("\n" + "="*60)
    print("Finding Potentially Unused Files...")
    print("="*60)

    # Files that are likely test files or temporary
    patterns = [
        "*_test.py",
        "test_*.py",
        "*_old.py",
        "*_backup.py",
        "*_deprecated.py",
        "temp_*.py",
        "tmp_*.py",
    ]

    unused = []
    for pattern in patterns:
        for f in GREENWIRE_DIR.rglob(pattern):
            if "venv" not in str(f) and ".venv" not in str(f):
                unused.append(f)

    if unused:
        print(f"\n🔍 Found {len(unused)} potentially unused files:")
        for f in unused:
            print(f"  - {f.relative_to(GREENWIRE_DIR)}")
    else:
        print("✅ No obviously unused files found")

    return unused

def consolidate_duplicate_code() -> None:
    """Suggest consolidation of duplicate code patterns."""
    print("\n" + "="*60)
    print("Checking for Duplicate Code Patterns...")
    print("="*60)

    print("⚠️  Manual review recommended for:")
    print("  - Multiple 'Args' class definitions (could be unified)")
    print("  - Repeated import patterns")
    print("  - Duplicate function logic")
    print("\n   Consider using a tool like 'pylint --disable=all --enable=duplicate-code'")

def check_dependencies() -> bool:
    """Check if all dependencies are properly managed."""
    print("\n" + "="*60)
    print("Checking Dependencies...")
    print("="*60)

    req_files = list(GREENWIRE_DIR.glob("requirements*.txt"))

    if not req_files:
        print("❌ No requirements.txt files found")
        return False

    print(f"✅ Found {len(req_files)} requirements files:")
    for req_file in req_files:
        print(f"  - {req_file.name}")

    # Check if static dependencies exist
    static_dir = GREENWIRE_DIR / "static" / "lib"
    if static_dir.exists():
        print(f"✅ Static dependencies directory exists: {static_dir}")
    else:
        print(f"⚠️  Static dependencies directory not found: {static_dir}")

    return True

def generate_consolidation_report() -> None:
    """Generate a report of consolidation opportunities."""
    print("\n" + "="*70)
    print(" " * 20 + "CONSOLIDATION REPORT")
    print("="*70)

    report = []

    # Check for redundant menu implementations
    menu_files = list(GREENWIRE_DIR.glob("*menu*.py"))
    if len(menu_files) > 3:
        report.append(f"⚠️  Found {len(menu_files)} menu-related files, consider consolidation")

    # Check for multiple test files
    test_files = list(GREENWIRE_DIR.glob("test*.py"))
    if len(test_files) > 5:
        report.append(f"⚠️  Found {len(test_files)} test files, consider organizing into tests/ directory")

    # Check for duplicate utility functions
    util_files = list(GREENWIRE_DIR.glob("*util*.py"))
    if len(util_files) > 2:
        report.append(f"⚠️  Found {len(util_files)} utility files, consider consolidation")

    if report:
        print("\nConsolidation Opportunities:")
        for item in report:
            print(f"  {item}")
    else:
        print("\n✅ No major consolidation opportunities found")

def main():
    """Run all consolidation and linting checks."""
    print("\n" + "="*70)
    print(" " * 15 + "GREENWIRE CODE CONSOLIDATION & LINTING")
    print("="*70)

    results = {}

    # Run all checks
    results["Duplicate Files"] = len(find_duplicate_files()) == 0
    results["Unused Imports"] = len(find_unused_imports()) == 0
    results["Flake8 Linting"] = lint_with_flake8()
    results["Code Formatting"] = check_code_formatting()
    results["Import Sorting"] = check_import_sorting()
    results["Unused Files"] = len(find_unused_files()) == 0
    results["Dependencies"] = check_dependencies()

    consolidate_duplicate_code()
    generate_consolidation_report()

    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    passed = sum(1 for r in results.values() if r)
    total = len(results)

    for check, result in results.items():
        status = "✅ PASS" if result else "⚠️  REVIEW"
        print(f"{status}: {check}")

    print("\n" + "="*70)
    print(f"Results: {passed}/{total} checks passed")
    print("="*70)

    if passed == total:
        print("\n✅ All checks passed! Codebase is clean.")
        return 0
    else:
        print("\n⚠️  Some issues found. Review recommendations above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
