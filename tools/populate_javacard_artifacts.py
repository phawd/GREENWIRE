#!/usr/bin/env python3
"""
Helper: populate GREENWIRE with JavaCard SDK artifacts (Nexa-only static copy).

What it does:
 - Searches the repository for candidate JavaCard SDK artifacts:
   * tools.jar (JavaCard converter runtime)
   * api_export_files (directories containing .exp files)
   * GlobalPlatformPro.jar (GPPro fat jar used for deploy)
 - Picks sensible defaults (prefers oracle_javacard_sdks and larger files)
 - Optionally copies the selected candidates into the GREENWIRE expected
   locations so Gradle tasks (convertCap/deployCap) can run offline:
     GREENWIRE/sdk/javacard/lib/tools.jar
     GREENWIRE/sdk/javacard/api_export_files/*
     GREENWIRE/lib/GlobalPlatformPro.jar

Usage:
  python populate_javacard_artifacts.py         # dry-run; prints choices
  python populate_javacard_artifacts.py --apply --yes

Notes:
 - This script assumes it is located at GREENWIRE/tools/. It will locate the
   repository root by going up two directories from its location.
 - It will not overwrite existing files unless --backup is provided (default
   behavior is to create a .bak timestamped backup of replaced files).
 - Only use --apply when you are comfortable copying vendor artifacts into
   this repo for Nexa-only internal distribution (check licensing!).
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
import sys
import time


def find_tools_jar_candidates(root: Path):
    candidates = list(root.glob('**/lib/tools.jar'))
    # Exclude the GREENWIRE target path if already present
    candidates = [p for p in candidates if 'GREENWIRE/sdk/javacard/lib' not in str(p).replace('\\','/')]
    return candidates


def find_export_dir_candidates(root: Path):
    candidates = []
    for pattern in ('**/api_export_files*', '**/export*', '**/exp*'):
        for p in root.glob(pattern):
            if p.is_dir():
                # check for any .exp files inside
                if any(p.rglob('*.exp')):
                    candidates.append(p)
    # Deduplicate
    uniq = []
    for p in candidates:
        if p not in uniq:
            uniq.append(p)
    return uniq


def find_gppro_candidates(root: Path):
    candidates = list(root.glob('**/GlobalPlatformPro.jar'))
    # Also look for gp.jar variants
    candidates += list(root.glob('**/gp.jar'))
    # Deduplicate
    return list({p.resolve(): p for p in candidates}.values())


def score_tools_candidate(path: Path):
    s = 0
    txt = str(path).lower()
    if 'oracle_javacard_sdks' in txt or 'javacard_sdks' in txt:
        s += 10000
    # prefer jc[0-9] appearances
    import re
    m = re.search(r'jc(\d+)', txt)
    if m:
        try:
            s += int(m.group(1)) * 10
        except Exception:
            pass
    try:
        s += path.stat().st_size // 1024
    except Exception:
        pass
    return s


def pick_best_tools(candidates):
    if not candidates:
        return None
    candidates = sorted(candidates, key=score_tools_candidate, reverse=True)
    return candidates[0]


def pick_export_dir_for_tools(export_dirs, tools_path: Path | None):
    if not export_dirs:
        return None
    if tools_path:
        # prefer export dirs under same SDK tree
        ttxt = str(tools_path)
        for d in export_dirs:
            if ttxt in str(d):
                return d
    # fallback to largest export dir (most .exp files)
    def count_exps(p: Path):
        return sum(1 for _ in p.rglob('*.exp'))
    export_dirs = sorted(export_dirs, key=count_exps, reverse=True)
    return export_dirs[0]


def pick_best_gppro(candidates):
    if not candidates:
        return None
    # prefer repository-local repo2/GlobalPlatformPro builds if present
    for c in candidates:
        if 'repo2' in str(c) or 'globalplatformpro' in str(c).lower():
            return c
    # else largest file
    candidates = sorted(candidates, key=lambda p: p.stat().st_size if p.exists() else 0, reverse=True)
    return candidates[0]


def backup_path(target: Path):
    ts = time.strftime('%Y%m%d_%H%M%S')
    return target.with_name(target.name + '.bak.' + ts)


def copy_tools(tools_src: Path, dest_lib_dir: Path, apply: bool, backup: bool):
    dest_lib_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_lib_dir / 'tools.jar'
    print(f"-> target: {dest}")
    if not apply:
        print(f"DRY RUN: would copy {tools_src} -> {dest}")
        return
    if dest.exists():
        if backup:
            b = backup_path(dest)
            print(f"Backing up existing {dest} -> {b}")
            shutil.copy2(dest, b)
    print(f"Copying {tools_src} -> {dest}")
    shutil.copy2(tools_src, dest)


def copy_export_dir(src_dir: Path, dest_api_dir: Path, apply: bool, backup: bool):
    dest_api_dir_parent = dest_api_dir.parent
    dest_api_dir_parent.mkdir(parents=True, exist_ok=True)
    if dest_api_dir.exists():
        if apply:
            if backup:
                b = backup_path(dest_api_dir)
                print(f"Backing up existing {dest_api_dir} -> {b}")
                shutil.move(str(dest_api_dir), str(b))
            else:
                print(f"Removing existing {dest_api_dir}")
                shutil.rmtree(dest_api_dir)
        else:
            print(f"DRY RUN: would replace {dest_api_dir} with {src_dir}")
            return
    print(f"Copying export dir {src_dir} -> {dest_api_dir}")
    shutil.copytree(src_dir, dest_api_dir)


def copy_gppro(src: Path, dest_lib_dir: Path, apply: bool, backup: bool):
    dest_lib_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_lib_dir / 'GlobalPlatformPro.jar'
    print(f"-> target: {dest}")
    if not apply:
        print(f"DRY RUN: would copy {src} -> {dest}")
        return
    if dest.exists():
        if backup:
            b = backup_path(dest)
            print(f"Backing up existing {dest} -> {b}")
            shutil.copy2(dest, b)
    print(f"Copying {src} -> {dest}")
    try:
        shutil.copy2(src, dest)
    except PermissionError:
        # On Windows the destination may be locked by a running process. Fall back to
        # creating a staged replacement named GlobalPlatformPro.new.jar and inform the user.
        staged = dest_lib_dir / 'GlobalPlatformPro.new.jar'
        print(f"⚠️ Could not overwrite {dest} (in use). Attempting staged copy to {staged}")
        try:
            shutil.copy2(src, staged)
            print(f"✅ Staged copy written to {staged}. Update build.gradle or restart processes to activate it.")
        except Exception as e2:
            print(f"❌ Failed to write staged copy to {staged}: {e2}")
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description='Populate GREENWIRE with JavaCard SDK artifacts from repo_other candidates')
    parser.add_argument('--apply', action='store_true', help='Perform copy operations (default: dry-run)')
    parser.add_argument('--yes', action='store_true', help='Assume yes for prompts')
    parser.add_argument('--backup', action='store_true', default=True, help='Backup replaced files (default: True)')
    args = parser.parse_args(argv)

    here = Path(__file__).resolve()
    repo_root = here.parents[2]
    print(f"Repo root: {repo_root}")

    tools_candidates = find_tools_jar_candidates(repo_root)
    export_candidates = find_export_dir_candidates(repo_root)
    gppro_candidates = find_gppro_candidates(repo_root)

    print(f"Found {len(tools_candidates)} tools.jar candidates, {len(export_candidates)} export dirs, {len(gppro_candidates)} GlobalPlatformPro candidates")

    tools_choice = pick_best_tools(tools_candidates)
    export_choice = pick_export_dir_for_tools(export_candidates, tools_choice)
    gppro_choice = pick_best_gppro(gppro_candidates)

    print('\nSelections (best-effort):')
    if tools_choice:
        print(' tools.jar:', tools_choice)
    else:
        print(' tools.jar: NONE FOUND')
    if export_choice:
        print(' api_export_files dir:', export_choice)
    else:
        print(' api_export_files dir: NONE FOUND')
    if gppro_choice:
        print(' GlobalPlatformPro jar:', gppro_choice)
    else:
        print(' GlobalPlatformPro jar: NONE FOUND')

    sdk_lib = repo_root / 'GREENWIRE' / 'sdk' / 'javacard' / 'lib'
    sdk_api_dir = repo_root / 'GREENWIRE' / 'sdk' / 'javacard' / 'api_export_files'
    greenwire_lib = repo_root / 'GREENWIRE' / 'lib'

    if not args.apply:
        print('\nDRY RUN mode. Re-run with --apply to perform copies.')
        print('Example: python populate_javacard_artifacts.py --apply --yes')
        return 0

    # Proceed with copying
    if tools_choice:
        copy_tools(tools_choice, sdk_lib, apply=args.apply, backup=args.backup)
    else:
        print('No tools.jar candidate found; cannot populate tools.jar')

    if export_choice:
        copy_export_dir(export_choice, sdk_api_dir, apply=args.apply, backup=args.backup)
    else:
        print('No api_export_files candidate found; convertCap may still fail')

    if gppro_choice:
        copy_gppro(gppro_choice, greenwire_lib, apply=args.apply, backup=args.backup)
    else:
        print('No GlobalPlatformPro.jar candidate found; deployCap will likely fail without GPPro')

    print('\nDone. If you used --apply, run the Gradle convert/deploy tasks locally to verify:')
    print('  cd GREENWIRE/javacard/applet')
    print('  ./gradlew convertCap')
    print('  ./gradlew deployCap')
    return 0


if __name__ == '__main__':
    sys.exit(main())
