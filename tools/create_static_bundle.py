"""Helper to create a minimal static bundle of GREENWIRE for offline use.

This helper copies required static shim modules from static/lib into a target
bundle directory and collects top-level resources (data/, ca_keys.json, etc.)
so a simple zip or single-folder distribution can be created for testing.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

ROOT = Path(__file__).parent.parent
STATIC_LIB = ROOT / "static" / "lib"
BUNDLE_OUT = ROOT / "dist" / "greenwire-static"


def collect_static(target: Path = BUNDLE_OUT):
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)

    # Copy static/lib shims
    lib_out = target / "static" / "lib"
    if STATIC_LIB.exists():
        shutil.copytree(STATIC_LIB, lib_out, dirs_exist_ok=True)
    else:
        lib_out.mkdir(parents=True, exist_ok=True)

    # Copy core GREENWIRE modules to static/lib
    modules_dir = ROOT / "modules"
    core_modules = [
        "greenwire_protocol_logger.py",
        "greenwire_emv_compliance.py", 
        "greenwire_crypto_fuzzer.py",
        "greenwire_key_manager.py",
        "android_nfc.py",
        "emulation.py"
    ]
    
    for module in core_modules:
        src = modules_dir / module
        if src.exists():
            shutil.copy(src, lib_out / module)
            print(f"  Copied {module} to static/lib")

    # Copy core system files
    core_files = ["greenwire.py", "menu_handlers.py", "menu_implementations.py"]
    for file in core_files:
        src = ROOT / file
        if src.exists():
            shutil.copy(src, target / file)
            print(f"  Copied {file}")

    # Copy core directory
    core_dir = ROOT / "core"
    if core_dir.exists():
        shutil.copytree(core_dir, target / "core", dirs_exist_ok=True)
        print("  Copied core/ directory")

    # Copy greenwire package
    greenwire_pkg = ROOT / "greenwire"
    if greenwire_pkg.exists():
        shutil.copytree(greenwire_pkg, target / "greenwire", dirs_exist_ok=True)
        print("  Copied greenwire/ package")

    # Copy other essential directories
    essential_dirs = ["apdu4j_data", "javacard", "sdk"]
    for dir_name in essential_dirs:
        src_dir = ROOT / dir_name
        if src_dir.exists():
            shutil.copytree(src_dir, target / dir_name, dirs_exist_ok=True)
            print(f"  Copied {dir_name}/ directory")

    # Copy CA keys and data
    if (ROOT / "ca_keys.json").exists():
        shutil.copy(ROOT / "ca_keys.json", target / "ca_keys.json")
        print("  Copied ca_keys.json")
    
    data_dir = ROOT / "data"
    if data_dir.exists():
        shutil.copytree(data_dir, target / "data", dirs_exist_ok=True)
        print("  Copied data/ directory")

    # Create run script for static bundle
    run_script = target / "run_greenwire.py"
    with run_script.open("w", encoding="utf-8") as f:
        f.write("""#!/usr/bin/env python3
\"\"\"Static GREENWIRE launcher with bundled dependencies.\"\"\"
import os
import sys
from pathlib import Path

# Add static lib to path for bundled modules
bundle_root = Path(__file__).parent
static_lib = bundle_root / "static" / "lib"
if static_lib.exists():
    sys.path.insert(0, str(static_lib))

# Set static mode environment
os.environ["GREENWIRE_STATIC"] = "1"

# Import and run main
if __name__ == "__main__":
    from greenwire import main
    main()
""")
    
    # Make run script executable
    run_script.chmod(0o755)
    print("  Created run_greenwire.py launcher")

    print(f"\n✅ Static bundle created at {target}")
    print(f"   Run with: python {target / 'run_greenwire.py'}")
    return target


if __name__ == '__main__':
    collect_static()
