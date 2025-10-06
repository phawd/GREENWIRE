#!/usr/bin/env python3
"""Verify GREENWIRE static build completeness"""

import os
import sys
from pathlib import Path

def check_static_dependencies():
    """Check all static dependencies are present"""
    base_path = Path(".")
    missing = []
    
    # Required static Java components
    java_deps = [
        "static/java/javacard_lib/api_classic.jar",
        "static/java/ant-javacard.jar", 
        "static/java/gp.jar",
        "static/java/apache-ant-1.10.15/bin/ant",
    ]
    
    # Check for JDK (either extracted or zip)
    jdk_extracted = base_path / "static/java/jdk/jdk8u462-b08/bin/javac.exe"
    jdk_zip = base_path / "static/java/temurin8.zip"
    
    if not jdk_extracted.exists() and not jdk_zip.exists():
        missing.append("static/java/jdk or temurin8.zip")
    
    # Check Java dependencies
    for dep in java_deps:
        if not (base_path / dep).exists():
            missing.append(dep)
    
    # Required Python static libs
    python_deps = [
        "static/lib/android_nfc.py",
        "static/lib/emulation.py",
        "static/lib/greenwire_crypto_fuzzer.py",
        "static/lib/greenwire_emv_compliance.py",
    ]
    
    for dep in python_deps:
        if not (base_path / dep).exists():
            missing.append(dep)
    
    # Check compiled Java files exist
    java_files = [
        "CommandAPDU.java",
        "caplets/merchant_probes/ECommerceProbe.java",
        "applets/emv_vulntests/AmountModificationTester.java",
        "javacard/applet/src/com/greenwire/PinLogicApplet.java",
    ]
    
    for java_file in java_files:
        if not (base_path / java_file).exists():
            missing.append(java_file)
    
    return missing

def verify_build_capability():
    """Verify build can be executed"""
    issues = []
    
    # Check build script exists
    if not Path("build_static.bat").exists():
        issues.append("build_static.bat missing")
    
    # Check static directory structure
    static_dirs = [
        "static/java",
        "static/lib", 
        "build"
    ]
    
    for dir_path in static_dirs:
        if not Path(dir_path).exists():
            issues.append(f"Directory {dir_path} missing")
    
    return issues

def main():
    print("GREENWIRE Static Build Verification")
    print("=" * 40)
    
    # Check dependencies
    missing_deps = check_static_dependencies()
    if missing_deps:
        print("[ERROR] Missing dependencies:")
        for dep in missing_deps:
            print(f"   - {dep}")
    else:
        print("[OK] All static dependencies present")
    
    # Check build capability
    build_issues = verify_build_capability()
    if build_issues:
        print("[ERROR] Build issues:")
        for issue in build_issues:
            print(f"   - {issue}")
    else:
        print("[OK] Build environment ready")
    
    # Summary
    total_issues = len(missing_deps) + len(build_issues)
    if total_issues == 0:
        print("\n[SUCCESS] GREENWIRE is ready for static deployment!")
        print("Run: build_static.bat")
        return 0
    else:
        print(f"\n[WARNING] {total_issues} issues found - fix before deployment")
        return 1

if __name__ == "__main__":
    sys.exit(main())