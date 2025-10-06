#!/usr/bin/env python3
"""
Convenience helper to compile JavaCard applets and produce .cap files using the
local SDK and offline tools bundled in the repository.

Usage:
  python tools/build_javacard_applet.py --applet-dir javacard/applet \
      --applet-class com.greenwire.fuzz.FuzzingApplet \
      --package-name com.greenwire.fuzz \
      --applet-aid A0000006230146555A5A \
      --package-aid A0000006230146555A50

The script will:
- Copy any SDK jars from sdk/javacard/lib to static/java/javacard_lib
- Compile .java sources with javac using api_classic.jar on the classpath
- Attempt to convert classes to a .cap using tools.jar (JavaCard converter) if available
- Fallback: attempt ant-javacard.jar conversion if present
- Place resulting .cap in javacard/applet/build/cap/

This is best-effort and will print helpful diagnostics for missing dependencies.
"""

import argparse
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SDK_LIB = ROOT / 'sdk' / 'javacard' / 'lib'
STATIC_JAVA = ROOT / 'static' / 'java'
STATIC_JAVACARD_LIB = STATIC_JAVA / 'javacard_lib'
ANT_JAVACARD_JAR = STATIC_JAVA / 'ant-javacard.jar'
_jdk_bins = list((STATIC_JAVA / 'jdk').glob('jdk*/bin'))
if _jdk_bins:
    STATIC_JDK_BIN = max(_jdk_bins, key=lambda p: len(str(p)))
else:
    STATIC_JDK_BIN = STATIC_JAVA / 'jdk' / 'bin'


def run(cmd, cwd=None):
    print("+", " ".join(cmd))
    try:
        res = subprocess.run(
            cmd,
            cwd=cwd or str(ROOT),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        print(res.stdout)
        if res.stderr:
            print(res.stderr)
        return res.returncode, res.stdout + res.stderr
    except FileNotFoundError as e:
        print(f"Command not found: {e}")
        return 127, str(e)
    except subprocess.TimeoutExpired as e:
        print(f"Command timed out: {e}")
        return 124, str(e)


def ensure_static_javacard_lib():
    STATIC_JAVACARD_LIB.mkdir(parents=True, exist_ok=True)
    if SDK_LIB.exists():
        found = list(SDK_LIB.glob('*.jar'))
        for jar in found:
            dst = STATIC_JAVACARD_LIB / jar.name
            if not dst.exists():
                print(f"Copying {jar} -> {dst}")
                shutil.copy2(jar, dst)
    else:
        print("Warning: SDK lib directory not found:", SDK_LIB)


def collect_java_sources(applet_dir: Path):
    candidates = []
    for src_root in [
        applet_dir / 'src',
        applet_dir / 'src' / 'main' / 'java',
        applet_dir / 'src' / 'com',
    ]:
        if src_root.exists():
            candidates.append(src_root)
    files = []
    for root in candidates:
        files += list(root.rglob('*.java'))
    return files


def compile_sources(sources, classpath, outdir):
    outdir.mkdir(parents=True, exist_ok=True)
    src_list = [str(s) for s in sources]
    if not src_list:
        print('No Java sources found to compile')
        return 1, 'no sources'
    javac_bin = str(STATIC_JDK_BIN / ('javac.exe' if Path.home().anchor else 'javac'))
    if not Path(javac_bin).exists():
        javac_bin = 'javac'
    # Compile for JavaCard-compatible class version and API.
    # Do NOT override bootclasspath; keep standard rt.jar available and add
    # JavaCard API via -classpath only to avoid missing java.lang.* symbols.
    cmd = [
        javac_bin,
        '-g:none',
        '-source', '1.6',
        '-target', '1.6',
        '-classpath', classpath,
        '-extdirs', '',  # ensure no unexpected extensions leak in
        '-d', str(outdir),
    ] + src_list
    return run(cmd)


def convert_with_toolsjar(
    toolsjar,
    classes_dir,
    export_path,
    out_dir,
    applet_class,
    package_name,
    package_aid,
    applet_aid,
    package_version='1.0',
):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if not Path(toolsjar).exists():
        print('tools.jar not found at', toolsjar)
        return 1, 'tools.jar missing'
    if not Path(export_path).exists():
        print('API export path not found:', export_path)
        return 1, 'export path missing'
    java_bin = str(STATIC_JDK_BIN / ('java.exe' if Path.home().anchor else 'java'))
    if not Path(java_bin).exists():
        java_bin = 'java'
    cmd = [
        java_bin, '-cp', str(toolsjar), 'com.sun.javacard.converter.Main',
        '-classdir', str(classes_dir),
        '-d', str(out_dir),
        '-exportpath', str(export_path),
        '-out', 'CAP',
        '-applet', applet_aid, applet_class,
        package_name, package_aid, package_version
    ]
    return run(cmd)


def convert_with_antjar(
    antjar,
    applet_dir,
    out_dir,
    package_name,
    applet_aid,
    applet_class,
):
    if not Path(antjar).exists():
        print('ant-javacard jar not found at', antjar)
        return 1, 'ant-javacard missing'
    # Heuristic invocation (ant-javacard CLI varies; try commonly supported flags)
    java_bin = str(STATIC_JDK_BIN / ('java.exe' if Path.home().anchor else 'java'))
    if not Path(java_bin).exists():
        java_bin = 'java'
    cmd = [
        java_bin, '-jar', str(antjar),
        '-src', str(applet_dir / 'src'),
        '-out', str(out_dir),
        '-pkg', package_name,
        '-aid', applet_aid,
        '-applet', applet_class
    ]
    return run(cmd)


def normalize_aid(aid: str) -> str:
    """Normalize AID for validation and human display (colon-separated byte pairs)."""
    s = aid.strip().replace(':', '').replace(' ', '').upper()
    if len(s) % 2 != 0:
        raise ValueError(f"Invalid AID length: {aid}")
    pairs = [s[i:i+2] for i in range(0, len(s), 2)]
    return ':'.join(pairs)


def aid_hex(aid: str) -> str:
    """Return contiguous uppercase hex for AID (no separators), for converter."""
    s = aid.strip().replace(':', '').replace(' ', '').upper()
    if len(s) % 2 != 0:
        raise ValueError(f"Invalid AID length: {aid}")
    return s


def aid_colon_0x(aid: str) -> str:
    """Return 0x-prefixed, colon-separated AID (e.g., 0xA0:0x00:...)."""
    s = aid.strip().replace(':', '').replace(' ', '').upper()
    if len(s) % 2 != 0:
        raise ValueError(f"Invalid AID length: {aid}")
    pairs = [s[i:i + 2] for i in range(0, len(s), 2)]
    return ':'.join('0x' + p for p in pairs)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--applet-dir', default='javacard/applet')
    p.add_argument('--applet-class', required=True)
    p.add_argument('--package-name', required=True)
    p.add_argument('--applet-aid', required=True)
    p.add_argument('--package-aid', required=True)
    p.add_argument('--export-path', default='sdk/javacard/api_export_files')
    args = p.parse_args()

    applet_dir = ROOT / args.applet_dir
    print('Working on applet dir:', applet_dir)

    # 1. Ensure static area contains SDK jars
    ensure_static_javacard_lib()

    # 2. Collect java sources
    sources = collect_java_sources(applet_dir)
    print(f'Found {len(sources)} Java source files')

    # 3. Compile using javac
    api_jar = STATIC_JAVACARD_LIB / 'api_classic.jar'
    classpath = str(api_jar) if api_jar.exists() else ''
    build_classes = applet_dir / 'build' / 'classes'
    rc, _ = compile_sources(sources, classpath, build_classes)
    if rc != 0:
        print('Compilation failed; aborting conversion')
        return rc

    # 4. Try conversion with tools.jar
    toolsjar = STATIC_JAVACARD_LIB / 'tools.jar'
    export_path = ROOT / args.export_path
    # If export_path does not exist, create a minimal placeholder that may allow
    # the JavaCard converter to run in limited/offline mode. This is a best-effort
    # fallback — full JavaCard export files from the SDK are recommended.
    if not export_path.exists():
        print('Export path not found, creating minimal placeholder at:', export_path)
        export_path.mkdir(parents=True, exist_ok=True)
        placeholder = export_path / 'api_classic.exp'
        if not placeholder.exists():
            placeholder.write_text(
                '# Minimal placeholder export file\n', encoding='utf-8'
            )
            print('Wrote placeholder export file:', placeholder)
    cap_out = applet_dir / 'build' / 'cap'
    if toolsjar.exists() and export_path.exists():
        print('Attempting converter (tools.jar) path...')
        try:
            # Validate AIDs; prefer 0x-prefixed colon-separated format for converter
            _ = normalize_aid(args.applet_aid)
            _ = normalize_aid(args.package_aid)
            conv_applet_aid = aid_colon_0x(args.applet_aid)
            conv_package_aid = aid_colon_0x(args.package_aid)
        except ValueError as e:
            print('AID normalization error:', e)
            return 2, str(e)

        rc, _ = convert_with_toolsjar(
            str(toolsjar),
            build_classes,
            export_path,
            cap_out,
            args.applet_class,
            args.package_name,
            conv_package_aid,
            conv_applet_aid,
        )
        if rc == 0:
            print('Conversion with tools.jar succeeded')
            return 0
        else:
            print('tools.jar conversion failed, falling back to ant-javacard')

    # 5. Fallback to ant-javacard
    if ANT_JAVACARD_JAR.exists():
        print('Attempting ant-javacard conversion...')
        try:
            norm_applet_aid = normalize_aid(args.applet_aid)
        except ValueError as e:
            print('AID normalization error:', e)
            return 2, str(e)

        rc, _ = convert_with_antjar(
            str(ANT_JAVACARD_JAR),
            applet_dir,
            cap_out,
            args.package_name,
            norm_applet_aid,
            args.applet_class,
        )
        if rc == 0:
            print('ant-javacard conversion succeeded')
            return 0
        else:
            print('ant-javacard conversion failed')
            return rc

    print(
        'No converter available (tools.jar or ant-javacard.jar). '
        'Please provide SDK export files or ant-javacard in static/java'
    )
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
