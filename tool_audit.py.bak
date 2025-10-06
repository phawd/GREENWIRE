"""Minimal environment audit for GREENWIRE.

Provides aggregate(), human(), check_readiness(), and main() used by greenwire.py.
Checks: java, adb, gp.jar presence and version where applicable.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path


def which(name: str) -> str | None:
    return shutil.which(name)


def _pcsc_ready() -> bool:
    try:
        # Windows: winscard.dll
        import ctypes
        ctypes.WinDLL('winscard')
        return True
    except Exception:
        pass
    try:
        import smartcard  # type: ignore
        return True
    except Exception:
        return False


def _javac_build_ready(root: Path) -> bool:
    # Consider JavaCard build ready if java exists and SDK jars (tools.jar + api) are present
    java = which('java')
    sdk_dir = root / 'sdk' / 'javacard' / 'lib'
    tools = sdk_dir / 'tools.jar'
    api = None
    for cand in ['api_classic.jar', 'javacard_framework.jar']:
        p = sdk_dir / cand
        if p.exists():
            api = p
            break
    return bool(java) and tools.exists() and (api is not None)


def check_readiness() -> bool:
    root = Path(__file__).parent
    return _javac_build_ready(root) and _pcsc_ready()


def aggregate() -> dict:
    root = Path(__file__).parent
    java = which('java')
    adb = which('adb')
    gpjar = root / 'static' / 'java' / 'gp.jar'
    gppro = root / 'lib' / 'GlobalPlatformPro.jar'

    tools = {
        'java': {'ok': bool(java), 'path': java},
        'adb': {'ok': bool(adb), 'path': adb},
        'gp.jar': {'ok': gpjar.exists(), 'path': str(gpjar)},
        'GlobalPlatformPro.jar': {'ok': gppro.exists(), 'path': str(gppro)},
    }

    readiness = {
        'javac_build_ready': _javac_build_ready(root),
        'pcsc_ready': _pcsc_ready(),
    }

    ok = all(v['ok'] for v in tools.values()) and all(readiness.values())
    return {'ok': ok, 'tools': tools, 'readiness': readiness}


def human(report: dict) -> str:
    def mark(ok: bool) -> str:
        return '✅' if ok else '❌'
    lines = ['GREENWIRE toolchain audit']
    for key, info in report['tools'].items():
        lines.append(f"  {mark(info['ok'])} {key}: {info.get('path','')}")
    lines.append('Readiness:')
    for key, val in report['readiness'].items():
        lines.append(f"  {mark(bool(val))} {key}")
    return '\n'.join(lines)


def main(json_out: bool = False) -> int:
    ag = aggregate()
    if json_out:
        print(json.dumps(ag, indent=2))
    else:
        print(human(ag['items']))
        print(f"\nOverall: {'OK' if ag['ok'] else 'INCOMPLETE'}")
    return 0 if ag['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())