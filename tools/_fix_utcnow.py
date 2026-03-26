"""One-shot script: replace every datetime.now(timezone.utc) across the repo.

Run from repo root:  python tools/_fix_utcnow.py
"""
import re
import pathlib

ROOT = pathlib.Path(__file__).parent.parent
SKIP_DIRS = {'.git', '__pycache__', 'archive', 'dist', 'node_modules'}

_replacements = 0


def _add_timezone_import(text: str) -> str:
    """Ensure `timezone` is in the `from datetime import ...` line.""", timezone
    def _patch(m):
        imports = m.group(2)
        if 'timezone' in imports:
            return m.group(0)
        return m.group(1) + imports.rstrip() + ', timezone'
    return re.sub(r'(from datetime import\s+)([^\n]+)', _patch, text, count=1)


def fix_file(path: pathlib.Path) -> bool:
    global _replacements
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return False
    orig = text

    # 1. Fully-qualified: datetime.datetime.now(datetime.timezone.utc) …
    text = re.sub(
        r'datetime\.datetime\.utcnow\(\)\.isoformat\(\)\s*\+\s*["\']Z["\']',
        'datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"',
        text)
    text = re.sub(
        r'datetime\.datetime\.utcnow\(\)',
        'datetime.datetime.now(datetime.timezone.utc)',
        text)

    # 2. Short form: datetime.now(timezone.utc) …
    text = re.sub(
        r'datetime\.utcnow\(\)\.isoformat\(\)\s*\+\s*["\']Z["\']',
        'datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"',
        text)
    text = re.sub(
        r'datetime\.utcnow\(\)\.strftime\(',
        'datetime.now(timezone.utc).strftime(',
        text)
    # .replace() — strip tzinfo so arithmetic still works with naive timedeltas
    text = re.sub(
        r'datetime\.utcnow\(\)\.replace\(',
        'datetime.now(timezone.utc).replace(tzinfo=None).replace(',
        text)
    # + timedelta
    text = re.sub(
        r'datetime\.utcnow\(\)\s*\+\s*timedelta',
        'datetime.now(timezone.utc).replace(tzinfo=None) + timedelta',
        text)
    # bare call
    text = re.sub(r'datetime\.utcnow\(\)', 'datetime.now(timezone.utc)', text)

    if text == orig:
        return False

    # Patch imports if we introduced timezone.utc references
    if 'datetime.now(timezone.utc)' in text:
        if 'from datetime import' in text:
            text = _add_timezone_import(text)
        # If file uses `import datetime` style only, datetime.timezone.utc already works

    path.write_text(text, encoding='utf-8')
    _replacements += 1
    return True


def main():
    fixed = []
    for p in sorted(ROOT.rglob('*.py')):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if fix_file(p):
            fixed.append(p.relative_to(ROOT))
            print(f'  fixed: {p.relative_to(ROOT)}')
    print(f'\nDone — {len(fixed)} files updated.')


if __name__ == '__main__':
    main()
