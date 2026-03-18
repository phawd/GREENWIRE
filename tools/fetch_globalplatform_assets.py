#!/usr/bin/env python3
"""Fetch and audit public GlobalPlatform tooling metadata.

Downloads the public GPPro `gp.jar` asset when requested and scrapes Oracle's
Java Card downloads page for the current file names/operators must fetch
manually after accepting Oracle's license terms.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.globalplatform_reference import (
    GP_GITHUB_RELEASE_URL,
    GP_ORACLE_DOWNLOADS_PAGE,
    list_test_key_profiles,
)


ORACLE_FILE_RE = re.compile(
    r"data-file=['\"](?P<url>[^'\"]*java_card_[^'\"]+)['\"][\s\S]*?>(?P<name>\s*java_card_[^<]+)<"
)


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8", errors="ignore")


def discover_oracle_javacard_downloads(html: str | None = None) -> List[Dict[str, str]]:
    html = html if html is not None else fetch_text(GP_ORACLE_DOWNLOADS_PAGE)
    downloads: List[Dict[str, str]] = []
    seen: set[str] = set()
    for match in ORACLE_FILE_RE.finditer(html):
        raw_url = match.group("url")
        url = raw_url if raw_url.startswith("http") else f"https:{raw_url}"
        name = match.group("name").strip()
        if name in seen:
            continue
        seen.add(name)
        downloads.append({"name": name, "url": url})
    return downloads


def download_gppro(target: Path, overwrite: bool = False) -> Path:
    if target.exists() and not overwrite:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(GP_GITHUB_RELEASE_URL, timeout=60) as response:
        data = response.read()
    target.write_bytes(data)
    return target


def build_manifest(root: Path) -> Dict[str, object]:
    return {
        "gppro": {
            "download_url": GP_GITHUB_RELEASE_URL,
            "repo_target": "static/java/gp.jar",
            "present": (root / "static" / "java" / "gp.jar").exists(),
        },
        "oracle_javacard": {
            "downloads_page": GP_ORACLE_DOWNLOADS_PAGE,
            "discovered_assets": discover_oracle_javacard_downloads(),
        },
        "test_keys": list_test_key_profiles(),
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch/audit GlobalPlatform assets.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root.")
    parser.add_argument(
        "--download-gppro",
        action="store_true",
        help="Download the latest public gp.jar into static/java/gp.jar.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite gp.jar if it already exists.",
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        help="Optional path for the generated JSON manifest.",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    if args.download_gppro:
        download_gppro(root / "static" / "java" / "gp.jar", overwrite=args.overwrite)

    manifest = build_manifest(root)
    payload = json.dumps(manifest, indent=2)
    if args.manifest_out:
        args.manifest_out.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
