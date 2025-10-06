"""Data manager for production-scraped EMV and merchant datasets.

Provides listing and loading of scraped production data used to generate NFC/GP cards.
This module is intentionally lightweight and uses JSON/YAML files placed under
`data/production_scrapes/` or `data/`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any

DATA_DIRS = [
    Path(__file__).parent.parent.parent / "data" / "production_scrapes",
    Path(__file__).parent.parent.parent / "data",
]


def _candidate_files() -> List[Path]:
    out: List[Path] = []
    for d in DATA_DIRS:
        if d.exists() and d.is_dir():
            for p in d.glob("**/*"):
                if p.suffix.lower() in (".json", ".yaml", ".yml"):
                    out.append(p)
    return sorted(out)


def list_datasets() -> List[str]:
    """Return a list of available dataset basenames (no extension).

    Uses DATA_DIRS in order and returns unique names (first match wins).
    """
    files = _candidate_files()
    seen = set()
    names: List[str] = []
    for p in files:
        name = p.stem
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def find_dataset_path(name: str) -> Optional[Path]:
    files = _candidate_files()
    for p in files:
        if p.stem == name:
            return p
    return None


def load_dataset(name: str) -> Optional[Dict[str, Any]]:
    """Load a named dataset (JSON/YAML) and return it as a dict.

    Returns None if not found or parse failed.
    """
    p = find_dataset_path(name)
    if p is None:
        return None
    try:
        if p.suffix.lower() == ".json":
            with p.open("r", encoding="utf-8") as f:
                return json.load(f)
        else:
            # optional YAML support via safe_load if PyYAML present
            try:
                import yaml  # type: ignore
            except Exception:
                return None
            with p.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f)
    except Exception:
        return None


def choose_dataset_interactive() -> Optional[str]:
    names = list_datasets()
    if not names:
        print("No production-scraped datasets found in data/production_scrapes or data/")
        return None
    print("Available datasets:")
    for i, n in enumerate(names, 1):
        print(f"  {i}. {n}")
    choice = input("Select dataset by number (or name, blank to cancel): ").strip()
    if not choice:
        return None
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(names):
            return names[idx]
        return None
    if choice in names:
        return choice
    return None


def create_sample_dataset(name: str, out_dir: Optional[Path] = None) -> Path:
    """Create a small JSON sample dataset for development and return its path."""
    out_dir = out_dir or Path(__file__).parent.parent.parent / "data" / "production_scrapes"
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"{name}.json"
    sample = {
        "scheme": "visa",
        "count": 1,
        "type": "credit",
        "region": "us",
        "dda": True,
        "generate_cap": False,
        "cap_output_dir": "generated_caps",
        "test_merchant": True,
        "merchants": [
            {"id": "MERCH001", "name": "Sample Merchant", "country": "US"},
        ],
    }
    with p.open("w", encoding="utf-8") as f:
        json.dump(sample, f, indent=2)
    return p


def dataset_summary(name: str) -> dict:
    """Return a small summary for the named dataset (counts and keys)."""
    ds = load_dataset(name)
    if ds is None:
        return {"error": "not found or failed to parse"}
    summary = {
        "name": name,
        "size_bytes": len(json.dumps(ds)),
        "top_keys": list(ds.keys())[:10],
    }
    if isinstance(ds.get("merchants"), list):
        summary["merchant_count"] = len(ds.get("merchants") or [])
    return summary
