"""Recursive discovery of EMV CA/certificate material in emv* directories."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List


CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p7b", ".pfx", ".key"}
TEXT_EXTENSIONS = {".json", ".txt", ".md", ".html"}
KEYWORDS = (
    "root-ca",
    "intermediate-ca",
    "issuer public key",
    "icc public key",
    "certificate authority",
    "ca key",
    "ca public keys",
    "public key certificate",
    "rid index",
    "rid list",
)


@dataclass(frozen=True)
class EMVCertificateAsset:
    path: str
    kind: str
    size: int

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _iter_emv_roots(root: Path) -> List[Path]:
    roots: List[Path] = []
    for child in root.iterdir():
        if child.is_dir() and child.name.lower().startswith("emv"):
            roots.append(child)
    return sorted(roots)


def find_emv_certificate_assets(root: str | Path | None = None) -> List[EMVCertificateAsset]:
    repo_root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    assets: List[EMVCertificateAsset] = []

    for emv_root in _iter_emv_roots(repo_root):
        for path in emv_root.rglob("*"):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            rel = path.relative_to(repo_root).as_posix()
            if suffix in CERT_EXTENSIONS:
                kind = "certificate_or_key"
            elif suffix in TEXT_EXTENSIONS:
                text = path.read_text(encoding="utf-8", errors="ignore").lower()
                if not any(keyword in text for keyword in KEYWORDS):
                    continue
                kind = "certificate_reference"
            else:
                continue
            assets.append(EMVCertificateAsset(path=rel, kind=kind, size=path.stat().st_size))

    return sorted(assets, key=lambda asset: asset.path)


def build_emv_certificate_inventory(root: str | Path | None = None) -> Dict[str, object]:
    assets = find_emv_certificate_assets(root)
    return {
        "count": len(assets),
        "assets": [asset.to_dict() for asset in assets],
    }


__all__ = [
    "EMVCertificateAsset",
    "build_emv_certificate_inventory",
    "find_emv_certificate_assets",
]
