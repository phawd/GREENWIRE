from __future__ import annotations

from pathlib import Path

from core.emv_ca_locator import build_emv_certificate_inventory, find_emv_certificate_assets


def test_find_emv_certificate_assets_discovers_recursive_material(tmp_path: Path) -> None:
    emv_root = tmp_path / "emv_data"
    emv_root.mkdir(parents=True)
    pem_path = emv_root / "ca" / "root-ca.pem"
    pem_path.parent.mkdir(parents=True)
    pem_path.write_text("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n", encoding="utf-8")

    html_path = emv_root / "refs" / "keys.html"
    html_path.parent.mkdir(parents=True)
    html_path.write_text("<html><body>Issuer Public Key Certificate</body></html>", encoding="utf-8")

    assets = find_emv_certificate_assets(tmp_path)
    assert [asset.path for asset in assets] == [
        "emv_data/ca/root-ca.pem",
        "emv_data/refs/keys.html",
    ]


def test_build_emv_certificate_inventory_returns_count(tmp_path: Path) -> None:
    emv_root = tmp_path / "emv"
    emv_root.mkdir(parents=True)
    (emv_root / "intermediate-ca.pem").write_text("pem", encoding="utf-8")

    inventory = build_emv_certificate_inventory(tmp_path)
    assert inventory["count"] == 1
    assert inventory["assets"][0]["path"] == "emv/intermediate-ca.pem"
