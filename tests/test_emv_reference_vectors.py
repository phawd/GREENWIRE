from __future__ import annotations

from core.emv_reference_vectors import get_reference_cryptogram, load_reference_vectors
from modules.production_crypto_engine import ProductionCryptoEngine


def test_reference_vector_loader_reads_emv_directory() -> None:
    vectors = load_reference_vectors()
    assert "visa" in vectors
    assert "mastercard" in vectors
    assert "amex" in vectors
    assert len(vectors["visa"]["cryptogram_example"]) == 16
    assert len(vectors["mastercard"]["cryptogram_example"]) == 16


def test_production_crypto_engine_uses_emv_reference_cryptograms() -> None:
    engine = ProductionCryptoEngine(verbose=False)
    visa_ref = get_reference_cryptogram("visa")
    mc_ref = get_reference_cryptogram("mastercard")
    amex_ref = get_reference_cryptogram("amex")

    assert engine.test_vectors["visa_cvn_10"]["expected_arqc"] == visa_ref["cryptogram_example"]
    assert engine.test_vectors["mastercard_cvn_17"]["expected_arqc"] == mc_ref["cryptogram_example"]
    assert engine.test_vectors["amex_proprietary"]["expected_arqc"] == amex_ref["cryptogram_example"]
