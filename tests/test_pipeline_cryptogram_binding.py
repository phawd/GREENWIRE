from __future__ import annotations

from core.pipeline_providers import EmulatorHSMBackend, build_cryptogram_payload


def test_cryptogram_payload_binds_pan_and_transaction_context() -> None:
    payload_a = build_cryptogram_payload(
        pan="4003123412341234",
        track2="4003123412341234D25122010000000000",
        amount=1.25,
        currency="USD",
        terminal_country="840",
        transaction_id="TXN123",
        atc=1,
    )
    payload_b = build_cryptogram_payload(
        pan="4003123412341235",
        track2="4003123412341235D25122010000000000",
        amount=1.25,
        currency="USD",
        terminal_country="840",
        transaction_id="TXN123",
        atc=1,
    )
    assert payload_a != payload_b


def test_hsm_backend_generates_and_verifies_pan_bound_arqc() -> None:
    backend = EmulatorHSMBackend()
    payload = build_cryptogram_payload(
        pan="4003123412341234",
        track2="4003123412341234D25122010000000000",
        amount=2.00,
        currency="USD",
        terminal_country="840",
        transaction_id="TXN999",
        atc=7,
    )
    arqc = backend.generate_arqc(pan="4003123412341234", atc=7, payload=payload)
    assert backend.verify_arqc(pan="4003123412341234", atc=7, payload=payload, arqc=arqc) is True
    assert backend.verify_arqc(pan="4003123412341235", atc=7, payload=payload, arqc=arqc) is False
