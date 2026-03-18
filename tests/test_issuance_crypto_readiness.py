from __future__ import annotations

from core import issuance_validation as validation


def test_validate_issuance_crypto_readiness_passes_with_valid_dependencies(monkeypatch) -> None:
    class _FakeKeys:
        mac_key = "A" * 32
        enc_key = "B" * 32
        dek_key = "C" * 32

    class _FakeHSM:
        def derive_session_keys(self, *, pan: str, pan_sequence: str, atc: int):
            return _FakeKeys()

        def generate_arqc(self, *, pan: str, atc: int, payload: bytes) -> str:
            return "D" * 16

        def verify_arqc(self, *, pan: str, atc: int, payload: bytes, arqc: str) -> bool:
            return True

    monkeypatch.setattr(validation, "build_emv_certificate_inventory", lambda: {"count": 1})
    monkeypatch.setattr(validation, "load_reference_vectors", lambda: {"visa": {"rid": "A000000003"}})
    monkeypatch.setattr(validation, "EmulatorHSMBackend", lambda: _FakeHSM())
    errors = validation.validate_issuance_crypto_readiness(pan="4003123412341234", atc=1)
    assert errors == []


def test_validate_issuance_crypto_readiness_flags_missing_ca(monkeypatch) -> None:
    class _FakeKeys:
        mac_key = "A" * 32
        enc_key = "B" * 32
        dek_key = "C" * 32

    class _FakeHSM:
        def derive_session_keys(self, *, pan: str, pan_sequence: str, atc: int):
            return _FakeKeys()

        def generate_arqc(self, *, pan: str, atc: int, payload: bytes) -> str:
            return "D" * 16

        def verify_arqc(self, *, pan: str, atc: int, payload: bytes, arqc: str) -> bool:
            return True

    monkeypatch.setattr(validation, "build_emv_certificate_inventory", lambda: {"count": 0})
    monkeypatch.setattr(validation, "load_reference_vectors", lambda: {"visa": {"rid": "A000000003"}})
    monkeypatch.setattr(validation, "EmulatorHSMBackend", lambda: _FakeHSM())
    errors = validation.validate_issuance_crypto_readiness(pan="4003123412341234", atc=1)
    assert any("No EMV CA/certificate assets" in err for err in errors)


def test_validate_issuance_crypto_readiness_can_include_atm_checks(monkeypatch) -> None:
    class _FakeKeys:
        mac_key = "A" * 32
        enc_key = "B" * 32
        dek_key = "C" * 32

    class _FakeHSM:
        def __init__(self) -> None:
            self.calls = 0

        def derive_session_keys(self, *, pan: str, pan_sequence: str, atc: int):
            return _FakeKeys()

        def generate_arqc(self, *, pan: str, atc: int, payload: bytes) -> str:
            self.calls += 1
            return "D" * 16

        def verify_arqc(self, *, pan: str, atc: int, payload: bytes, arqc: str) -> bool:
            return True

    fake_hsm = _FakeHSM()
    monkeypatch.setattr(validation, "build_emv_certificate_inventory", lambda: {"count": 1})
    monkeypatch.setattr(validation, "load_reference_vectors", lambda: {"visa": {"rid": "A000000003"}})
    monkeypatch.setattr(validation, "EmulatorHSMBackend", lambda: fake_hsm)
    errors = validation.validate_issuance_crypto_readiness(
        pan="4003123412341234",
        atc=1,
        include_atm=True,
    )
    assert errors == []
    assert fake_hsm.calls == 2
