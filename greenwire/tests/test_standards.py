import importlib.util
from pathlib import Path

_std_path = Path(__file__).resolve().parents[1] / "core" / "standards.py"
spec = importlib.util.spec_from_file_location("standards", _std_path)
standards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(standards)


def test_all_standards_listed():
    handler = standards.StandardHandler()
    supported = handler.list_supported()
    expected = [
        "ISO/IEC 7810",
        "ISO/IEC 7816",
        "T=0/T=1 (ISO 7816-3)",
        "EMV",
        "GlobalPlatform",
        "GlobalPlatform Issuer",
        "GlobalPlatform Cardholder",
        "Card OS",
        "ICAO 9303",
        "ISO/IEC 18000-x",
        "ISO/IEC 15693",
        "EPCglobal",
        "ISO/IEC 29167",
        "ISO 14443",
        "ISO 18092",
        "NDEF",
        "LLCP",
        "RTD",
        "SNEP",
    ]
    assert supported == expected


def test_handle_returns_message():
    handler = standards.StandardHandler()
    assert handler.handle(standards.Standard.EMV) == "Handling EMV"


def test_check_compliance_returns_message():
    handler = standards.StandardHandler()
    msg = handler.check_compliance(standards.Standard.GLOBALPLATFORM_ISSUER)
    assert msg == "Following GlobalPlatform Issuer standard"
