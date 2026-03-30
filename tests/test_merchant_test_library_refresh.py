from __future__ import annotations

from modules.merchant_test_library import MerchantTestLibrary, TestCategory, TestSeverity


def test_contactless_tests_are_marked_with_required_capabilities() -> None:
    library = MerchantTestLibrary()

    contactless_tests = library.get_tests_by_category(TestCategory.INTERFACE_SECURITY)
    contactless_ids = {item["test_id"] for item in contactless_tests}

    assert "T049_NFC_RELAY_ATTACK" in contactless_ids
    assert "T050_CONTACTLESS_COLLISION" in contactless_ids

    relay = library.get_test("T049_NFC_RELAY_ATTACK")
    collision = library.get_test("T050_CONTACTLESS_COLLISION")
    biometric = library.get_test("T056_BIOMETRIC_AUTHENTICATION")

    assert relay["required_capabilities"] == {"contactless": True}
    assert collision["required_capabilities"] == {"contactless": True}
    assert biometric["required_capabilities"] == {"biometric": True}


def test_library_reports_expected_test_counts() -> None:
    library = MerchantTestLibrary()

    assert library.get_test_count() == 56
    critical_tests = library.get_tests_by_severity(TestSeverity.CRITICAL)
    assert len(critical_tests) >= 1
