from __future__ import annotations

from core.card_standards import get_profile
from core.globalplatform_reference import (
    GEMALTO_VISA2_TEST_KEY,
    GP_DEFAULT_TEST_KEY,
    common_test_keys,
    get_test_key_profile,
)
from tools.fetch_globalplatform_assets import discover_oracle_javacard_downloads


def test_globalplatform_reference_profiles_expose_public_lab_keys() -> None:
    default_profile = get_test_key_profile("default")
    gemalto_profile = get_test_key_profile("gemalto_visa2")

    assert default_profile.key_hex == GP_DEFAULT_TEST_KEY
    assert default_profile.diversification == "none"
    assert gemalto_profile.key_hex == GEMALTO_VISA2_TEST_KEY
    assert gemalto_profile.diversification == "visa2"


def test_common_test_keys_prioritize_gp_defaults() -> None:
    keys = common_test_keys()
    assert keys[0] == GP_DEFAULT_TEST_KEY
    assert GEMALTO_VISA2_TEST_KEY in keys


def test_globalplatform_card_profile_uses_stable_test_keys() -> None:
    profile = get_profile("globalplatform")
    assert profile is not None
    assert profile["keys"]["SCP02_MASTER_KEY"] == GP_DEFAULT_TEST_KEY
    assert profile["keys"]["SCP02_DIVERSIFICATION"] == "emv"
    assert "SCP02_ENC" not in profile["keys"]
    assert profile["keys"]["SCP03_ENC"] == GP_DEFAULT_TEST_KEY


def test_oracle_download_scraper_extracts_current_file_links() -> None:
    html = """
    <a class='license-link icn-download'
       data-file='//download.oracle.com/otn-pub/java/java_card_kit/3.2/java_card_devkit_tools-bin-v25.1-b_611-26-OCT-2025.zip'
       data-license='158'
       href='/downloads/software-license-agreement.html#license-lightbox'>
       java_card_devkit_tools-bin-v25.1-b_611-26-OCT-2025.zip</a>
    <a class='license-link icn-download'
       data-file='//download.oracle.com/otn-pub/java/java_card_kit/3.2/java_card_devkit_simulator-win-bin-v25.1-b_627-26-OCT-2025.zip'
       data-license='158'
       href='/downloads/software-license-agreement.html#license-lightbox'>
       java_card_devkit_simulator-win-bin-v25.1-b_627-26-OCT-2025.zip</a>
    """

    downloads = discover_oracle_javacard_downloads(html)
    assert downloads == [
        {
            "name": "java_card_devkit_tools-bin-v25.1-b_611-26-OCT-2025.zip",
            "url": "https://download.oracle.com/otn-pub/java/java_card_kit/3.2/java_card_devkit_tools-bin-v25.1-b_611-26-OCT-2025.zip",
        },
        {
            "name": "java_card_devkit_simulator-win-bin-v25.1-b_627-26-OCT-2025.zip",
            "url": "https://download.oracle.com/otn-pub/java/java_card_kit/3.2/java_card_devkit_simulator-win-bin-v25.1-b_627-26-OCT-2025.zip",
        },
    ]
