from __future__ import annotations

from pathlib import Path

from greenwire.core.configuration_manager import ConfigurationManager


def test_configuration_manager_defaults_card_pin_to_6666(tmp_path: Path) -> None:
    config_path = tmp_path / "greenwire_config.json"
    manager = ConfigurationManager(path=config_path)
    assert manager.default_card_pin() == "6666"


def test_configuration_manager_reads_default_pin_from_greenwire_conf(tmp_path: Path) -> None:
    config_path = tmp_path / "greenwire_config.json"
    conf_path = tmp_path / "GREENWIRE.conf"
    conf_path.write_text("[cards]\ndefault_pin=7777\n", encoding="utf-8")
    manager = ConfigurationManager(path=config_path)
    assert manager.default_card_pin() == "7777"
