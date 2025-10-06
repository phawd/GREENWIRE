#!/usr/bin/env python3
"""Central configuration manager for GREENWIRE.

Provides a single source of truth for top-level configuration values that can
be updated either by editing the configuration file directly or via the UI/CLI.
"""
from __future__ import annotations

import json
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional

_DEFAULT_CONFIG: Dict[str, Any] = {
    "cards": {
        "default_profile": "visa_premium_contact_credit",
        "default_variant": "dda",
        "authentication_modes": ["dda", "sda", "mifare_classic"],
        "prompt_operator_on_creation": True,
        "allow_production_overrides": True,
        "log_apdu_transcript": True,
    },
    "profiles": {
        "preferred_variants": {
            "emv": "dda",
            "mifare": "desfire_ev2",
        },
        "prompt_operator": True,
    },
    "pos": {
        "default_test_plan": [
            "contact",
            "contactless",
            "magstripe_fallback",
            "gratuity_adjustment",
        ],
        "log_terminal_responses": True,
        "auto_run_after_issue": True,
        "run_default_suite": True,
    },
    "atm": {
        "default_test_plan": [
            "cash_withdrawal",
            "balance_inquiry",
            "offline_pin",
        ],
        "default_currency": "USD",
        "auto_run_after_issue": False,
        "run_default_suite": False,
    },
    "hsm": {
        "enabled": False,
        "profile": "simulated",
        "host": "127.0.0.1",
        "port": 1500,
        "default_key_slot": "IMK-DEFAULT",
        "vendors": [],
    },
    "vulnerability_scanning": {
        "enable_cap_checks": True,
        "enable_gp_checks": True,
        "default_suite": [
            "cap_signature",
            "cap_size",
            "gp_transport_keys",
            "gp_default_keyset",
            "card_log_integrity",
            "gp_binary_hash",
        ],
    },
    "logging": {
        "store_on_card": True,
        "ef_identifier": "EFVLOG",
        "max_records": 256,
        "include_apdu_payloads": True,
        "mirror_transaction_log": True,
    },
    "terminal_profiles": [
        {
            "profile_id": "retail_attended",
            "display_name": "Retail POS – Attended",
            "terminal_type": "22",
            "capabilities": {
                "contact": True,
                "contactless": True,
                "offline_pin": True,
                "online_pin": True,
                "signature": True,
            },
            "environment": {
                "merchant_category_code": "5411",
                "currency": "USD",
                "country_code": "840",
                "acquirer_id": "00000012345",
            },
        },
        {
            "profile_id": "atm_high_security",
            "display_name": "ATM – High Security",
            "terminal_type": "21",
            "capabilities": {
                "contact": True,
                "contactless": False,
                "offline_pin": True,
                "online_pin": True,
                "signature": False,
            },
            "environment": {
                "merchant_category_code": "6011",
                "currency": "USD",
                "country_code": "840",
                "acquirer_id": "00000067890",
            },
        },
        {
            "profile_id": "transit_contactless",
            "display_name": "Transit Gate – Contactless",
            "terminal_type": "46",
            "capabilities": {
                "contact": False,
                "contactless": True,
                "offline_pin": False,
                "online_pin": False,
                "signature": False,
            },
            "environment": {
                "merchant_category_code": "4111",
                "currency": "USD",
                "country_code": "840",
                "acquirer_id": "00000024680",
            },
        },
    ],
}

_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent.parent / "config" / "greenwire_config.json"
)


class ConfigurationManager:
    """Thread-safe manager for the GREENWIRE configuration file."""

    _instance: Optional["ConfigurationManager"] = None
    _instance_lock = threading.Lock()

    def __init__(self, path: Optional[Path] = None):
        self._lock = threading.RLock()
        self.config_path = Path(path) if path else _CONFIG_PATH
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._data = self._load()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            self._write(_DEFAULT_CONFIG)
            return deepcopy(_DEFAULT_CONFIG)
        try:
            with self.config_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            data = {}
        merged = deepcopy(_DEFAULT_CONFIG)
        _deep_update(merged, data)
        return merged

    def _write(self, data: Dict[str, Any]) -> None:
        with self.config_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def reload(self) -> Dict[str, Any]:
        with self._lock:
            self._data = self._load()
            return deepcopy(self._data)

    def save(self) -> None:
        with self._lock:
            self._write(self._data)

    def get(self, path: str, default: Any = None) -> Any:
        with self._lock:
            node = self._data
            for segment in path.split("."):
                if isinstance(node, dict) and segment in node:
                    node = node[segment]
                else:
                    return default
            return deepcopy(node)

    def set(self, path: str, value: Any) -> None:
        with self._lock:
            node = self._data
            segments = path.split(".")
            for segment in segments[:-1]:
                node = node.setdefault(segment, {})
            node[segments[-1]] = value
            self.save()

    def update_section(self, section: str, values: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            target = self._data.setdefault(section, {})
            if not isinstance(target, dict):
                raise ValueError(f"Section '{section}' is not a dictionary")
            _deep_update(target, values)
            self.save()
            return deepcopy(target)

    def data(self) -> Dict[str, Any]:
        with self._lock:
            return deepcopy(self._data)

    def reset(self, section: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if section:
                defaults = deepcopy(_DEFAULT_CONFIG.get(section, {}))
                self._data[section] = defaults
                self.save()
                return deepcopy(self._data[section])
            self._data = deepcopy(_DEFAULT_CONFIG)
            self.save()
            return deepcopy(self._data)

    # ------------------------------------------------------------------
    # Convenience helpers for card operations
    # ------------------------------------------------------------------
    def allowed_authentication_modes(self) -> Dict[str, Any]:
        return self.get("cards.authentication_modes", [])

    def default_profile(self) -> str:
        return self.get("cards.default_profile", _DEFAULT_CONFIG["cards"]["default_profile"])

    def default_variant(self) -> str:
        return self.get("cards.default_variant", _DEFAULT_CONFIG["cards"]["default_variant"])

    def store_logs_on_card(self) -> bool:
        return bool(self.get("logging.store_on_card", True))


def _deep_update(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_update(base[key], value)
        else:
            base[key] = value
    return base


def get_configuration_manager() -> ConfigurationManager:
    with ConfigurationManager._instance_lock:
        if ConfigurationManager._instance is None:
            ConfigurationManager._instance = ConfigurationManager()
        return ConfigurationManager._instance


def load_config() -> Dict[str, Any]:
    return get_configuration_manager().data()


def set_config_value(path: str, value: Any) -> None:
    get_configuration_manager().set(path, value)


def update_config_section(section: str, values: Dict[str, Any]) -> Dict[str, Any]:
    return get_configuration_manager().update_section(section, values)


def reset_config(section: Optional[str] = None) -> Dict[str, Any]:
    return get_configuration_manager().reset(section)


__all__ = [
    "ConfigurationManager",
    "get_configuration_manager",
    "load_config",
    "set_config_value",
    "update_config_section",
    "reset_config",
]
