from __future__ import annotations

from argparse import Namespace

from commands.gp_commands import gp_session


def _base_args(**overrides):
    data = {
        "action": "run",
        "scp": "both",
        "session": "test",
        "key_profile": "default",
        "cap_file": None,
        "applet_aid": None,
        "package_aid": None,
        "instance_aid": None,
        "install_params": None,
        "personalization_data": None,
        "reader": None,
        "execute": False,
        "allow_destructive": False,
        "key_enc": None,
        "key_mac": None,
        "key_dek": None,
        "new_key_version": None,
        "new_key_hex": None,
        "command": "gp-test-session",
    }
    data.update(overrides)
    return Namespace(**data)


def test_gp_session_builds_both_scp_plans() -> None:
    result = gp_session(_base_args())
    assert result.success is True
    plans = result.data["plans"]
    assert [plan["scp"] for plan in plans] == ["scp02", "scp03"]
    assert all(plan["steps"][0]["name"] == "tool-version" for plan in plans)


def test_gp_session_includes_install_and_personalization_steps() -> None:
    result = gp_session(
        _base_args(
            scp="scp02",
            cap_file="sample.cap",
            applet_aid="A00000000101",
            package_aid="A000000001",
            instance_aid="A00000000102",
            install_params="C900",
            personalization_data="01020304",
        )
    )
    steps = result.data["plans"][0]["steps"]
    names = [step["name"] for step in steps]
    assert "load-cap" in names
    assert "install-cap" in names
    assert "personalize" in names


def test_gp_session_production_plan_requires_explicit_keys() -> None:
    result = gp_session(
        _base_args(
            scp="scp03",
            command="gp-session",
            session="production",
            key_enc="00112233445566778899AABBCCDDEEFF",
            key_mac="11112222333344445555666677778888",
            key_dek="9999AAAABBBBCCCCDDDDEEEEFFFF0000",
            new_key_version=1,
            new_key_hex="0102030405060708090A0B0C0D0E0F10",
        )
    )
    steps = result.data["plans"][0]["steps"]
    assert any(step["name"] == "rotate-keys" and step["destructive"] for step in steps)


def test_gp_session_rejects_test_mode_without_test_command() -> None:
    result = gp_session(_base_args(command="gp-session"))
    assert result.success is False
    assert "gp-test-session" in result.message
