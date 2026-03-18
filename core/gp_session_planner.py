from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

from core.globalplatform_reference import get_test_key_profile, resolve_gp_jar


@dataclass
class GPStep:
    name: str
    args: List[str]
    destructive: bool = False

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _format_hex(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = "".join(ch for ch in value if ch.strip()).upper()
    return cleaned or None


def _build_key_args(
    *,
    scp: str,
    key_profile: str,
    production_keys: Optional[Dict[str, str]] = None,
    key_version: int = 0,
) -> List[str]:
    if production_keys:
        enc = _format_hex(production_keys.get("enc"))
        mac = _format_hex(production_keys.get("mac"))
        dek = _format_hex(production_keys.get("dek"))
        if not (enc and mac and dek):
            raise ValueError("Production SCP keys require enc, mac, and dek values")
        args = [
            "--key-enc",
            enc,
            "--key-mac",
            mac,
            "--key-dek",
            dek,
            "--key-ver",
            str(key_version),
        ]
        if scp == "scp03":
            args.append("--s16")
        return args

    profile = get_test_key_profile(key_profile)
    if scp not in profile.protocols:
        raise ValueError(f"Key profile '{key_profile}' does not support {scp}")

    if profile.diversification == "none":
        args = ["--key", profile.key_hex, "--key-ver", str(key_version)]
    else:
        alias = "default" if profile.name == "emv_default" else profile.key_hex
        args = ["--key", f"{profile.diversification}:{alias}", "--key-ver", str(key_version)]
    if scp == "scp03":
        args.append("--s16")
    return args


def build_gp_session_plan(
    *,
    scp: str,
    key_profile: str = "default",
    session_type: str = "test",
    cap_file: Optional[str] = None,
    applet_aid: Optional[str] = None,
    package_aid: Optional[str] = None,
    instance_aid: Optional[str] = None,
    install_params: Optional[str] = None,
    personalization_data: Optional[str] = None,
    production_keys: Optional[Dict[str, str]] = None,
    new_key_version: Optional[int] = None,
    new_key_hex: Optional[str] = None,
    reader: Optional[str] = None,
) -> Dict[str, object]:
    if scp not in {"scp02", "scp03"}:
        raise ValueError("scp must be one of: scp02, scp03")
    if session_type not in {"test", "production"}:
        raise ValueError("session_type must be one of: test, production")

    gp_jar = resolve_gp_jar(Path.cwd())
    if gp_jar is None:
        raise FileNotFoundError("GlobalPlatformPro jar not found")

    key_args = _build_key_args(
        scp=scp,
        key_profile=key_profile,
        production_keys=production_keys if session_type == "production" else None,
        key_version=0,
    )
    reader_args = ["--reader", reader] if reader else []

    steps: List[GPStep] = [
        GPStep(name="tool-version", args=["--version"]),
        GPStep(name="card-list", args=reader_args + key_args + ["--list"]),
        GPStep(name="card-info", args=reader_args + key_args + ["--info"]),
    ]

    if cap_file:
        load_args = reader_args + key_args + ["--load", cap_file]
        steps.append(GPStep(name="load-cap", args=load_args))

        install_target = cap_file
        install_args = reader_args + key_args + ["--install", install_target]
        if applet_aid:
            install_args.extend(["--applet", applet_aid])
        if package_aid:
            install_args.extend(["--package", package_aid])
        if instance_aid:
            install_args.extend(["--create", instance_aid])
        if install_params:
            install_args.extend(["--params", _format_hex(install_params) or ""])
        steps.append(GPStep(name="install-cap", args=install_args))

    if personalization_data:
        steps.append(
            GPStep(
                name="personalize",
                args=reader_args + key_args + ["--store-data", _format_hex(personalization_data) or ""],
            )
        )

    if session_type == "production" and new_key_version is not None and new_key_hex:
        rotated_key = _format_hex(new_key_hex)
        steps.append(
            GPStep(
                name="rotate-keys",
                args=reader_args
                + key_args
                + ["--lock", rotated_key, "--new-keyver", str(new_key_version)],
                destructive=True,
            )
        )

    return {
        "scp": scp,
        "session_type": session_type,
        "key_profile": key_profile,
        "gp_jar": str(gp_jar),
        "steps": [step.to_dict() for step in steps],
    }
