from __future__ import annotations

import argparse
import subprocess
from typing import Dict, List, Optional

from core.globalplatform_reference import list_test_key_profiles
from core.gp_session_planner import build_gp_session_plan
from greenwire_modern import CommandResult, GreenwireCLI


def _run_step(gp_jar: str, step: Dict[str, object]) -> Dict[str, object]:
    args = [str(item) for item in step["args"]]
    command = ["java", "-jar", gp_jar] + args
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    return {
        "name": step["name"],
        "command": command,
        "destructive": bool(step.get("destructive", False)),
        "return_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "success": result.returncode == 0,
    }


def _expand_scps(value: str) -> List[str]:
    if value == "both":
        return ["scp02", "scp03"]
    return [value]


def _is_test_invocation(args: argparse.Namespace) -> bool:
    command_name = str(getattr(args, "command", "") or "")
    return "test" in command_name.lower()


def gp_session(args: argparse.Namespace) -> CommandResult:
    is_test_invocation = _is_test_invocation(args)

    if args.action == "profiles":
        if not is_test_invocation:
            return CommandResult(
                False,
                "Test key profiles are only available through an explicit test command",
            )
        return CommandResult(True, "GlobalPlatform key profiles listed", data={"profiles": list_test_key_profiles()})

    if args.session == "test" and not is_test_invocation:
        return CommandResult(
            False,
            "Test GP sessions require an explicit test command such as gp-test-session",
        )

    if args.key_profile != "default" and not is_test_invocation:
        return CommandResult(
            False,
            "Test key profiles require an explicit test command such as gp-test-session",
        )

    if args.session == "production" and is_test_invocation:
        return CommandResult(
            False,
            "Production GP sessions must use the non-test gp-session command",
        )

    production_keys: Optional[Dict[str, str]] = None
    if args.session == "production":
        production_keys = {
            "enc": args.key_enc,
            "mac": args.key_mac,
            "dek": args.key_dek,
        }

    plans = []
    executions = []
    for scp in _expand_scps(args.scp):
        plan = build_gp_session_plan(
            scp=scp,
            key_profile=args.key_profile,
            session_type=args.session,
            cap_file=args.cap_file,
            applet_aid=args.applet_aid,
            package_aid=args.package_aid,
            instance_aid=args.instance_aid,
            install_params=args.install_params,
            personalization_data=args.personalization_data,
            production_keys=production_keys,
            new_key_version=args.new_key_version,
            new_key_hex=args.new_key_hex,
            reader=args.reader,
        )
        plans.append(plan)

        if not args.execute:
            continue

        gp_jar = str(plan["gp_jar"])
        step_results = []
        for step in plan["steps"]:
            if step.get("destructive") and not args.allow_destructive:
                step_results.append(
                    {
                        "name": step["name"],
                        "skipped": True,
                        "reason": "destructive step requires --allow-destructive",
                    }
                )
                continue
            step_results.append(_run_step(gp_jar, step))
        executions.append({"scp": scp, "steps": step_results})

    message = "GlobalPlatform session plan generated"
    if args.execute:
        failures = [
            step
            for execution in executions
            for step in execution["steps"]
            if isinstance(step, dict) and step.get("success") is False
        ]
        message = "GlobalPlatform session execution completed"
        if failures:
            return CommandResult(
                False,
                "GlobalPlatform session execution completed with failures",
                data={"plans": plans, "executions": executions},
            )

    return CommandResult(
        True,
        message,
        data={
            "plans": plans,
            "executions": executions,
        },
    )


def register_gp_commands(cli: GreenwireCLI) -> None:
    cli.register_command(
        name="gp-session",
        func=gp_session,
        description="Plan or execute production SCP02/SCP03 GlobalPlatform install and personalization sessions",
        args=[
            {"name": "action", "nargs": "?", "choices": ["run", "profiles"], "default": "run"},
            {"name": "--scp", "choices": ["scp02", "scp03", "both"], "default": "both"},
            {"name": "--session", "choices": ["test", "production"], "default": "production"},
            {"name": "--key-profile", "choices": ["default", "emv_default", "gemalto_visa2"], "default": "default"},
            {"name": "--cap-file", "type": str, "help": "CAP file to load and install"},
            {"name": "--applet-aid", "type": str, "help": "Applet AID for install"},
            {"name": "--package-aid", "type": str, "help": "Package AID for install"},
            {"name": "--instance-aid", "type": str, "help": "Instance AID for create"},
            {"name": "--install-params", "type": str, "help": "Installation parameters as hex"},
            {"name": "--personalization-data", "type": str, "help": "STORE DATA blob as hex"},
            {"name": "--reader", "type": str, "help": "PC/SC reader name"},
            {"name": "--execute", "action": "store_true", "help": "Execute the planned GP session"},
            {"name": "--allow-destructive", "action": "store_true", "help": "Allow production key rotation steps"},
            {"name": "--key-enc", "type": str, "help": "Production SCP ENC key"},
            {"name": "--key-mac", "type": str, "help": "Production SCP MAC key"},
            {"name": "--key-dek", "type": str, "help": "Production SCP DEK key"},
            {"name": "--new-key-version", "type": int, "help": "New key version for rotation"},
            {"name": "--new-key-hex", "type": str, "help": "Replacement key value for --lock"},
        ],
        aliases=["gp-install", "gp-personalize"],
    )
    cli.register_command(
        name="gp-test-session",
        func=gp_session,
        description="Plan or execute test SCP02/SCP03 GlobalPlatform sessions with lab key profiles",
        args=[
            {"name": "action", "nargs": "?", "choices": ["run", "profiles"], "default": "run"},
            {"name": "--scp", "choices": ["scp02", "scp03", "both"], "default": "both"},
            {"name": "--session", "choices": ["test"], "default": "test"},
            {"name": "--key-profile", "choices": ["default", "emv_default", "gemalto_visa2"], "default": "default"},
            {"name": "--cap-file", "type": str, "help": "CAP file to load and install"},
            {"name": "--applet-aid", "type": str, "help": "Applet AID for install"},
            {"name": "--package-aid", "type": str, "help": "Package AID for install"},
            {"name": "--instance-aid", "type": str, "help": "Instance AID for create"},
            {"name": "--install-params", "type": str, "help": "Installation parameters as hex"},
            {"name": "--personalization-data", "type": str, "help": "STORE DATA blob as hex"},
            {"name": "--reader", "type": str, "help": "PC/SC reader name"},
            {"name": "--execute", "action": "store_true", "help": "Execute the planned GP session"},
            {"name": "--allow-destructive", "action": "store_true", "help": "Allow destructive test steps if ever added"},
            {"name": "--key-enc", "type": str, "help": "Unused in test mode"},
            {"name": "--key-mac", "type": str, "help": "Unused in test mode"},
            {"name": "--key-dek", "type": str, "help": "Unused in test mode"},
            {"name": "--new-key-version", "type": int, "help": "Unused in test mode unless explicit rotation is added"},
            {"name": "--new-key-hex", "type": str, "help": "Unused in test mode unless explicit rotation is added"},
        ],
        aliases=["gp-test-install", "gp-test-personalize"],
    )
