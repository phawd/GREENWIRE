"""Command handlers for the emulation subsystem."""

from __future__ import annotations

import argparse
import os
import sys
import time
from contextlib import suppress
from typing import Iterable, List

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from greenwire_modern import CommandResult, GreenwireCLI
from modules.emulation import CardEmulator, TerminalEmulator

DEFAULT_SESSION_SECONDS = 20


def _sanitize_duration(value: int | None) -> int:
    if not value or value <= 0:
        return DEFAULT_SESSION_SECONDS
    return min(int(value), 600)


def _mask_pan(pan: str | None) -> str | None:
    if not pan:
        return None
    digits = ''.join(ch for ch in pan if ch.isdigit())
    if len(digits) <= 10:
        return digits
    return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"


def _resolve_aids(card_types: Iterable[str]) -> List[str]:
    aids: List[str] = []
    for card_type in card_types:
        details = CardEmulator.SUPPORTED_CARDS.get(card_type.lower())
        if details and details.get('aid'):
            aids.append(details['aid'])
    return aids


def _run_emulation_session(emulator, duration: int) -> tuple[bool, str, float]:
    start_time = time.monotonic()
    try:
        if not emulator.start():
            return False, "Emulator already running", 0.0

        end_time = start_time + duration
        while time.monotonic() < end_time:
            time.sleep(min(1.0, end_time - time.monotonic()))

        elapsed = time.monotonic() - start_time
        return True, f"Emulation session completed ({elapsed:.1f}s)", elapsed
    except Exception as exc:  # pragma: no cover - defensive guard against hardware issues
        return False, f"Emulation error: {exc}", time.monotonic() - start_time
    finally:
        with suppress(Exception):
            emulator.stop()


def emulate_terminal(args: argparse.Namespace) -> CommandResult:
    """Run a bounded payment terminal emulation session."""

    card_types = args.card_types or ['visa', 'mastercard']
    duration = _sanitize_duration(args.duration)
    aids = _resolve_aids(card_types)

    config = {
        'mode': 'terminal',
        'wireless': bool(args.wireless),
        'card_types': card_types,
        'authentication': args.auth_mode,
        'amount_limit': args.amount_limit,
        'runtime_seconds': duration,
        'aids': aids,
    }

    if args.dry_run:
        return CommandResult(True, "Terminal emulation configuration validated", data=config)

    emulator = TerminalEmulator(
        contactless=bool(args.wireless),
        contact=True,
        aids=aids,
        terminal_type=args.auth_mode,
    )

    success, message, elapsed = _run_emulation_session(emulator, duration)
    config['runtime_seconds'] = max(duration, int(elapsed))

    return CommandResult(success=success, message=message, data=config, exit_code=0 if success else 1)


def emulate_card(args: argparse.Namespace) -> CommandResult:
    """Run a bounded payment card emulation session."""

    duration = _sanitize_duration(args.duration)
    masked_pan = _mask_pan(args.pan)

    config = {
        'mode': 'card',
        'card_type': args.card_type,
        'pan': masked_pan,
        'uid': args.uid,
        'contactless': bool(args.contactless),
        'runtime_seconds': duration,
    }

    if args.dry_run:
        return CommandResult(True, "Card emulation configuration validated", data=config)

    emulator = CardEmulator(
        card_type=args.card_type,
        wireless=bool(args.contactless),
        uid=args.uid,
    )

    success, message, elapsed = _run_emulation_session(emulator, duration)
    config['runtime_seconds'] = max(duration, int(elapsed))

    return CommandResult(success=success, message=message, data=config, exit_code=0 if success else 1)


def register_emulation_commands(cli: GreenwireCLI):
    """Register emulation commands with the CLI."""

    cli.register_command(
        name='emulate-terminal',
        func=emulate_terminal,
        description='Run a payment terminal emulation session',
        args=[
            {'name': '--wireless', 'action': 'store_true', 'help': 'Enable contactless mode'},
            {'name': '--card-types', 'nargs': '+', 'help': 'Card profiles to advertise'},
            {'name': '--auth-mode', 'choices': ['pin', 'signature', 'contactless'], 'default': 'pin'},
            {'name': '--amount-limit', 'type': float, 'default': 100.0, 'help': 'Transaction limit'},
            {'name': '--duration', 'type': int, 'default': DEFAULT_SESSION_SECONDS, 'help': 'Session length in seconds'},
        ],
        aliases=['terminal']
    )

    cli.register_command(
        name='emulate-card',
        func=emulate_card,
        description='Run a payment card emulation session',
        args=[
            {'name': '--card-type', 'choices': list(CardEmulator.SUPPORTED_CARDS.keys()), 'default': 'visa'},
            {'name': '--pan', 'type': str, 'help': 'Primary Account Number used for metadata'},
            {'name': '--uid', 'type': str, 'help': 'Card UID (hex-encoded)'},
            {'name': '--contactless', 'action': 'store_true', 'help': 'Enable contactless mode'},
            {'name': '--duration', 'type': int, 'default': DEFAULT_SESSION_SECONDS, 'help': 'Session length in seconds'},
        ],
        aliases=['card']
    )
