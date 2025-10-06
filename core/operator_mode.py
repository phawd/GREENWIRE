"""Operator mode helpers for GREENWIRE CLI.

Provides ask_operator_mode(args) used by the main CLI to prompt the operator
for SIMULATION vs PRODUCTION and to collect a small set of production
overrides (production dataset, IIN override, Luhn enforcement, CA file,
and generation mode).

This module is intentionally minimal and import-safe so it may be used from
both interactive and non-interactive contexts.
"""
from typing import Any
import os

from greenwire.core.data_manager import choose_dataset_interactive


def ask_operator_mode(args: Any) -> Any:
    """Prompt operator to select simulation or production and populate args.

    Populates:
      - args.operator_mode: 'simulation' or 'production'
      - args.production_options: dict with keys use_dataset, iin_override,
        enforce_luhn, ca_file, generation_mode
    """
    # If caller already set operator_mode and production options, do nothing.
    if (
        getattr(args, 'operator_mode', None)
        and getattr(args, 'production_options', None)
    ):
        return args

    # Prepare defaults from CLI flags where present
    prod_opts = {
        'use_dataset': getattr(args, 'production_dataset', None),
        'iin_override': getattr(args, 'prod_iin', None),
        'enforce_luhn': getattr(args, 'prod_enforce_luhn', True),
        'ca_file': getattr(args, 'prod_ca_file', None),
        'generation_mode': getattr(args, 'prod_generation_mode', 'random')
    }

    # Non-interactive mode: obey flags and decide
    if getattr(args, 'non_interactive', False):
        if (
            prod_opts['use_dataset']
            or prod_opts['iin_override']
            or prod_opts['ca_file']
        ):
            args.operator_mode = 'production'
        else:
            args.operator_mode = 'simulation'
        args.production_options = prod_opts
        return args

    # Interactive: prompt user
    try:
        print("\n🔔 Operator Mode Selection")
        print("  1) Simulation testing (safe default)")
        print("  2) Production (be careful)")
        choice = input('Select mode [1/2, default=1]: ').strip()
        if choice == '2':
            args.operator_mode = 'production'

            # If dataset not provided, allow interactive selection
            if not prod_opts['use_dataset']:
                ds = choose_dataset_interactive()
                if ds:
                    prod_opts['use_dataset'] = ds

            # IIN override prompt
            if not prod_opts['iin_override']:
                iin = input('IIN/BIN override (blank to skip): ').strip()
                if iin:
                    prod_opts['iin_override'] = iin

            # Luhn enforcement
            luhn_ans = input(
                'Enforce Luhn check on generated PANs? [Y/n] (default=Y): '
            ).strip().lower()
            if luhn_ans in ('n', 'no'):
                prod_opts['enforce_luhn'] = False

            # CA file selection
            if not prod_opts['ca_file']:
                default_ca = 'ca_keys.json' if os.path.exists('ca_keys.json') else None
                ca = input(f"CA keys file to use [{default_ca or 'none'}]: ").strip()
                if ca:
                    prod_opts['ca_file'] = ca
                elif default_ca:
                    prod_opts['ca_file'] = default_ca

            # Generation mode
            if not prod_opts.get('generation_mode'):
                gm = input(
                    'Generation mode [random/specific] (default=random): '
                ).strip().lower()
                if gm in ('specific', 's'):
                    prod_opts['generation_mode'] = 'specific'
                else:
                    prod_opts['generation_mode'] = 'random'
        else:
            args.operator_mode = 'simulation'
    except KeyboardInterrupt:
        print('\nOperator selection cancelled - defaulting to simulation')
        args.operator_mode = 'simulation'
    except Exception:
        # Fallback to simulation on any unexpected error
        args.operator_mode = 'simulation'

    args.production_options = prod_opts
    return args
