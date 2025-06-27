"""Menu-based CLI for GREENWIRE tools.

This module provides a simple menu system with three subsystems:
- generation: create sample cards, keys, and related data
- attack: fuzzing and other advanced attack attempts
- dump: reading, dumping, or cloning card content

Each subsystem defines a set of stub tools. The actual security
functionality is outside the scope of this environment, so each tool
simply logs that it was invoked. This structure demonstrates how a
full-featured tool menu could be organized.
"""

from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from typing import Callable, Dict


@dataclass
class Tool:
    """Representation of a single CLI tool."""

    name: str
    description: str
    func: Callable[[argparse.Namespace], None]


# ---------------------------------------------------------------------------
# Stub actions
# ---------------------------------------------------------------------------

def _stub_action(args: argparse.Namespace) -> None:
    """Default action for stub tools."""
    logging.info("Executing %s", args.tool)


# Build tool lists with at least 30 entries per subsystem
GENERATION_TOOLS: Dict[str, Tool] = {
    f"gen_tool_{i}": Tool(
        name=f"gen_tool_{i}",
        description=f"Generation tool number {i}",
        func=_stub_action,
    )
    for i in range(1, 31)
}

ATTACK_TOOLS: Dict[str, Tool] = {
    f"atk_tool_{i}": Tool(
        name=f"atk_tool_{i}",
        description=f"Attack tool number {i}",
        func=_stub_action,
    )
    for i in range(1, 31)
}

DUMP_TOOLS: Dict[str, Tool] = {
    f"dump_tool_{i}": Tool(
        name=f"dump_tool_{i}",
        description=f"Dump tool number {i}",
        func=_stub_action,
    )
    for i in range(1, 31)
}

MENU_MAP = {
    "generate": GENERATION_TOOLS,
    "attack": ATTACK_TOOLS,
    "dump": DUMP_TOOLS,
}


# ---------------------------------------------------------------------------
# CLI Helpers
# ---------------------------------------------------------------------------

def configure_logging(verbosity: int) -> None:
    """Setup logging according to verbosity level."""
    levels = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
        3: logging.NOTSET,
    }
    level = levels.get(verbosity, logging.NOTSET)
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(description="GREENWIRE Menu CLI")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (use up to -vvv)",
    )

    subparsers = parser.add_subparsers(dest="subsystem", required=True)

    for name, tools in MENU_MAP.items():
        sub = subparsers.add_parser(name, help=f"{name} subsystem tools")
        sub.add_argument(
            "tool",
            choices=sorted(tools.keys()),
            help="Tool to execute",
        )

    return parser


def main(argv: list[str] | None = None) -> None:
    """Entry point for command line execution."""
    parser = create_parser()
    args = parser.parse_args(argv)
    configure_logging(min(args.verbose, 3))

    tools = MENU_MAP[args.subsystem]
    tool = tools[args.tool]
    logging.debug("Selected subsystem: %s", args.subsystem)
    logging.debug("Selected tool: %s", args.tool)
    tool.func(args)


if __name__ == "__main__":
    main()
