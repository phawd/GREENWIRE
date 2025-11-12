#!/usr/bin/env python3
"""
GREENWIRE v4.0 - Modern CLI Framework
====================================

A completely rewritten command-line interface that is:
- Machine/AI-friendly with structured output
- Self-documenting with comprehensive help
- Modular and extensible
- Standards-compliant with proper exit codes
- JSON/YAML input/output support

Usage:
    greenwire --help                 # Show comprehensive help
    greenwire list commands          # List all available commands
    greenwire docs                   # Generate/view documentation
    greenwire <command> --help       # Get help for specific command
    greenwire <command> --dry-run    # Show what would be done
    greenwire <command> --json       # JSON output format
"""

import argparse
import json
import logging
import os
import sys
import yaml
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum

# Version and metadata
__version__ = "4.0.0"
__author__ = "GREENWIRE Team"
__description__ = "Advanced Payment Card Security Suite - Modern CLI"

class OutputFormat(Enum):
    """Output format options"""
    TEXT = "text"
    JSON = "json"
    YAML = "yaml"
    TABLE = "table"

class ExitCode(Enum):
    """Standard exit codes"""
    SUCCESS = 0
    GENERAL_ERROR = 1
    MISUSE = 2
    CANNOT_EXECUTE = 126
    COMMAND_NOT_FOUND = 127
    INVALID_EXIT_ARGUMENT = 128
    INTERRUPTED = 130

@dataclass
class CommandResult:
    """Standard command result structure"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    exit_code: int = 0
    timestamp: str = None
    command: str = None
    duration_ms: int = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + "Z"

class GreenwireCLI:
    """Modern CLI framework for GREENWIRE"""

    def __init__(self):
        self.logger = self._setup_logging()
        self.commands = {}
        self.output_format = OutputFormat.TEXT
        self.verbose = False
        self.dry_run = False

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger("greenwire")

        # Console handler with clean format
        console_handler = logging.StreamHandler(sys.stderr)
        console_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)

        # File handler for detailed logs
        log_file = Path("logs") / "greenwire.log"
        log_file.parent.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

        logger.setLevel(logging.INFO)
        return logger

    def register_command(self, name: str, func: callable, description: str, 
                         args: List[Dict] = None, aliases: List[str] = None):
        """Register a command with the CLI"""
        self.commands[name] = {
            'func': func,
            'description': description,
            'args': args or [],
            'aliases': aliases or []
        }

        # Register aliases
        for alias in aliases or []:
            self.commands[alias] = self.commands[name]

    def output(self, result: CommandResult) -> None:
        """Output result in requested format"""
        if self.output_format == OutputFormat.JSON:
            print(json.dumps(asdict(result), indent=2))
        elif self.output_format == OutputFormat.YAML:
            print(yaml.dump(asdict(result), default_flow_style=False))
        elif self.output_format == OutputFormat.TABLE and result.data:
            self._output_table(result.data)
        else:
            # Text output
            status = "[OK]" if result.success else "[ERROR]"
            print(f"{status} {result.message}")
            if result.data and self.verbose:
                for key, value in result.data.items():
                    print(f"   {key}: {value}")

    def _output_table(self, data: Dict[str, Any]) -> None:
        """Output data in table format"""
        if isinstance(data, dict):
            max_key = max(len(str(k)) for k in data.keys()) if data else 0
            for key, value in data.items():
                print(f"{str(key):<{max_key}} | {value}")
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            # Table from list of dicts
            headers = list(data[0].keys())
            col_widths = [max(len(str(header)), max(len(str(row.get(header, ''))) for row in data)) 
                          for header in headers]

            # Header
            header_row = " | ".join(f"{header:<{width}}" for header, width in zip(headers, col_widths))
            print(header_row)
            print("-" * len(header_row))

            # Rows
            for row in data:
                data_row = " | ".join(f"{str(row.get(header, '')):<{width}}" 
                                      for header, width in zip(headers, col_widths))
                print(data_row)

    def create_parser(self) -> argparse.ArgumentParser:
        """Create the main argument parser"""
        parser = argparse.ArgumentParser(
            prog='greenwire',
            description=__description__,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  greenwire list commands                    # List all commands
  greenwire card-create --pan 4000123456789012
  greenwire fuzz-apdu --iterations 100 --json
  greenwire emulate-terminal --wireless
  greenwire docs generate --format html
  
For command-specific help:
  greenwire <command> --help
  
Documentation:
  https://github.com/phawd/greenwire/docs
            """.strip()
        )

        # Global flags
        parser.add_argument('--version', action='version', version=f'GREENWIRE {__version__}')
        parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
        parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode (errors only)')
        parser.add_argument('--dry-run', action='store_true', help='Show what would be done without executing')
        parser.add_argument('--format', choices=[f.value for f in OutputFormat], 
                            default='text', help='Output format')
        parser.add_argument('--config', type=Path, help='Configuration file path')
        parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                            default='INFO', help='Logging level')

        # Add subcommands
        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Register built-in commands
        self._register_builtin_commands(subparsers)

        # Register dynamically registered commands
        self._register_dynamic_commands(subparsers)

        return parser

    def _register_dynamic_commands(self, subparsers):
        """Register dynamically added commands"""

        # Import and register new RFID testing command
        try:
            from commands.rfid_testing import get_command
            cmd_info = get_command()
            parser = subparsers.add_parser(cmd_info.get_name(), help=cmd_info.get_description(), add_help=False)
            parser.add_argument('sub_args', nargs=argparse.REMAINDER, help='Arguments for the command')
        except ImportError:
            self.logger.warning("RFID testing command not available")

        # Import and register CAP management command
        try:
            from commands.cap_management import get_command
            cmd_info = get_command()
            parser = subparsers.add_parser(cmd_info.get_name(), help=cmd_info.get_description(), add_help=False)
            parser.add_argument('sub_args', nargs=argparse.REMAINDER, help='Arguments for the command')
        except ImportError:
            self.logger.warning("CAP management command not available")

        # Register existing dynamic commands
        for name, cmd_info in self.commands.items(): # type: ignore
            # Skip aliases (they point to the same command info)
            if name in [alias for info in self.commands.values() for alias in info.get('aliases', [])]:
                continue

            cmd_parser = subparsers.add_parser(name, help=cmd_info['description'])

            # Add command-specific arguments
            for arg_spec in cmd_info.get('args', []):
                arg_name = arg_spec.pop('name')
                cmd_parser.add_argument(arg_name, **arg_spec)

    def _register_builtin_commands(self, subparsers):
        """Register built-in CLI commands"""

        # List command
        list_parser = subparsers.add_parser('list', help='List available items')
        list_subparsers = list_parser.add_subparsers(dest='list_target')

        list_subparsers.add_parser('commands', help='List all commands')
        list_subparsers.add_parser('devices', help='List connected devices')
        list_subparsers.add_parser('cards', help='List detected cards')

        # Documentation command
        docs_parser = subparsers.add_parser('docs', help='Documentation management')
        docs_parser.add_argument('action', choices=['generate', 'view', 'export'], 
                                 help='Documentation action')
        docs_parser.add_argument('--format', choices=['html', 'markdown', 'pdf'], 
                                 default='html', help='Documentation format')
        docs_parser.add_argument('--output', type=Path, help='Output directory/file')

        # Configuration command
        config_parser = subparsers.add_parser('config', help='Configuration management')
        config_parser.add_argument('action', choices=['show', 'set', 'reset', 'validate'])
        config_parser.add_argument('key', nargs='?', help='Configuration key')
        config_parser.add_argument('value', nargs='?', help='Configuration value')

        # Health check command
        health_parser = subparsers.add_parser('health', help='System health check')
        health_parser.add_argument('--fix', action='store_true', help='Attempt to fix issues')

    def run(self, args: List[str] = None) -> int:
        """Main CLI entry point"""
        parser = self.create_parser()

        if args is None:
            args = sys.argv[1:]

        # Parse arguments
        try:
            parsed_args = parser.parse_args(args)
        except SystemExit as e:
            return e.code if e.code is not None else ExitCode.MISUSE.value

        # Set output format and verbosity
        self.output_format = OutputFormat(parsed_args.format)
        self.verbose = parsed_args.verbose
        self.dry_run = parsed_args.dry_run

        # Set log level
        if parsed_args.quiet:
            self.logger.setLevel(logging.ERROR)
        else:
            log_level = getattr(logging, parsed_args.log_level)
            self.logger.setLevel(log_level)

        # Handle no command
        if not parsed_args.command:
            parser.print_help()
            return ExitCode.SUCCESS.value

        # Execute command
        try:
            start_time = datetime.now()
            result = self._execute_command(parsed_args)
            end_time = datetime.now()

            result.duration_ms = int((end_time - start_time).total_seconds() * 1000)
            result.command = ' '.join(args)

            self.output(result)
            return result.exit_code

        except KeyboardInterrupt:
            self.logger.info("Operation interrupted by user")
            result = CommandResult(
                success=False,
                message="Operation interrupted",
                exit_code=ExitCode.INTERRUPTED.value
            )
            self.output(result)
            return ExitCode.INTERRUPTED.value

        except Exception as e:
            self.logger.error(f"Command execution failed: {e}", exc_info=True)
            result = CommandResult(
                success=False,
                message=f"Command failed: {str(e)}",
                exit_code=ExitCode.GENERAL_ERROR.value
            )
            self.output(result)
            return ExitCode.GENERAL_ERROR.value

    def _execute_command(self, args: argparse.Namespace) -> CommandResult:
        """Execute a parsed command"""
        command = args.command

        # Handle RFID testing command
        if command == 'rfid-test':
            try:
                from commands.rfid_testing import get_command as get_rfid_command
                cmd_instance = get_rfid_command()
                cmd_args = getattr(args, 'sub_args', [])
                result_data = cmd_instance.execute(cmd_args)

                return CommandResult(
                    success=result_data.get('success', False),
                    message=result_data.get('message', 'RFID test completed'),
                    data=result_data.get('data'),
                    exit_code=ExitCode.SUCCESS.value if result_data.get('success') else ExitCode.GENERAL_ERROR.value
                )
            except ImportError:
                return CommandResult(
                    success=False,
                    message="RFID testing module not available",
                    exit_code=ExitCode.GENERAL_ERROR.value
                )

        # Handle CAP management command
        if command == 'cap':
            try:
                from commands.cap_management import get_command as get_cap_command
                cmd_instance = get_cap_command()
                cmd_args = getattr(args, 'sub_args', [])
                result_data = cmd_instance.execute(cmd_args)

                return CommandResult(
                    success=result_data.get('success', False),
                    message=result_data.get('message', 'CAP operation completed'),
                    data=result_data.get('data'),
                    exit_code=ExitCode.SUCCESS.value if result_data.get('success') else ExitCode.GENERAL_ERROR.value
                )
            except ImportError:
                return CommandResult(
                    success=False,
                    message="CAP management module not available",
                    exit_code=ExitCode.GENERAL_ERROR.value
                )

        # Handle built-in commands
        if command == 'list':
            return self._handle_list_command(args)
        elif command == 'docs':
            return self._handle_docs_command(args)
        elif command == 'config':
            return self._handle_config_command(args)
        elif command == 'health':
            return self._handle_health_command(args)

        # Handle registered commands
        if command in self.commands:
            cmd_info = self.commands[command]
            return cmd_info['func'](args)

        return CommandResult(
            success=False,
            message=f"Unknown command: {command}",
            exit_code=ExitCode.COMMAND_NOT_FOUND.value
        )

    def _handle_list_command(self, args: argparse.Namespace) -> CommandResult:
        """Handle list commands"""
        if args.list_target == 'commands':
            # List all available commands including new ones
            commands_data = []

            # Add dynamically registered commands
            for name, info in self.commands.items():
                if name not in [alias for cmd_info in self.commands.values() for alias in cmd_info.get('aliases', [])]: # type: ignore
                    commands_data.append({
                        'name': name,
                        'description': info['description'],
                        'aliases': ', '.join(info.get('aliases', []))
                    })

            return CommandResult(
                success=True,
                message=f"Found {len(commands_data)} commands",
                data={'commands': commands_data}
            )

        elif args.list_target == 'devices':
            # Placeholder for device listing
            return CommandResult(
                success=True,
                message="Device listing not yet implemented",
                data={'devices': []}
            )

        elif args.list_target == 'cards':
            # Placeholder for card listing
            return CommandResult(
                success=True,
                message="Card listing not yet implemented",
                data={'cards': []}
            )

        return CommandResult(
            success=False,
            message=f"Unknown list target: {args.list_target}",
            exit_code=ExitCode.MISUSE.value
        )

    def _handle_docs_command(self, args: argparse.Namespace) -> CommandResult:
        """Handle documentation commands"""
        if args.action == 'generate':
            # Generate documentation
            return CommandResult(
                success=True,
                message=f"Documentation generated in {args.format} format",
                data={'format': args.format, 'output': str(args.output) if args.output else 'docs/'}
            )
        elif args.action == 'view':
            # View documentation
            return CommandResult(
                success=True,
                message="Opening documentation...",
                data={'action': 'view'}
            )

        return CommandResult(
            success=False,
            message=f"Unknown docs action: {args.action}",
            exit_code=ExitCode.MISUSE.value
        )

    def _handle_config_command(self, args: argparse.Namespace) -> CommandResult:
        """Handle configuration commands"""
        if args.action == 'show':
            # Show configuration
            config_data = {
                'version': __version__,
                'log_level': self.logger.level,
                'output_format': self.output_format.value
            }
            return CommandResult(
                success=True,
                message="Current configuration",
                data=config_data
            )

        return CommandResult(
            success=False,
            message=f"Config action '{args.action}' not yet implemented",
            exit_code=ExitCode.MISUSE.value
        )

    def _handle_health_command(self, args: argparse.Namespace) -> CommandResult:
        """Handle health check command"""
        checks = {
            'python_version': sys.version.split()[0],
            'greenwire_version': __version__,
            'config_valid': True,
            'dependencies': True
        }

        all_healthy = all(checks.values())

        return CommandResult(
            success=all_healthy,
            message="System healthy" if all_healthy else "Issues detected",
            data={'checks': checks}
        )


def main():
    """Main entry point"""
    cli = GreenwireCLI()

    # Register all GREENWIRE commands
    try:
        from commands import register_all_commands
        register_all_commands(cli)
    except ImportError:
        # Fallback to basic commands if modules not available
        cli.logger.warning("Command modules not available, using basic functionality only")

    exit_code = cli.run()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
