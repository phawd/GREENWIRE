"""
GREENWIRE Modern CLI - Commands Package

This package contains the command modules that bridge the modern CLI
with the core logic of the GREENWIRE framework.
"""

def get_cap_command():
    """Return the CAP management command instance."""

    from .cap_management import get_command

    return get_command()


def get_pipeline_command():
    """Return the issuer pipeline command instance."""

    from .issuer_pipeline import get_command

    return get_command()


def get_rfid_command():
    """Return the RFID testing command instance."""

    from .rfid_testing import get_command

    return get_command()


def register_all_commands(cli):
    """Register command modules that plug directly into the modern CLI."""

    registrars = [
        ("card", "register_card_commands"),
        ("crypto", "register_crypto_commands"),
        ("emulation", "register_emulation_commands"),
        ("fuzz", "register_fuzz_commands"),
        ("nfc", "register_nfc_commands"),
        ("security", "register_security_commands"),
    ]

    for module_name, registrar_name in registrars:
        try:
            module = __import__(f"commands.{module_name}_commands", fromlist=[registrar_name])
            registrar = getattr(module, registrar_name)
            registrar(cli)
        except Exception as exc:
            cli.logger.warning("Skipping %s commands: %s", module_name, exc)

__all__ = [
    'get_cap_command', 'get_pipeline_command', 'get_rfid_command', 'register_all_commands'
]
