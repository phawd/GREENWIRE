"""Console output customisations for the GREENWIRE toolchain.

This module installs a console output filter that strips emoji and other
non-essential pictographic symbols from interactive output so the interface
remains compliant with audit requirements that prohibit emoji usage.
The module is loaded automatically by Python when present on the import path.
"""

from __future__ import annotations

import builtins
import logging
import unicodedata
from functools import lru_cache

_ORIGINAL_PRINT = builtins.print


@lru_cache(maxsize=None)
def _should_drop(char: str) -> bool:
    """Return True if *char* should be suppressed from console output."""
    codepoint = ord(char)

    # Fast-path ASCII and common control characters
    if codepoint in (9, 10, 13) or 32 <= codepoint <= 126:
        return False

    category = unicodedata.category(char)

    # Drop emoji presentation selectors and variation selectors outright
    if 0xFE00 <= codepoint <= 0xFE0F:
        return True

    # Pictographic ranges that predominantly contain emoji or symbols
    if codepoint >= 0x1F000:
        return True
    if 0x2700 <= codepoint <= 0x27BF:
        return True
    if 0x1F300 <= codepoint <= 0x1FAFF:
        return True

    # Miscellaneous Symbols (2600-26FF) contains weather, zodiac, etc.
    if 0x2600 <= codepoint <= 0x26FF and category == "So":
        return True

    # General fallback: suppress miscellaneous symbols and dingbats that slip
    # through the explicit range checks above.
    if category in {"So", "Sk"}:
        return True

    return False


def _sanitize_argument(arg: object) -> object:
    text = str(arg)
    if not text:
        return text
    if all(not _should_drop(ch) for ch in text):
        return text
    return "".join(ch for ch in text if not _should_drop(ch))


def _sanitized_print(*values, **kwargs):
    sanitized_values = tuple(_sanitize_argument(value) for value in values)
    return _ORIGINAL_PRINT(*sanitized_values, **kwargs)


builtins.print = _sanitized_print


class _EmojiStrippingFilter(logging.Filter):
    """Ensure log records honour the emoji-free output policy."""

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - simple sanitiser
        if isinstance(record.msg, str):
            record.msg = _sanitize_argument(record.msg)
        if record.args:
            record.args = tuple(_sanitize_argument(arg) for arg in record.args)
        return True


logging.getLogger().addFilter(_EmojiStrippingFilter())
