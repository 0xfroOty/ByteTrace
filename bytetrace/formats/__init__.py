"""
Binary format registry.

The registry holds one instance of every format parser.  Call
``load(path)`` and it returns a fully-populated ``Binary`` without the
caller needing to know which parser handled the file.

Usage
─────
    from bytetrace.formats import load, detect_format

    binary = load(Path("./target"))          # raises on unknown format
    fmt    = detect_format(Path("./target")) # returns parser name or None

Adding a new format
───────────────────
1. Create ``bytetrace/formats/pe.py`` implementing ``BaseParser``.
2. Import and add an instance to ``_PARSERS`` below.
3. Done — ``load()`` will automatically try it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from bytetrace.core.binary import Binary
from bytetrace.formats.base import BaseParser, ParseError
from bytetrace.formats.elf import ELFParser

# ── Ordered parser registry ───────────────────────────────────────
# Parsers are tried in order; first detect() match wins.
# Add PE and Mach-O parsers here in future phases.

_PARSERS: list[BaseParser] = [
    ELFParser(),
    # PEParser(),    # Phase N
    # MachOParser(), # Phase N
]


# ── Public API ────────────────────────────────────────────────────


def load(path: Path) -> Binary:
    """
    Detect the format of *path* and return a fully-parsed ``Binary``.
    Raises
    ------
    ParseError   -- no parser recognised the file, or parsing failed.
    OSError      -- the file could not be read.
    """
    path = Path(path)
    for parser in _PARSERS:
        if parser.detect(path):
            return parser.parse(path)

    raise ParseError(
        f"'{path.name}' is not a recognised binary format.\n"
        f"Supported formats: {', '.join(p.name for p in _PARSERS)}"
    )


def detect_format(path: Path) -> Optional[str]:
    """
    Return the parser name that would handle *path*, or None.

    Never raises -- safe for format sniffing without full parsing.
    """
    path = Path(path)
    for parser in _PARSERS:
        try:
            if parser.detect(path):
                return parser.name
        except Exception:
            pass
    return None


def supported_formats() -> list[str]:
    """Return the names of all registered format parsers."""
    return [p.name for p in _PARSERS]
