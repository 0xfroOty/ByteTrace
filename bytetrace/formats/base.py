"""
Abstract base class for binary format parsers.

Every supported format (ELF, PE, Mach-O) provides one concrete
subclass.  The format registry in ``formats/__init__.py`` holds one
instance of each parser and calls ``detect()`` first, then ``parse()``.

Rules for implementors
──────────────────────
• ``detect()`` must be fast and side-effect-free — read at most ~16 bytes.
• ``detect()`` must never raise; return False on any I/O problem.
• ``parse()`` must return a fully-populated ``Binary`` or raise ``ParseError``.
• Neither method may touch the CLI or produce any output.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from bytetrace.core.binary import Binary


class ParseError(Exception):
    """Raised when a parser cannot understand the file it was given."""


class BaseParser(ABC):
    """Interface that every binary-format parser must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short display name, e.g. ``'ELF'``."""

    @abstractmethod
    def detect(self, path: Path) -> bool:
        """
        Return True if this parser handles *path*.

        Reads only magic bytes — no full parsing, no exceptions.
        """

    @abstractmethod
    def parse(self, path: Path) -> Binary:
        """
        Parse *path* fully and return a populated ``Binary``.

        Raises
        ──────
        ParseError  — file is corrupt or uses an unsupported variant.
        OSError     — file cannot be opened or read.
        """
