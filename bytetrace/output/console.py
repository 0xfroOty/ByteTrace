"""
Console abstraction for ByteTrace terminal output.

Wraps Rich when it is installed (the production path) and falls back
to a thin ANSI-aware writer when it is not.  Every rendering module
imports ``make_console()`` rather than touching Rich or sys.stdout
directly — this keeps the Rich dependency soft and the code testable.

Usage
─────
    from bytetrace.output.console import make_console

    console = make_console(no_color=ctx.obj.get("no_color", False))
    console.print("[bold cyan]Hello[/bold cyan]")   # Rich markup
    console.print_raw("plain text")                  # always plain
"""

from __future__ import annotations

import sys
from typing import Any


# ── ANSI escape helpers (used by the fallback renderer) ───────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RED    = "\033[31m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"
_WHITE  = "\033[37m"

# Subset of Rich markup tags → ANSI codes understood by the fallback.
_MARKUP_TO_ANSI: dict[str, str] = {
    "bold":        _BOLD,
    "dim":         _DIM,
    "red":         _RED,
    "green":       _GREEN,
    "yellow":      _YELLOW,
    "cyan":        _CYAN,
    "bold cyan":   _BOLD + _CYAN,
    "bold green":  _BOLD + _GREEN,
    "bold yellow": _BOLD + _YELLOW,
    "bold red":    _BOLD + _RED,
    "bold white":  _BOLD + _WHITE,
}


# ═════════════════════════════════════════════════════════════════
# RichConsole — production path
# ═════════════════════════════════════════════════════════════════


class RichConsole:
    """
    Thin wrapper around ``rich.console.Console``.

    Exposes only the methods ByteTrace needs so the rest of the
    codebase is not coupled to Rich's full API.
    """

    def __init__(self, no_color: bool = False) -> None:
        from rich.console import Console  # deferred import
        self._c = Console(no_color=no_color, highlight=False)

    def print(self, *args: Any, **kwargs: Any) -> None:
        """Print with Rich markup support."""
        self._c.print(*args, **kwargs)

    def print_raw(self, text: str) -> None:
        """Print plain text with no markup processing."""
        self._c.print(text, markup=False, highlight=False)

    def rule(self, title: str = "", style: str = "dim") -> None:
        """Print a horizontal rule with an optional centred title."""
        self._c.rule(title, style=style)

    @property
    def width(self) -> int:
        return self._c.width

    @property
    def no_color(self) -> bool:
        return self._c.no_color


# ═════════════════════════════════════════════════════════════════
# FallbackConsole — no-Rich path
# ═════════════════════════════════════════════════════════════════


def _strip_markup(text: str) -> str:
    """
    Convert a Rich markup string to a plain ANSI string, or strip all
    codes if no_color is True.

    Handles ``[bold cyan]text[/bold cyan]`` and ``[dim]text[/dim]``
    style tags.  Unrecognised tags are removed silently.
    """
    import re
    result: list[str] = []
    pos = 0

    for m in re.finditer(r"\[(/?)([^\]]+)\]", text):
        # Text before this tag
        result.append(text[pos : m.start()])
        pos = m.end()

        closing = m.group(1) == "/"
        tag     = m.group(2).lower()

        if closing:
            result.append(_RESET)
        else:
            code = _MARKUP_TO_ANSI.get(tag, "")
            result.append(code)

    result.append(text[pos:])
    return "".join(result)


def _strip_all_markup(text: str) -> str:
    """Remove all Rich markup tags and ANSI codes, leaving plain text."""
    import re
    # Remove markup tags
    text = re.sub(r"\[[^\]]*\]", "", text)
    # Remove ANSI escape sequences
    text = re.sub(r"\033\[[0-9;]*m", "", text)
    return text


class FallbackConsole:
    """
    Pure-Python console renderer.  Used when Rich is not installed.

    Converts the Rich markup subset used by ByteTrace to ANSI codes.
    Strips all colour when no_color=True.
    """

    def __init__(self, no_color: bool = False) -> None:
        self._no_color = no_color
        import shutil
        self._width = shutil.get_terminal_size().columns

    def print(self, *args: Any, end: str = "\n", **_kwargs: Any) -> None:
        """Print with markup → ANSI translation."""
        text = " ".join(str(a) for a in args)
        if self._no_color:
            sys.stdout.write(_strip_all_markup(text) + end)
        else:
            sys.stdout.write(_strip_markup(text) + _RESET + end)
        sys.stdout.flush()

    def print_raw(self, text: str) -> None:
        """Print completely plain text."""
        sys.stdout.write(text + "\n")
        sys.stdout.flush()

    def rule(self, title: str = "", style: str = "dim") -> None:
        """Print a plain horizontal rule."""
        width = self._width
        if title:
            pad   = max(0, (width - len(title) - 2) // 2)
            line  = "─" * pad + f" {title} " + "─" * pad
        else:
            line = "─" * width
        if not self._no_color:
            sys.stdout.write(_DIM + line + _RESET + "\n")
        else:
            sys.stdout.write(line + "\n")
        sys.stdout.flush()

    @property
    def width(self) -> int:
        return self._width

    @property
    def no_color(self) -> bool:
        return self._no_color


# ═════════════════════════════════════════════════════════════════
# Factory
# ═════════════════════════════════════════════════════════════════


def make_console(no_color: bool = False) -> RichConsole | FallbackConsole:
    """
    Return a ``RichConsole`` when Rich is installed, or a
    ``FallbackConsole`` otherwise.

    Always call this factory — never instantiate either class directly.
    """
    try:
        return RichConsole(no_color=no_color)
    except ImportError:
        return FallbackConsole(no_color=no_color)
