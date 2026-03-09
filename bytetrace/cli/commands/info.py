"""
``bytetrace info`` command.

Prints a high-level overview of a binary: format, architecture, entry
point, section/symbol counts, PIE status, and interpreter path.

Examples
────────
    bytetrace info ./target
    bytetrace info ./target --explain
    bytetrace info ./target --json
"""

from __future__ import annotations

import json

import click

from bytetrace.cli.options import binary_argument, explain_option, json_option, quiet_option
from bytetrace.formats import load
from bytetrace.formats.base import ParseError
from bytetrace.output.console import make_console
from bytetrace.output.tables import render_info


@click.command("info")
@binary_argument
@json_option
@explain_option
@quiet_option
@click.pass_context
def info(ctx: click.Context, binary: str, as_json: bool, explain: bool, quiet: bool) -> None:
    """
    Show a high-level overview of a binary.

    \b
    Displays:
      • Format, architecture, word size, endianness
      • Entry point address
      • PIE / stripped status
      • Dynamic linker interpreter path
      • Section and symbol counts

    \b
    Examples:
      bytetrace info ./target
      bytetrace info ./target --explain
      bytetrace info ./target --json
    """
    no_color: bool = (ctx.obj or {}).get("no_color", False)
    console = make_console(no_color=no_color)

    try:
        b = load(binary)
    except ParseError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)
    except OSError as exc:
        console.print(f"[bold red]Error:[/bold red] Cannot read '{binary}': {exc.strerror}")
        raise SystemExit(1)

    if as_json:
        click.echo(json.dumps(b.to_dict(), indent=2))
        return

    if not quiet:
        render_info(b, console, explain=explain)
    else:
        # Quiet: emit only the essential key=value pairs, one per line.
        for key, value in [
            ("file",        b.name),
            ("format",      b.fmt.value),
            ("arch",        b.arch.value),
            ("bits",        str(b.bits)),
            ("endian",      b.endian.value),
            ("entry",       hex(b.entry_point)),
            ("pie",         str(b.is_pie).lower()),
            ("stripped",    str(b.is_stripped).lower()),
            ("sections",    str(len(b.sections))),
            ("symbols",     str(len(b.symbols))),
        ]:
            click.echo(f"{key}={value}")
