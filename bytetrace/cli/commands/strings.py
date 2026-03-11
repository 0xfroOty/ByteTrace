"""
``bytetrace strings`` command.

Extracts printable ASCII strings from a binary or a specific section.

Examples
────────
    bytetrace strings ./target
    bytetrace strings ./target --section .rodata
    bytetrace strings ./target --min-len 8
    bytetrace strings ./target --offset
    bytetrace strings ./target --json
    bytetrace strings ./target --quiet
"""

from __future__ import annotations

import json

import click

from bytetrace.cli.options import binary_argument, explain_option, json_option, quiet_option
from bytetrace.core.strings import extract_strings
from bytetrace.formats import load
from bytetrace.formats.base import ParseError
from bytetrace.output.console import make_console
from bytetrace.output.tables import render_strings


@click.command("strings")
@binary_argument
@json_option
@quiet_option
@explain_option
@click.option(
    "--min-len", "-m",
    default=4,
    show_default=True,
    metavar="N",
    help="Minimum printable-byte run length to report.",
)
@click.option(
    "--section", "-s",
    default=None,
    metavar="NAME",
    help="Scan only this section (e.g. .rodata, .dynstr).",
)
@click.option(
    "--offset/--no-offset", "-o/-O",
    default=True,
    help="Show / hide the file offset column (default: show).",
)
@click.pass_context
def strings(
    ctx: click.Context,
    binary: str,
    as_json: bool,
    quiet: bool,
    explain: bool,
    min_len: int,
    section: str | None,
    offset: bool,
) -> None:
    """
    Extract printable ASCII strings from a binary.

    \b
    Scans raw bytes for runs of printable characters (0x20–0x7E) of at
    least --min-len bytes.  Use --section to restrict the scan to a
    specific ELF section such as .rodata or .dynstr.

    \b
    Examples:
      bytetrace strings ./target
      bytetrace strings ./target --section .rodata
      bytetrace strings ./target --min-len 8
      bytetrace strings ./target --offset --quiet
      bytetrace strings ./target --json | jq '.strings | length'
    """
    no_color: bool = (ctx.obj or {}).get("no_color", False)
    console = make_console(no_color=no_color)

    # ── Load binary ───────────────────────────────────────────────
    try:
        b = load(binary)
    except ParseError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)
    except OSError as exc:
        console.print(f"[bold red]Error:[/bold red] Cannot read '{binary}': {exc.strerror}")
        raise SystemExit(1)

    # ── Extract strings ───────────────────────────────────────────
    try:
        results = extract_strings(b, min_len=min_len, section_name=section)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)

    # ── Build title ───────────────────────────────────────────────
    scope = f"[{section}]" if section else "[whole file]"
    title = f"Strings — {b.name}  {scope}  (min-len {min_len})"

    # ── Emit output ───────────────────────────────────────────────
    if as_json:
        click.echo(json.dumps({
            "binary":   str(b.path),
            "section":  section,
            "min_len":  min_len,
            "count":    len(results),
            "strings":  [s.to_dict() for s in results],
        }, indent=2))
        return

    if quiet:
        for s in results:
            if offset:
                click.echo(f"0x{s.offset:08x}\t{s.value}")
            else:
                click.echo(s.value)
        return

    render_strings(results, console, title=title, show_offset=offset, explain=explain)
