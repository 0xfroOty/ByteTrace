"""
``bytetrace hexdump`` command.

Displays raw bytes as a classic hexdump -C style view.

Examples
────────
    bytetrace hexdump ./target --section .rodata
    bytetrace hexdump ./target --offset 0x2000 --size 128
    bytetrace hexdump ./target --section .text --size 64 --width 8
    bytetrace hexdump ./target --section .rodata --json
    bytetrace hexdump ./target --offset 0x0 --size 16 --quiet
"""

from __future__ import annotations

import json

import click

from bytetrace.cli.options import binary_argument, explain_option, json_option, quiet_option
from bytetrace.core.hexdump import HexdumpError, hexdump_offset, hexdump_section
from bytetrace.formats import load
from bytetrace.formats.base import ParseError
from bytetrace.output.console import make_console
from bytetrace.output.tables import render_hexdump


def _parse_int(value: str, param_name: str) -> int:
    """Accept 0x… hex or decimal integer strings."""
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        raise click.BadParameter(
            f"'{value}' is not a valid integer for {param_name}."
        )


@click.command("hexdump")
@binary_argument
@json_option
@quiet_option
@explain_option
@click.option(
    "--section", "-s",
    default=None,
    metavar="NAME",
    help="Dump a named section (e.g. .rodata, .text).",
)
@click.option(
    "--offset", "-o",
    default=None,
    metavar="OFFSET",
    help="Start at a file offset (hex 0x… or decimal). Requires --size.",
)
@click.option(
    "--size", "-n",
    default=None,
    metavar="N",
    help="Number of bytes to dump (default: whole section, or required with --offset).",
)
@click.option(
    "--width", "-w",
    default=16,
    show_default=True,
    metavar="N",
    help="Bytes per display line.",
)
@click.pass_context
def hexdump(
    ctx: click.Context,
    binary: str,
    as_json: bool,
    quiet: bool,
    explain: bool,
    section: str | None,
    offset: str | None,
    size: str | None,
    width: int,
) -> None:
    """
    Display raw bytes with ASCII view (like hexdump -C).

    \b
    Target selection (one required):
      -s / --section NAME    dump a named section
      -o / --offset OFFSET   dump from a file offset (requires --size)

    \b
    Examples:
      bytetrace hexdump ./target --section .rodata
      bytetrace hexdump ./target --offset 0x2000 --size 128
      bytetrace hexdump ./target --section .text --size 64 --width 8
      bytetrace hexdump ./target --section .rodata --json
      bytetrace hexdump ./target --offset 0x0 --size 16 --quiet
    """
    no_color: bool = (ctx.obj or {}).get("no_color", False)
    console = make_console(no_color=no_color)

    # ── Validate arguments ────────────────────────────────────────
    if section is None and offset is None:
        console.print(
            "[bold red]Error:[/bold red] Specify a target with "
            "--section NAME  or  --offset OFFSET --size N"
        )
        console.print("Run with --help for usage examples.")
        raise SystemExit(1)

    if section is not None and offset is not None:
        console.print(
            "[bold red]Error:[/bold red] --section and --offset are mutually exclusive."
        )
        raise SystemExit(1)

    if offset is not None and size is None:
        console.print(
            "[bold red]Error:[/bold red] --offset requires --size N."
        )
        raise SystemExit(1)

    if width < 1 or width > 64:
        console.print("[bold red]Error:[/bold red] --width must be between 1 and 64.")
        raise SystemExit(1)

    # ── Load binary ───────────────────────────────────────────────
    try:
        b = load(binary)
    except ParseError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)
    except OSError as exc:
        console.print(f"[bold red]Error:[/bold red] Cannot read '{binary}': {exc.strerror}")
        raise SystemExit(1)

    # ── Produce HexLine list ──────────────────────────────────────
    try:
        if section is not None:
            max_b = _parse_int(size, "--size") if size else 0
            lines = hexdump_section(b, section, width=width, max_bytes=max_b)
            title = f"Hexdump — {b.name}  [{section}]"
            if max_b:
                title += f"  (first {max_b} bytes)"
        else:
            off_int  = _parse_int(offset, "--offset")
            size_int = _parse_int(size,   "--size")
            lines = hexdump_offset(b, off_int, size_int, width=width)
            title = f"Hexdump — {b.name}  [0x{off_int:x}+{size_int}]"

    except HexdumpError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)
    except click.BadParameter as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)

    # ── Emit output ───────────────────────────────────────────────
    if as_json:
        click.echo(json.dumps({
            "binary":   str(b.path),
            "section":  section,
            "offset":   lines[0].offset if lines else None,
            "bytes":    sum(len(ln.data) for ln in lines),
            "width":    width,
            "lines":    [ln.to_dict() for ln in lines],
        }, indent=2))
        return

    if quiet:
        # Classic hexdump -C minimal format
        for ln in lines:
            cols  = ln.hex_cols
            w     = ln.width
            mid   = w // 2
            left  = " ".join(cols[:mid])
            right = " ".join(cols[mid:w])
            click.echo(f"{ln.offset:08x}  {left}  {right}  |{ln.ascii_col}|")
        return

    render_hexdump(lines, console, title=title, explain=explain)
