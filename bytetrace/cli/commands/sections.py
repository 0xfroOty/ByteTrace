"""
``bytetrace sections`` command.

Prints the section header table of a binary.  Supports filtering by
flag (exec, write, alloc) and ``--explain`` mode which adds a
Purpose column describing what each section is for.

Examples
────────
    bytetrace sections ./target
    bytetrace sections ./target --explain
    bytetrace sections ./target --filter exec
    bytetrace sections ./target --json
"""

from __future__ import annotations

import json

import click

from bytetrace.cli.options import binary_argument, explain_option, json_option, quiet_option
from bytetrace.formats import load
from bytetrace.formats.base import ParseError
from bytetrace.output.console import make_console
from bytetrace.output.tables import render_sections


_FILTER_CHOICES = click.Choice(["exec", "write", "alloc", "tls"], case_sensitive=False)


@click.command("sections")
@binary_argument
@json_option
@explain_option
@quiet_option
@click.option(
    "--filter", "filter_flag",
    type=_FILTER_CHOICES,
    default=None,
    help="Show only sections with this flag (exec, write, alloc, tls).",
)
@click.pass_context
def sections(
    ctx: click.Context,
    binary: str,
    as_json: bool,
    explain: bool,
    quiet: bool,
    filter_flag: str | None,
) -> None:
    """
    List the section header table of a binary.

    \b
    Each row shows:
      • Section name  (e.g. .text, .data, .rodata)
      • File offset and virtual load address
      • Size in bytes
      • Permission flags: A=alloc, X=executable, W=writable

    \b
    Examples:
      bytetrace sections ./target
      bytetrace sections ./target --explain
      bytetrace sections ./target --filter exec
      bytetrace sections ./target --json | jq '.sections[] | .name'
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
        from bytetrace.core.enums import SectionFlags
        secs = b.sections
        if filter_flag:
            flag_map = {
                "exec":  SectionFlags.EXEC,
                "write": SectionFlags.WRITE,
                "alloc": SectionFlags.ALLOC,
                "tls":   SectionFlags.TLS,
            }
            flag = flag_map.get(filter_flag.lower())
            if flag:
                secs = tuple(s for s in secs if flag in s.flags)
        result = {
            "binary":   str(b.path),
            "sections": [s.to_dict() for s in secs],
            "total":    len(secs),
        }
        click.echo(json.dumps(result, indent=2))
        return

    if quiet:
        from bytetrace.core.enums import SectionFlags
        secs = b.sections
        if filter_flag:
            flag_map = {"exec": SectionFlags.EXEC, "write": SectionFlags.WRITE,
                        "alloc": SectionFlags.ALLOC, "tls": SectionFlags.TLS}
            flag = flag_map.get(filter_flag.lower() if filter_flag else "")
            if flag:
                secs = tuple(s for s in secs if flag in s.flags)
        for s in secs:
            click.echo(f"{s.name}\t0x{s.vaddr:x}\t{s.size}\t{s.flags_str()}")
        return

    render_sections(b, console, explain=explain, filter_flag=filter_flag)
