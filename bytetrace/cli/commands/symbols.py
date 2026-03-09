"""
``bytetrace symbols`` command.

Lists the symbol table of a binary.  Supports:
  • Filtering by type  (--filter functions | objects | dynamic | undefined)
  • Fuzzy search       (--search <query>)
  • Sorting            (--sort name | address | size | type)
  • Educational mode   (--explain)

Examples
────────
    bytetrace symbols ./target
    bytetrace symbols ./target --filter functions
    bytetrace symbols ./target --search malloc
    bytetrace symbols ./target --sort size
    bytetrace symbols ./target --json
"""

from __future__ import annotations

import json

import click

from bytetrace.cli.options import binary_argument, explain_option, json_option, quiet_option
from bytetrace.formats import load
from bytetrace.formats.base import ParseError
from bytetrace.output.console import make_console
from bytetrace.output.tables import render_symbols


_FILTER_CHOICES = click.Choice(
    ["functions", "objects", "dynamic", "undefined"],
    case_sensitive=False,
)
_SORT_CHOICES = click.Choice(
    ["name", "address", "size", "type"],
    case_sensitive=False,
)


@click.command("symbols")
@binary_argument
@json_option
@explain_option
@quiet_option
@click.option(
    "--filter", "filter_type",
    type=_FILTER_CHOICES,
    default=None,
    help="Show only symbols of this kind.",
)
@click.option(
    "--search", "-s",
    default=None,
    metavar="QUERY",
    help="Case-insensitive substring search on symbol names.",
)
@click.option(
    "--sort",
    type=_SORT_CHOICES,
    default="name",
    show_default=True,
    help="Sort symbols by this field.",
)
@click.pass_context
def symbols(
    ctx: click.Context,
    binary: str,
    as_json: bool,
    explain: bool,
    quiet: bool,
    filter_type: str | None,
    search: str | None,
    sort: str,
) -> None:
    """
    List symbols from the static and dynamic symbol tables.

    \b
    Each row shows:
      • Symbol name
      • Virtual address (or 'undefined' for dynamic imports)
      • Size in bytes
      • Type (function, object, notype, …)
      • Binding (global, local, weak)
      • Dyn marker — ● if from .dynsym (runtime import/export)

    \b
    Examples:
      bytetrace symbols ./target
      bytetrace symbols ./target --filter functions
      bytetrace symbols ./target --filter dynamic
      bytetrace symbols ./target --search malloc
      bytetrace symbols ./target --sort size
      bytetrace symbols ./target --json | jq '[.symbols[] | .name]'
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

    # ── Apply filters + search + sort to get the working symbol list ──
    from bytetrace.core.enums import SymbolType

    syms = list(b.symbols)

    if filter_type:
        if filter_type == "dynamic":
            syms = [s for s in syms if s.is_dynamic]
        elif filter_type == "undefined":
            syms = [s for s in syms if s.is_undefined]
        elif filter_type == "functions":
            syms = [s for s in syms if s.is_function]
        elif filter_type == "objects":
            syms = [s for s in syms if s.is_object]

    if search:
        q = search.lower()
        syms = [s for s in syms if q in s.name.lower()]

    sort_map = {
        "name":    lambda s: s.name.lower(),
        "address": lambda s: s.address,
        "size":    lambda s: -s.size,
        "type":    lambda s: s.sym_type.value,
    }
    syms = sorted(syms, key=sort_map.get(sort, sort_map["name"]))

    # ── JSON output ───────────────────────────────────────────────
    if as_json:
        result = {
            "binary":  str(b.path),
            "symbols": [s.to_dict() for s in syms],
            "total":   len(syms),
            "filters": {
                "type":   filter_type,
                "search": search,
                "sort":   sort,
            },
        }
        click.echo(json.dumps(result, indent=2))
        return

    # ── Quiet output ──────────────────────────────────────────────
    if quiet:
        for s in syms:
            addr = "0x0" if s.is_undefined else f"0x{s.address:x}"
            click.echo(f"{s.name}\t{addr}\t{s.size}\t{s.sym_type.value}")
        return

    # ── Rich / fallback table ─────────────────────────────────────
    render_symbols(
        b,
        console,
        explain=explain,
        filter_type=filter_type,
        search=search,
        sort_by=sort,
    )
