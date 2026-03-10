"""
``bytetrace cfg`` command.

Builds and displays the Control Flow Graph of a function.

Examples
────────
    bytetrace cfg ./target --func main
    bytetrace cfg ./target --func main --max-insns 200
    bytetrace cfg ./target --addr 0x401234
    bytetrace cfg ./target --func main --json
    bytetrace cfg ./target --func main --quiet
"""

from __future__ import annotations

import json

import click

from bytetrace.cfg import CFGError, build_cfg_from_address, build_cfg_from_function
from bytetrace.cli.options import binary_argument, json_option, quiet_option
from bytetrace.formats import load
from bytetrace.formats.base import ParseError
from bytetrace.output.console import make_console
from bytetrace.output.tables import render_cfg


def _parse_address(value: str) -> int:
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        raise click.BadParameter(
            f"'{value}' is not a valid address (use hex 0x… or decimal)."
        )


@click.command("cfg")
@binary_argument
@json_option
@quiet_option
@click.option(
    "--func", "-f",
    default=None,
    metavar="NAME",
    help="Build CFG for a function by symbol name.",
)
@click.option(
    "--addr", "-a",
    default=None,
    metavar="ADDR",
    help="Build CFG starting at a virtual address (hex 0x… or decimal).",
)
@click.option(
    "--max-insns",
    default=500,
    show_default=True,
    metavar="N",
    help="Safety limit on instructions to disassemble.",
)
@click.pass_context
def cfg(
    ctx: click.Context,
    binary: str,
    as_json: bool,
    quiet: bool,
    func: str | None,
    addr: str | None,
    max_insns: int,
) -> None:
    """
    Build and display the Control Flow Graph of a function.

    \b
    Target selection (one required):
      -f / --func NAME   by function name
      -a / --addr ADDR   by virtual address

    \b
    Output modes:
      default   ASCII/Rich block diagram with edges
      --json    structured JSON with all blocks and edges
      --quiet   one line per block (address + instruction count)

    \b
    Examples:
      bytetrace cfg ./target --func main
      bytetrace cfg ./target --func main --max-insns 200
      bytetrace cfg ./target --addr 0x401234
      bytetrace cfg ./target --func main --json | jq '.block_count'
    """
    no_color: bool = (ctx.obj or {}).get("no_color", False)
    console = make_console(no_color=no_color)

    # ── Validate arguments ────────────────────────────────────────
    if func is None and addr is None:
        console.print(
            "[bold red]Error:[/bold red] Specify a target with "
            "--func NAME  or  --addr ADDRESS"
        )
        console.print("Run with --help for usage examples.")
        raise SystemExit(1)

    if func is not None and addr is not None:
        console.print(
            "[bold red]Error:[/bold red] --func and --addr are mutually exclusive."
        )
        raise SystemExit(1)

    # ── Load binary ───────────────────────────────────────────────
    try:
        b = load(binary)
    except ParseError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)
    except OSError as exc:
        console.print(
            f"[bold red]Error:[/bold red] Cannot read '{binary}': {exc.strerror}"
        )
        raise SystemExit(1)

    # ── Build CFG ─────────────────────────────────────────────────
    try:
        if func is not None:
            graph = build_cfg_from_function(b, func, max_insns=max_insns)
            title = f"CFG — {b.name}  [{func}]"
        else:
            address = _parse_address(addr)
            graph = build_cfg_from_address(b, address, max_insns=max_insns)
            title = f"CFG — {b.name}  [0x{address:x}]"

    except CFGError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)

    # ── Emit output ───────────────────────────────────────────────
    if as_json:
        result = graph.to_dict()
        result["binary"] = str(b.path)
        result["target"] = func or addr
        click.echo(json.dumps(result, indent=2))
        return

    if quiet:
        for block in graph.blocks():
            entry_mark = "*" if block.start_address == graph.entry else " "
            click.echo(
                f"{entry_mark}0x{block.start_address:x}"
                f"\t{block.instruction_count}"
                f"\t{'ret' if block.is_return else ''}"
            )
        return

    render_cfg(graph, console, title=title, binary=b)
