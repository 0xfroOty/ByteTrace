"""
``bytetrace disasm`` command.

Disassembles a binary using the Capstone engine.  Supports targeting
a function by name (``--func``) or a raw virtual address (``--addr``).

Examples
────────
    bytetrace disasm ./target --func main
    bytetrace disasm ./target --func main --count 30
    bytetrace disasm ./target --addr 0x401234
    bytetrace disasm ./target --addr 0x401234 --count 20
    bytetrace disasm ./target --func main --json
    bytetrace disasm ./target --func main --quiet
"""

from __future__ import annotations

import json

import click

from bytetrace.cli.options import binary_argument, json_option, quiet_option
from bytetrace.disasm.engine import DisasmError, disassemble_at, disassemble_function
from bytetrace.formats import load
from bytetrace.formats.base import ParseError
from bytetrace.output.console import make_console
from bytetrace.output.tables import render_disassembly


def _parse_address(value: str) -> int:
    """Accept 0x… or decimal address strings."""
    try:
        return int(value, 16) if value.startswith("0x") or value.startswith("0X") else int(value)
    except ValueError:
        raise click.BadParameter(f"'{value}' is not a valid address (use hex 0x… or decimal).")


@click.command("disasm")
@binary_argument
@json_option
@quiet_option
@click.option(
    "--func", "-f",
    default=None,
    metavar="NAME",
    help="Disassemble a function by symbol name (substring match).",
)
@click.option(
    "--addr", "-a",
    default=None,
    metavar="ADDR",
    help="Disassemble starting at a virtual address (hex 0x… or decimal).",
)
@click.option(
    "--count", "-n",
    default=50,
    show_default=True,
    metavar="N",
    help="Maximum number of instructions to show.",
)
@click.pass_context
def disasm(
    ctx: click.Context,
    binary: str,
    as_json: bool,
    quiet: bool,
    func: str | None,
    addr: str | None,
    count: int,
) -> None:
    """
    Disassemble instructions from a binary.

    \b
    Target selection (one required):
      -f / --func NAME   disassemble a named function
      -a / --addr ADDR   disassemble from a virtual address

    \b
    Examples:
      bytetrace disasm ./target --func main
      bytetrace disasm ./target --func main --count 30
      bytetrace disasm ./target --addr 0x401234
      bytetrace disasm ./target --addr 0x401234 --count 20
      bytetrace disasm ./target --func main --json
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
        console.print(f"[bold red]Error:[/bold red] Cannot read '{binary}': {exc.strerror}")
        raise SystemExit(1)

    # ── Disassemble ───────────────────────────────────────────────
    try:
        if func is not None:
            instructions = disassemble_function(b, func, count=count)
            title = f"Disassembly — {b.name}  [{func}]"
        else:
            address = _parse_address(addr)
            instructions = disassemble_at(b, address, count=count)
            title = f"Disassembly — {b.name}  [0x{address:x}]"

    except DisasmError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)

    # ── Emit output ───────────────────────────────────────────────
    if as_json:
        result = {
            "binary":       str(b.path),
            "target":       func or addr,
            "arch":         b.arch.value,
            "instructions": [i.to_dict() for i in instructions],
            "count":        len(instructions),
        }
        click.echo(json.dumps(result, indent=2))
        return

    if quiet:
        for insn in instructions:
            op = insn.op_str
            line = f"0x{insn.address:x}\t{insn.mnemonic}"
            if op:
                line += f"\t{op}"
            click.echo(line)
        return

    render_disassembly(instructions, console, title=title, binary=b)
