"""
``bytetrace disasm`` command — with --explain support.
"""
from __future__ import annotations
import json
import click
from bytetrace.cli.options import binary_argument, explain_option, json_option, quiet_option
from bytetrace.disasm.engine import DisasmError, disassemble_at, disassemble_function
from bytetrace.formats import load
from bytetrace.formats.base import ParseError
from bytetrace.output.console import make_console
from bytetrace.output.tables import render_disassembly


def _parse_address(value: str) -> int:
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        raise click.BadParameter(f"'{value}' is not a valid address.")


@click.command("disasm")
@binary_argument
@json_option
@quiet_option
@explain_option
@click.option("--func", "-f", default=None, metavar="NAME",
              help="Disassemble a function by symbol name (substring match).")
@click.option("--addr", "-a", default=None, metavar="ADDR",
              help="Disassemble starting at a virtual address (hex 0x… or decimal).")
@click.option("--count", "-n", default=50, show_default=True, metavar="N",
              help="Maximum number of instructions to show.")
@click.pass_context
def disasm(ctx, binary, as_json, quiet, explain, func, addr, count):
    """
    Disassemble instructions from a binary.

    \b
    Target selection (one required):
      -f / --func NAME   disassemble a named function
      -a / --addr ADDR   disassemble from a virtual address

    \b
    Examples:
      bytetrace disasm ./target --func main
      bytetrace disasm ./target --func main --explain
      bytetrace disasm ./target --func main --count 30
      bytetrace disasm ./target --addr 0x401234 --count 20
      bytetrace disasm ./target --func main --json
      bytetrace disasm ./target --func main --explain --json
    """
    no_color = (ctx.obj or {}).get("no_color", False)
    console  = make_console(no_color=no_color)

    if func is None and addr is None:
        console.print("[bold red]Error:[/bold red] Specify a target with --func NAME  or  --addr ADDRESS")
        console.print("Run with --help for usage examples.")
        raise SystemExit(1)
    if func is not None and addr is not None:
        console.print("[bold red]Error:[/bold red] --func and --addr are mutually exclusive.")
        raise SystemExit(1)

    try:
        b = load(binary)
    except ParseError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}"); raise SystemExit(1)
    except OSError as exc:
        console.print(f"[bold red]Error:[/bold red] Cannot read '{binary}': {exc.strerror}"); raise SystemExit(1)

    try:
        if func is not None:
            instructions = disassemble_function(b, func, count=count)
            title = f"Disassembly — {b.name}  [{func}]"
        else:
            address = _parse_address(addr)
            instructions = disassemble_at(b, address, count=count)
            title = f"Disassembly — {b.name}  [0x{address:x}]"
    except DisasmError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}"); raise SystemExit(1)

    # Symbol lookup (used by explainer for call-target annotation)
    sym_lookup = {sym.address: sym.name for sym in b.symbols if sym.address}

    # Produce explanations when requested
    def _get_explanations():
        if not explain:
            return [""] * len(instructions)
        try:
            from bytetrace.explain.explainer import explain_instructions
            return explain_instructions(instructions, sym_lookup)
        except ImportError:
            return [""] * len(instructions)

    if as_json:
        expls = _get_explanations()
        insn_dicts = []
        for insn, expl in zip(instructions, expls):
            d = insn.to_dict()
            if explain:
                d["explanation"] = expl
            insn_dicts.append(d)
        click.echo(json.dumps({
            "binary":       str(b.path),
            "target":       func or addr,
            "arch":         b.arch.value,
            "instructions": insn_dicts,
            "count":        len(instructions),
        }, indent=2))
        return

    if quiet:
        expls = _get_explanations()
        for insn, expl in zip(instructions, expls):
            line = f"0x{insn.address:x}\t{insn.mnemonic}"
            if insn.op_str:
                line += f"\t{insn.op_str}"
            if explain and expl:
                line += f"\t; {expl}"
            click.echo(line)
        return

    render_disassembly(instructions, console, title=title, binary=b, explain=explain)
