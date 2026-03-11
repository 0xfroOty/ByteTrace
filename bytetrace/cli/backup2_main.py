"""
ByteTrace CLI entry point.

Defines the root ``cli`` Click group and registers all sub-commands.
This is the target of the ``bytetrace`` console script in pyproject.toml.
"""

from __future__ import annotations

import click

from bytetrace import __version__


CONTEXT_SETTINGS: dict = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 100,
}


def _apply_no_color(
    ctx: click.Context,
    _param: click.Parameter,
    value: bool,
) -> None:
    ctx.ensure_object(dict)
    ctx.obj["no_color"] = value


@click.group(
    context_settings=CONTEXT_SETTINGS,
    invoke_without_command=True,
)
@click.version_option(
    version=__version__,
    prog_name="bytetrace",
    message="%(prog)s %(version)s",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    envvar="NO_COLOR",
    is_eager=True,
    expose_value=False,
    help="Disable colour output (also respects $NO_COLOR).",
    callback=_apply_no_color,
)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """
    \b
    ByteTrace — binary analysis for humans.

    Explore compiled binaries with clean output and inline explanations.

    \b
    Quick start:
      bytetrace info     ./binary   — binary overview
      bytetrace sections ./binary   — section table
      bytetrace symbols  ./binary   — symbol listing
      bytetrace disasm   ./binary   — disassemble a function
      bytetrace cfg      ./binary   — control flow graph

    \b
    Universal flags (work on every command):
      --explain    educational annotations
      --json       machine-readable JSON output
      --no-color   strip all ANSI colour codes
      --quiet/-q   suppress decorative chrome
    """
    if ctx.invoked_subcommand is not None:
        return

    no_color: bool = (ctx.obj or {}).get("no_color", False)
    banner = f"\n  ByteTrace v{__version__}\n  A modern, educational binary analysis tool.\n"

    try:
        from rich.console import Console
        Console(no_color=no_color).print(
            f"\n  [bold cyan]ByteTrace[/bold cyan] [dim]v{__version__}[/dim]\n"
            "  [dim]A modern, educational binary analysis tool.[/dim]\n"
        )
    except ImportError:
        click.echo(banner)

    click.echo(ctx.get_help())


# ── Sub-command registration ──────────────────────────────────────

from bytetrace.cli.commands.version  import version   # noqa: E402
from bytetrace.cli.commands.info     import info       # noqa: E402
from bytetrace.cli.commands.sections import sections   # noqa: E402
from bytetrace.cli.commands.symbols  import symbols    # noqa: E402
from bytetrace.cli.commands.disasm   import disasm     # noqa: E402

cli.add_command(version)
cli.add_command(info)
cli.add_command(sections)
cli.add_command(symbols)
cli.add_command(disasm)


def main() -> None:
    """Called by the ``bytetrace`` console script."""
    cli(obj={})


if __name__ == "__main__":
    main()
