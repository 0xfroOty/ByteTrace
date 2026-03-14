"""ByteTrace CLI entry point."""
from __future__ import annotations
import click
from bytetrace import __version__

CONTEXT_SETTINGS: dict = {
    "help_option_names": [],
    "max_content_width": 100,
}

BANNER = r"""
 ██████╗ ██╗   ██╗████████╗███████╗████████╗██████╗  █████╗  ██████╗███████╗
 ██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
 ██████╔╝ ╚████╔╝    ██║   █████╗     ██║   ██████╔╝███████║██║     █████╗
 ██╔══██╗  ╚██╔╝     ██║   ██╔══╝     ██║   ██╔══██╗██╔══██║██║     ██╔══╝
 ██████╔╝   ██║      ██║   ███████╗   ██║   ██║  ██║██║  ██║╚██████╗███████╗
 ╚═════╝    ╚═╝      ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝

 ByteTrace — Binary analysis for humans
"""


def _apply_no_color(ctx: click.Context, _param, value: bool) -> None:
    ctx.ensure_object(dict)
    ctx.obj["no_color"] = value


@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.version_option(version=__version__, prog_name="bytetrace", message="%(prog)s %(version)s")
@click.option("--no-color", is_flag=True, default=False, envvar="NO_COLOR",
              is_eager=True, expose_value=False,
              help="Disable colour output (also respects $NO_COLOR).",
              callback=_apply_no_color)
@click.option("-h", "--help", "show_help", is_flag=True, default=False,
              help="Show this message and exit.")
@click.pass_context
def cli(ctx: click.Context, show_help: bool) -> None:
    """
    \b
    ByteTrace — binary analysis for humans.

    \b
    Commands:
      info      binary overview
      sections  section table
      symbols   symbol listing
      disasm    disassemble a function
      cfg       control flow graph
      strings   extract printable strings
      hexdump   raw byte inspection

    \b
    Universal flags: --explain  --json  --no-color  --quiet/-q
    """
    if show_help or ctx.invoked_subcommand is None:
        click.echo(BANNER)
        click.echo(ctx.get_help())


# ── Sub-command registration ──────────────────────────────────────
from bytetrace.cli.commands.version  import version   # noqa: E402
from bytetrace.cli.commands.info     import info       # noqa: E402
from bytetrace.cli.commands.sections import sections   # noqa: E402
from bytetrace.cli.commands.symbols  import symbols    # noqa: E402
from bytetrace.cli.commands.disasm   import disasm     # noqa: E402
from bytetrace.cli.commands.cfg      import cfg        # noqa: E402
from bytetrace.cli.commands.strings  import strings    # noqa: E402
from bytetrace.cli.commands.hexdump  import hexdump    # noqa: E402

cli.add_command(version)
cli.add_command(info)
cli.add_command(sections)
cli.add_command(symbols)
cli.add_command(disasm)
cli.add_command(cfg)
cli.add_command(strings)
cli.add_command(hexdump)


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
