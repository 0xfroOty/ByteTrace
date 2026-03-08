"""
``bytetrace version`` command.

Provides richer version information than the --version flag alone:
Python version, platform, and installed optional dependencies.
Useful when filing bug reports.
"""

from __future__ import annotations

import importlib.metadata
import platform
import sys

import click

from bytetrace import __version__


@click.command("version")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Output as JSON.",
)
@click.pass_context
def version(ctx: click.Context, as_json: bool) -> None:
    """Show ByteTrace version and environment information."""
    no_color: bool = (ctx.obj or {}).get("no_color", False)
    info = _collect_version_info()

    if as_json:
        import json
        click.echo(json.dumps(info, indent=2))
        return

    _render_version(info, no_color)


# ── Helpers ───────────────────────────────────────────────────────


def _collect_version_info() -> dict:
    """Gather version strings for ByteTrace and key dependencies."""
    deps: dict[str, str] = {}
    pkg_map = {
        "click": "click",
        "rich": "rich",
        "capstone": "capstone",
        "pyelftools": "pyelftools",
        "networkx": "networkx",
        "rapidfuzz": "rapidfuzz",
    }
    for label, pkg in pkg_map.items():
        try:
            deps[label] = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            deps[label] = "not installed"

    return {
        "bytetrace": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(terse=True),
        "dependencies": deps,
    }


def _render_version(info: dict, no_color: bool) -> None:
    """Render version info — uses Rich when available, plain text otherwise."""
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console(no_color=no_color)
        table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
        table.add_column("key", style="dim")
        table.add_column("value")

        table.add_row("bytetrace", f"[bold cyan]{info['bytetrace']}[/bold cyan]")
        table.add_row("python", info["python"])
        table.add_row("platform", info["platform"])
        table.add_row("", "")

        for dep, ver in info["dependencies"].items():
            style = "green" if ver != "not installed" else "red"
            table.add_row(dep, f"[{style}]{ver}[/{style}]")

        console.print(table)

    except ImportError:
        # Rich not installed — degrade to plain text gracefully.
        click.echo(f"bytetrace  {info['bytetrace']}")
        click.echo(f"python     {info['python']}")
        click.echo(f"platform   {info['platform']}")
        click.echo("")
        for dep, ver in info["dependencies"].items():
            click.echo(f"{dep:<12} {ver}")
