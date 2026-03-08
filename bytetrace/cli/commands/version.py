import click
from bytetrace.version import __version__

@click.command()
def version():
    """Show ByteTrace version."""
    click.echo(f"ByteTrace version {__version__}")
