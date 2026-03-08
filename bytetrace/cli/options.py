"""
Shared CLI options and decorators.

Centralizing common options ensures consistent behaviour across all
commands — flags like --json, --explain, and --no-color work the
same way everywhere without copy-pasting.
"""

import click


# ── Reusable option decorators ────────────────────────────────────


def json_option(f):
    """Emit output as structured JSON instead of the Rich terminal view."""
    return click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Output results as JSON (machine-readable).",
    )(f)


def explain_option(f):
    """Add inline educational annotations to the output."""
    return click.option(
        "--explain",
        is_flag=True,
        default=False,
        help="Add human-readable explanations alongside output.",
    )(f)


def no_color_option(f):
    """Strip all ANSI color codes — useful when piping output."""
    return click.option(
        "--no-color",
        is_flag=True,
        default=False,
        envvar="NO_COLOR",
        help="Disable color output (also respects NO_COLOR env var).",
    )(f)


def quiet_option(f):
    """Suppress decorative chrome; emit only the core data."""
    return click.option(
        "--quiet",
        "-q",
        is_flag=True,
        default=False,
        help="Minimal output — suppress headers and decorations.",
    )(f)


# ── Argument: the binary file path (used by all analysis commands) ─


binary_argument = click.argument(
    "binary",
    type=click.Path(exists=True, readable=True, resolve_path=True),
)
