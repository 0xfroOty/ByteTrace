"""
Table and layout builders for ByteTrace terminal output.

All public functions accept a ``console`` object (from
``output.console.make_console``) plus data from the core models.
They write directly to the console and return nothing.

Rich path  — activated when ``console`` is a ``RichConsole`` instance.
Fallback   — hand-rolled ANSI/text columns when Rich is absent.

Both paths honour ``console.no_color``.
"""

from __future__ import annotations

import json
from typing import Any

from bytetrace.core.binary import Binary
from bytetrace.core.section import Section
from bytetrace.core.symbol import Symbol


# ═════════════════════════════════════════════════════════════════
# Rich availability guard
# ═════════════════════════════════════════════════════════════════

try:
    import rich as _rich
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False


# ═════════════════════════════════════════════════════════════════
# Shared styling helpers
# ═════════════════════════════════════════════════════════════════

def _c(text: str, style: str, no_color: bool) -> str:
    """Wrap *text* in Rich markup unless no_color or Rich is absent."""
    if no_color or not style or not _RICH_AVAILABLE:
        return text
    return f"[{style}]{text}[/{style}]"


def _size_str(size: int, no_color: bool) -> str:
    if size == 0:
        return _c("0", "dim", no_color)
    if size < 1024:
        s = f"{size} B"
    elif size < 1024 * 1024:
        s = f"{size / 1024:.1f} KiB"
    else:
        s = f"{size / 1024 / 1024:.2f} MiB"
    return _c(s, "yellow", no_color)


def _flag_str(flags_str: str, no_color: bool) -> str:
    """Colour flags: X=red bold, W=yellow, A=green."""
    if no_color or not _RICH_AVAILABLE:
        return flags_str or "-"
    if not flags_str or flags_str == "-":
        return "[dim]-[/dim]"
    parts = []
    for ch in flags_str:
        if ch == "X":   parts.append("[bold red]X[/bold red]")
        elif ch == "W": parts.append("[yellow]W[/yellow]")
        elif ch == "A": parts.append("[green]A[/green]")
        else:           parts.append(f"[dim]{ch}[/dim]")
    return "".join(parts)


def _bool_badge(value: bool, true_style: str, false_style: str, no_color: bool) -> str:
    text = "Yes" if value else "No"
    style = true_style if value else false_style
    return _c(text, style, no_color)


# ═════════════════════════════════════════════════════════════════
# Section purpose descriptions
# ═════════════════════════════════════════════════════════════════

_SECTION_DESC: dict[str, str] = {
    ".text":              "Executable code",
    ".data":              "Initialised read-write data",
    ".rodata":            "Read-only data / string literals",
    ".bss":               "Uninitialised data (zero-filled at load)",
    ".plt":               "Procedure Linkage Table (dynamic call stubs)",
    ".plt.got":           "PLT using GOT entries",
    ".plt.sec":           "PLT with security mitigations (IBT/SHSTK)",
    ".got":               "Global Offset Table (resolved at load time)",
    ".got.plt":           "GOT entries for PLT stubs",
    ".dynsym":            "Dynamic symbol table (imports/exports)",
    ".dynstr":            "String table for .dynsym",
    ".dynamic":           "Dynamic linking metadata",
    ".symtab":            "Full static symbol table",
    ".strtab":            "String table for .symtab",
    ".shstrtab":          "Section name string table",
    ".interp":            "ELF interpreter path (dynamic linker)",
    ".eh_frame":          "Exception handling / stack unwind data",
    ".eh_frame_hdr":      "Index into .eh_frame",
    ".init":              "Code executed before main()",
    ".fini":              "Code executed after main() returns",
    ".init_array":        "Constructor function pointers (run before main)",
    ".fini_array":        "Destructor function pointers (run after main)",
    ".rela.dyn":          "Dynamic relocation entries (with addends)",
    ".rela.plt":          "PLT relocation entries",
    ".rel.dyn":           "Dynamic relocation entries",
    ".rel.plt":           "PLT relocation entries",
    ".note.gnu.build-id": "Build ID hash — unique binary fingerprint",
    ".note.ABI-tag":      "Minimum Linux ABI version required",
    ".gnu.hash":          "GNU-style symbol hash table",
    ".gnu.version":       "Symbol version index",
    ".gnu.version_r":     "Symbol version requirements",
    ".data.rel.ro":       "Read-only after relocation (RELRO hardening)",
    ".debug_info":        "DWARF debug information",
    ".debug_str":         "DWARF debug strings",
    ".comment":           "Compiler / toolchain version string",
}


def section_description(name: str) -> str:
    """Return a short purpose string for a well-known section name."""
    return _SECTION_DESC.get(name, "")


# ═════════════════════════════════════════════════════════════════
# info command
# ═════════════════════════════════════════════════════════════════

def render_info(binary: Binary, console: Any, explain: bool = False) -> None:
    """Render the binary overview for ``bytetrace info``."""
    nc = console.no_color
    if _RICH_AVAILABLE:
        _render_info_rich(binary, console, explain, nc)
    else:
        _render_info_plain(binary, console, explain, nc)


def _render_info_rich(binary: Binary, console: Any, explain: bool, nc: bool) -> None:
    from rich.table import Table
    from rich.panel import Panel

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", min_width=16)
    grid.add_column()

    def row(label: str, value: str) -> None:
        grid.add_row(label, value)

    row("File",         _c(binary.name,              "bold white", nc))
    row("Path",         _c(str(binary.path),         "dim",        nc))
    row("Format",       _c(binary.fmt.value,         "bold cyan",  nc))
    row("Architecture", _c(binary.arch.value,        "bold cyan",  nc))
    row("Word size",    _c(f"{binary.bits}-bit",     "cyan",       nc))
    row("Endianness",   binary.endian.value)
    row("Entry point",  _c(f"0x{binary.entry_point:x}", "cyan",   nc))
    row("File size",    _size_str(binary.size_bytes, nc))
    row("Sections",     _c(str(len(binary.sections)), "yellow",    nc))
    row("Symbols",      _c(str(len(binary.symbols)),  "yellow",    nc))
    row("PIE",          _bool_badge(binary.is_pie,     "green", "dim", nc))
    row("Stripped",     _bool_badge(binary.is_stripped,"red",   "green", nc))
    if binary.interpreter:
        row("Interpreter", _c(binary.interpreter,    "dim",        nc))

    console.print(Panel(
        grid,
        title=f"[bold cyan]ByteTrace[/bold cyan] \u2014 {binary.name}",
        border_style="cyan",
        padding=(1, 2),
    ))

    if explain:
        _print_info_explanations(binary, console, nc)


def _render_info_plain(binary: Binary, console: Any, explain: bool, nc: bool) -> None:
    W = 62
    SEP = "─" * W
    console.print(f"\n  ByteTrace \u2014 {binary.name}")
    console.print(f"  {SEP}")

    def row(label: str, value: str) -> None:
        console.print(f"  {label:<16}  {value}")

    row("File",         binary.name)
    row("Path",         str(binary.path))
    row("Format",       binary.fmt.value)
    row("Architecture", binary.arch.value)
    row("Word size",    f"{binary.bits}-bit")
    row("Endianness",   binary.endian.value)
    row("Entry point",  f"0x{binary.entry_point:x}")
    row("File size",    f"{binary.size_bytes:,} bytes")
    row("Sections",     str(len(binary.sections)))
    row("Symbols",      str(len(binary.symbols)))
    row("PIE",          "Yes" if binary.is_pie else "No")
    row("Stripped",     "Yes" if binary.is_stripped else "No")
    if binary.interpreter:
        row("Interpreter",  binary.interpreter)
    console.print(f"  {SEP}\n")

    if explain:
        _print_info_explanations(binary, console, nc)


def _print_info_explanations(binary: Binary, console: Any, nc: bool) -> None:
    console.print(_c("  Explanations", "bold yellow", nc))
    console.print()
    if binary.is_pie:
        console.print(_c("  PIE (Position-Independent Executable)", "yellow", nc))
        console.print("  Loaded at a random base address each run (ASLR).")
        console.print("  Absolute addresses in disassembly are relative offsets.")
        console.print()
    else:
        console.print(_c("  Non-PIE (fixed base address)", "yellow", nc))
        console.print("  The binary always loads at the same virtual address.")
        console.print()
    if binary.is_stripped:
        console.print(_c("  Stripped", "yellow", nc))
        console.print("  Static symbol table removed — function names absent.")
        console.print("  Only dynamic imports (.dynsym) are available.")
        console.print()
    else:
        console.print(_c("  Not stripped", "green", nc))
        console.print("  Static symbol table present — function names visible.")
        console.print()
    if binary.interpreter:
        console.print(_c("  Dynamically linked", "yellow", nc))
        console.print(f"  Runtime linker: {binary.interpreter}")
        console.print("  Imports are resolved from shared libraries at load time.")
    else:
        console.print(_c("  Statically linked", "yellow", nc))
        console.print("  All library code is embedded — no runtime linker needed.")
    console.print()


# ═════════════════════════════════════════════════════════════════
# sections command
# ═════════════════════════════════════════════════════════════════

def render_sections(
    binary: Binary,
    console: Any,
    explain: bool = False,
    filter_flag: str | None = None,
) -> None:
    """Render the section table for ``bytetrace sections``."""
    from bytetrace.core.enums import SectionFlags

    sections = list(binary.sections)
    if filter_flag:
        flag_map = {
            "exec":  SectionFlags.EXEC,
            "write": SectionFlags.WRITE,
            "alloc": SectionFlags.ALLOC,
            "tls":   SectionFlags.TLS,
        }
        flag = flag_map.get(filter_flag.lower())
        if flag:
            sections = [s for s in sections if flag in s.flags]

    nc    = console.no_color
    title = f"Sections \u2014 {binary.name}"
    if filter_flag:
        title += f"  [filter: {filter_flag}]"

    if _RICH_AVAILABLE:
        _render_sections_rich(sections, console, explain, nc, title)
    else:
        _render_sections_plain(sections, console, explain, nc, title)


def _render_sections_rich(
    sections: list[Section], console: Any, explain: bool, nc: bool, title: str
) -> None:
    from rich.table import Table

    table = Table(
        title=title, title_style="bold cyan",
        border_style="dim", header_style="bold",
        show_lines=False, padding=(0, 1),
    )
    table.add_column("Name",   style="bold white", min_width=22, no_wrap=True)
    table.add_column("Offset", style="cyan",  justify="right", min_width=12)
    table.add_column("VAddr",  style="cyan",  justify="right", min_width=12)
    table.add_column("Size",   justify="right", min_width=10)
    table.add_column("Flags",  min_width=6)
    if explain:
        table.add_column("Purpose", style="dim", min_width=34)

    for sec in sections:
        row: list[str] = [
            sec.name,
            f"0x{sec.offset:08x}",
            f"0x{sec.vaddr:08x}",
            _size_str(sec.size, nc),
            _flag_str(sec.flags_str(), nc),
        ]
        if explain:
            row.append(section_description(sec.name))
        table.add_row(*row)

    console.print(table)
    if explain:
        console.print()
        console.print(
            _c("  Flag key: ", "dim", nc)
            + "[bold red]X[/bold red]=executable  "
            + "[yellow]W[/yellow]=writable  "
            + "[green]A[/green]=allocated in memory"
        )


def _render_sections_plain(
    sections: list[Section], console: Any, explain: bool, nc: bool, title: str
) -> None:
    console.print(f"\n  {title}")
    SEP = "─" * 74
    console.print(f"  {SEP}")
    hdr = f"  {'Name':<22} {'Offset':>12} {'VAddr':>12} {'Size':>10}  Flags"
    if explain:
        hdr += f"  Purpose"
    console.print(hdr)
    console.print(f"  {SEP}")
    for sec in sections:
        line = (
            f"  {sec.name:<22} "
            f"0x{sec.offset:08x}   "
            f"0x{sec.vaddr:08x}   "
            f"{sec.size:>8}  "
            f"{sec.flags_str() or '-':<6}"
        )
        if explain:
            line += f"  {section_description(sec.name)}"
        console.print(line)
    console.print(f"  {SEP}")
    console.print(f"  {len(sections)} section(s)")
    if explain:
        console.print()
        console.print("  Flag key: X=executable  W=writable  A=allocated in memory")


# ═════════════════════════════════════════════════════════════════
# symbols command
# ═════════════════════════════════════════════════════════════════

def render_symbols(
    binary: Binary,
    console: Any,
    explain: bool = False,
    filter_type: str | None = None,
    search: str | None = None,
    sort_by: str = "name",
) -> None:
    """
    Render the symbol table for ``bytetrace symbols``.

    Filtering, searching, and sorting are handled here so that the
    ``--json`` path in the CLI command can apply the same logic without
    duplicating it.
    """
    from bytetrace.core.enums import SymbolType

    syms = list(binary.symbols)

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

    sort_key = {
        "name":    lambda s: s.name.lower(),
        "address": lambda s: s.address,
        "size":    lambda s: -s.size,
        "type":    lambda s: s.sym_type.value,
    }.get(sort_by, lambda s: s.name.lower())
    syms = sorted(syms, key=sort_key)

    nc    = console.no_color
    parts = [f"Symbols \u2014 {binary.name}"]
    if filter_type: parts.append(f"filter: {filter_type}")
    if search:      parts.append(f"search: '{search}'")
    title = "  \u00b7  ".join(parts)

    if _RICH_AVAILABLE:
        _render_symbols_rich(syms, console, explain, nc, title)
    else:
        _render_symbols_plain(syms, console, explain, nc, title)


def _render_symbols_rich(
    syms: list[Symbol], console: Any, explain: bool, nc: bool, title: str
) -> None:
    from rich.table import Table

    table = Table(
        title=title, title_style="bold cyan",
        border_style="dim", header_style="bold",
        show_lines=False, padding=(0, 1),
    )
    table.add_column("Name",    style="bold white", min_width=32, no_wrap=True)
    table.add_column("Address", style="cyan",  justify="right", min_width=18)
    table.add_column("Size",    style="yellow", justify="right", min_width=8)
    table.add_column("Type",    min_width=10)
    table.add_column("Binding", min_width=8)
    table.add_column("Dyn",     min_width=3, justify="center")

    for sym in syms:
        addr_str = (
            _c("undefined", "dim", nc)
            if sym.is_undefined
            else f"0x{sym.address:016x}"
        )
        sz_str = _c("0", "dim", nc) if sym.size == 0 else str(sym.size)

        type_sty = "green" if sym.is_function else ("yellow" if sym.is_object else "dim")
        bind_sty = "bold"  if sym.is_global  else "dim"
        dyn_mark = _c("\u25cf", "cyan", nc) if sym.is_dynamic else _c("\u00b7", "dim", nc)

        table.add_row(
            sym.name,
            addr_str,
            sz_str,
            _c(sym.sym_type.value, type_sty, nc),
            _c(sym.binding.value,  bind_sty, nc),
            dyn_mark,
        )

    console.print(table)
    console.print(_c(f"  {len(syms)} symbol(s) shown", "dim", nc))

    if explain:
        console.print()
        _print_symbol_guide(console, nc)


def _render_symbols_plain(
    syms: list[Symbol], console: Any, explain: bool, nc: bool, title: str
) -> None:
    console.print(f"\n  {title}")
    SEP = "─" * 82
    console.print(f"  {SEP}")
    hdr = f"  {'Name':<34} {'Address':<20} {'Size':>8}  {'Type':<12} {'Bind':<8} D"
    console.print(hdr)
    console.print(f"  {SEP}")
    for sym in syms:
        addr = "undefined           " if sym.is_undefined else f"0x{sym.address:016x}    "
        dyn  = "\u25cf" if sym.is_dynamic else "\u00b7"
        console.print(
            f"  {sym.name:<34} {addr:<20} {sym.size:>8}  "
            f"{sym.sym_type.value:<12} {sym.binding.value:<8} {dyn}"
        )
    console.print(f"  {SEP}")
    console.print(f"  {len(syms)} symbol(s) shown")
    if explain:
        console.print()
        _print_symbol_guide(console, nc)


def _print_symbol_guide(console: Any, nc: bool) -> None:
    console.print(_c("  Symbol guide", "bold yellow", nc))
    console.print()
    console.print(f"  Type  {_c('function', 'green', nc):<12}  executable code (a call target)")
    console.print(f"  Type  {_c('object',   'yellow', nc):<12}  data variable or global")
    console.print(f"  Type  {_c('notype',   'dim', nc):<12}  unspecified (common after stripping)")
    console.print()
    console.print(f"  Bind  {'global':<12}  visible to the whole program")
    console.print(f"  Bind  {'local':<12}  file-scoped (C static equivalent)")
    console.print(f"  Bind  {'weak':<12}  overridable by a strong global")
    console.print()
    console.print(f"  Dyn   {_c(chr(0x25cf), 'cyan', nc)}             from .dynsym — resolved by the dynamic linker")
    console.print(f"  Dyn   {_c(chr(0xb7),   'dim', nc)}             from .symtab — static / debug info only")
    console.print()
