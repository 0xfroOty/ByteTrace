"""
ELF format parser — powered by pyelftools.

Parses ELF32 and ELF64 binaries (little-endian and big-endian) and
maps them onto ByteTrace's ``Binary``, ``Section``, and ``Symbol`` models.

Responsibilities
────────────────
• Detect ELF magic bytes (fast, no full parse).
• Read the ELF header → format, architecture, bits, endianness, entry point.
• Iterate section headers → ``Section`` objects.
• Iterate ``.symtab`` (static) and ``.dynsym`` (dynamic) symbol tables
  → ``Symbol`` objects, deduplicated by name.
• Extract the PT_INTERP interpreter path (e.g. /lib64/ld-linux-x86-64.so.2).
• Detect position-independent executables (ET_DYN type).
• Return a fully-populated ``Binary`` via ``Binary.create()``.

Out of scope for Phase 3
────────────────────────
• DWARF / debug information
• Relocation processing
• Disassembly (Phase 6)
• CFG analysis (Phase 8)
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from bytetrace.core.binary import Binary
from bytetrace.core.enums import (
    Architecture,
    BinaryFormat,
    Endianness,
    SectionFlags,
    SymbolBinding,
    SymbolType,
)
from bytetrace.core.section import Section
from bytetrace.core.symbol import Symbol
from bytetrace.formats.base import BaseParser, ParseError


# ── ELF magic ─────────────────────────────────────────────────────

_ELF_MAGIC = b"\x7fELF"

# ── e_machine string → Architecture ───────────────────────────────
# pyelftools exposes e_machine as a string like 'EM_X86_64'.

_MACHINE_TO_ARCH: dict[str, Architecture] = {
    "EM_386":     Architecture.X86,
    "EM_486":     Architecture.X86,
    "EM_ARM":     Architecture.ARM,
    "EM_X86_64":  Architecture.X86_64,
    "EM_AARCH64": Architecture.ARM64,
    "EM_MIPS":    Architecture.MIPS,
    "EM_MIPS_RS3_LE": Architecture.MIPS,
    "EM_RISCV":   Architecture.RISCV,
    "EM_PPC":     Architecture.PPC,
    "EM_PPC64":   Architecture.PPC,
}

# ── SHF_* flag bits → SectionFlags ────────────────────────────────

_SHF_WRITE     = 0x001
_SHF_ALLOC     = 0x002
_SHF_EXECINSTR = 0x004
_SHF_MERGE     = 0x010
_SHF_STRINGS   = 0x020
_SHF_TLS       = 0x400

# ── st_info type/bind string → enum ───────────────────────────────
# pyelftools exposes these as strings like 'STT_FUNC', 'STB_GLOBAL'.

_STT_TO_SYMTYPE: dict[str, SymbolType] = {
    "STT_NOTYPE":  SymbolType.NOTYPE,
    "STT_OBJECT":  SymbolType.OBJECT,
    "STT_FUNC":    SymbolType.FUNC,
    "STT_SECTION": SymbolType.SECTION,
    "STT_FILE":    SymbolType.FILE,
    "STT_TLS":     SymbolType.TLS,
}

_STB_TO_BINDING: dict[str, SymbolBinding] = {
    "STB_LOCAL":  SymbolBinding.LOCAL,
    "STB_GLOBAL": SymbolBinding.GLOBAL,
    "STB_WEAK":   SymbolBinding.WEAK,
}

# ── Section types we skip when building the section list ──────────

_SKIP_SECTION_TYPES = frozenset({
    "SHT_NULL",     # mandatory empty first entry
    "SHT_STRTAB",   # string tables are an implementation detail
    "SHT_RELA",     # relocation tables — not surfaced yet
    "SHT_REL",
})


# ═════════════════════════════════════════════════════════════════
# Public parser class
# ═════════════════════════════════════════════════════════════════


class ELFParser(BaseParser):
    """
    Parses ELF binaries using the ``pyelftools`` library.

    Install pyelftools with::

        pip install pyelftools

    If pyelftools is absent, the constructor raises ``ImportError``
    with a clear install message — this is surfaced to the user by
    the format registry in ``formats/__init__.py``.
    """

    def __init__(self) -> None:
        # Fail early with a clear message if the library is missing.
        try:
            from elftools.elf.elffile import ELFFile  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "pyelftools is required for ELF parsing.\n"
                "Install it with:  pip install pyelftools"
            ) from exc

    @property
    def name(self) -> str:
        return "ELF"

    # ── Public interface ──────────────────────────────────────────

    def detect(self, path: Path) -> bool:
        """
        Return True when *path* starts with the ELF magic bytes.

        Reads only the first 4 bytes — never raises.
        """
        try:
            with open(path, "rb") as fh:
                return fh.read(4) == _ELF_MAGIC
        except OSError:
            return False

    def parse(self, path: Path) -> Binary:
        """
        Parse an ELF binary at *path* and return a ``Binary``.

        Raises
        ──────
        ParseError   — file is not valid ELF or uses unsupported features.
        OSError      — file cannot be opened.
        """
        from elftools.elf.elffile import ELFFile

        raw = Path(path).read_bytes()

        if raw[:4] != _ELF_MAGIC:
            raise ParseError(f"'{path}' is not an ELF binary (bad magic bytes).")

        try:
            from io import BytesIO
            elf = ELFFile(BytesIO(raw))
        except Exception as exc:
            raise ParseError(f"pyelftools could not parse '{path}': {exc}") from exc

        bits    = elf.elfclass                                          # 32 or 64
        endian  = Endianness.LITTLE if elf.little_endian else Endianness.BIG
        arch    = _resolve_arch(elf.header["e_machine"])
        is_pie  = elf.header["e_type"] == "ET_DYN"

        sections    = list(_extract_sections(elf))
        symbols     = list(_extract_symbols(elf))
        interpreter = _extract_interpreter(elf)

        return Binary.create(
            path        = Path(path),
            fmt         = BinaryFormat.ELF,
            arch        = arch,
            bits        = bits,
            endian      = endian,
            entry_point = elf.header["e_entry"],
            sections    = sections,
            symbols     = symbols,
            raw         = raw,
            interpreter = interpreter,
            is_pie      = is_pie,
        )


# ═════════════════════════════════════════════════════════════════
# Private extraction helpers
# ═════════════════════════════════════════════════════════════════


def _resolve_arch(e_machine: str) -> Architecture:
    """Map a pyelftools e_machine string to an ``Architecture`` enum value."""
    return _MACHINE_TO_ARCH.get(e_machine, Architecture.UNKNOWN)


def _elf_shflags_to_section_flags(sh_flags: int) -> frozenset[SectionFlags]:
    """Translate raw SHF_* bits to a frozenset of ``SectionFlags``."""
    out: set[SectionFlags] = set()
    if sh_flags & _SHF_ALLOC:     out.add(SectionFlags.ALLOC)
    if sh_flags & _SHF_EXECINSTR: out.add(SectionFlags.EXEC)
    if sh_flags & _SHF_WRITE:     out.add(SectionFlags.WRITE)
    if sh_flags & _SHF_MERGE:     out.add(SectionFlags.MERGE)
    if sh_flags & _SHF_STRINGS:   out.add(SectionFlags.STRINGS)
    if sh_flags & _SHF_TLS:       out.add(SectionFlags.TLS)
    return frozenset(out)


def _extract_sections(elf) -> Iterator[Section]:
    """
    Yield a ``Section`` for each meaningful ELF section header.

    Skips SHT_NULL, relocation tables, and raw string tables — these
    are implementation details of the ELF format, not binary regions
    a user typically wants to inspect.
    """
    for sec in elf.iter_sections():
        # pyelftools names the type field 'sh_type' and returns a string
        sh_type: str = sec["sh_type"]

        if not sec.name:
            continue
        if sh_type in _SKIP_SECTION_TYPES:
            continue

        yield Section(
            name    = sec.name,
            offset  = sec["sh_offset"],
            vaddr   = sec["sh_addr"],
            size    = sec["sh_size"],
            flags   = _elf_shflags_to_section_flags(sec["sh_flags"]),
            align   = sec["sh_addralign"],
            link    = sec["sh_link"],
            entsize = sec["sh_entsize"],
        )


def _extract_symbols(elf) -> Iterator[Symbol]:
    """
    Yield ``Symbol`` objects from ``.symtab`` and ``.dynsym``.

    Deduplication strategy:
    • Static symbols (.symtab) are yielded first.
    • Dynamic symbols (.dynsym) are yielded only when their name was not
      already seen in .symtab — this avoids duplicating well-known
      functions like ``main`` that appear in both tables.
    • Section, file, and nameless meta-entries are discarded.
    """
    seen_names: set[str] = set()

    # Process static table first, then dynamic
    for table_name, is_dynamic in ((".symtab", False), (".dynsym", True)):
        section = elf.get_section_by_name(table_name)
        if section is None:
            continue

        # pyelftools: only SymbolTableSection has iter_symbols()
        if not hasattr(section, "iter_symbols"):
            continue

        for raw_sym in section.iter_symbols():
            sym = _build_symbol(raw_sym, is_dynamic)
            if sym is None:
                continue
            if sym.name in seen_names:
                continue
            seen_names.add(sym.name)
            yield sym


def _build_symbol(raw_sym, is_dynamic: bool) -> Symbol | None:
    """
    Convert a single pyelftools symbol object into a ``Symbol``.

    Returns None for entries that should be silently skipped:
    nameless symbols, section symbols, and file-name symbols.
    """
    name: str = raw_sym.name
    if not name:
        return None

    st_type: str = raw_sym["st_info"]["type"]
    st_bind: str = raw_sym["st_info"]["bind"]

    # Section and file symbols are ELF bookkeeping — not useful to users
    if st_type in ("STT_SECTION", "STT_FILE"):
        return None

    sym_type = _STT_TO_SYMTYPE.get(st_type, SymbolType.UNKNOWN)
    binding  = _STB_TO_BINDING.get(st_bind, SymbolBinding.UNKNOWN)

    # st_shndx is 'SHN_UNDEF' for undefined (imported) symbols,
    # 'SHN_ABS' for absolute symbols, or an integer section index.
    shndx = raw_sym["st_shndx"]
    if isinstance(shndx, str):
        section_name = ""          # SHN_UNDEF or SHN_ABS
    else:
        section_name = ""          # section name resolved at Binary level

    return Symbol(
        name       = name,
        address    = raw_sym["st_value"],
        size       = raw_sym["st_size"],
        sym_type   = sym_type,
        binding    = binding,
        section    = section_name,
        is_dynamic = is_dynamic,
    )


def _extract_interpreter(elf) -> str:
    """
    Return the ELF interpreter path from the PT_INTERP segment,
    or an empty string for static binaries.

    Compatible with both real pyelftools and the offline development stub:
    - Real pyelftools: segment['p_type'] == 'PT_INTERP', segment.data() method.
    - Offline stub:    segment['p_type'] == 'PT_INTERP', segment['_data'] bytes.
    - Fallback:        reads the .interp section header if no segments.
    """
    if hasattr(elf, "iter_segments"):
        for segment in elf.iter_segments():
            try:
                p_type = segment["p_type"]
            except (KeyError, TypeError):
                continue

            if p_type != "PT_INTERP":
                continue

            # Real pyelftools exposes a data() method on segments.
            if hasattr(segment, "data") and callable(segment.data):
                return segment.data().rstrip(b"\x00").decode("utf-8", errors="replace")

            # Offline stub stores bytes under '_data'.
            raw_data = segment.get("_data", b"")
            if isinstance(raw_data, bytes):
                return raw_data.rstrip(b"\x00").decode("utf-8", errors="replace")

    return ""
