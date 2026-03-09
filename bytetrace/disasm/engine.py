"""
Disassembly engine — powered by Capstone.

Responsibilities
────────────────
• Initialise a Capstone ``Cs`` handle for the architecture in the
  ``Binary`` model.
• Locate the bytes to disassemble (by symbol name or raw address).
• Produce a list of ``Instruction`` objects.

This module contains zero CLI logic and zero rendering logic.
It consumes ``Binary``, ``Section``, and ``Symbol`` and emits
``Instruction`` objects.  The CLI command and the renderer are
completely unaware of Capstone internals.

Supported architectures (Phase 5)
──────────────────────────────────
• x86 (32-bit)
• x86-64 (64-bit)

Architectures ARM / ARM64 / MIPS etc. can be added by extending
``_ARCH_MODE_MAP`` — no other code needs to change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from bytetrace.core.binary import Binary
from bytetrace.core.enums import Architecture
from bytetrace.core.section import Section
from bytetrace.core.symbol import Symbol


# ── Capstone architecture/mode map ────────────────────────────────
# Values are (CS_ARCH_*, CS_MODE_*) tuples.
# Populated lazily after Capstone is imported.

def _get_cs_arch_mode(arch: Architecture, bits: int):
    """
    Return (CS_ARCH_*, CS_MODE_*) for the given architecture.

    Raises ``DisasmError`` when the architecture is not supported.
    """
    try:
        import capstone as _cs
    except ImportError as exc:
        raise DisasmError(
            "Capstone is required for disassembly.\n"
            "Install it with:  pip install capstone"
        ) from exc

    # Resolve constants defensively — real capstone has all of these;
    # the offline stub may be missing ARM constants.
    CS_ARCH_X86   = getattr(_cs, "CS_ARCH_X86",   3)
    CS_ARCH_ARM   = getattr(_cs, "CS_ARCH_ARM",   1)
    CS_ARCH_ARM64 = getattr(_cs, "CS_ARCH_ARM64", 2)
    CS_MODE_32    = getattr(_cs, "CS_MODE_32",    1 << 2)
    CS_MODE_64    = getattr(_cs, "CS_MODE_64",    1 << 3)
    CS_MODE_ARM   = getattr(_cs, "CS_MODE_ARM",   0)
    CS_MODE_THUMB = getattr(_cs, "CS_MODE_THUMB", 1 << 4)

    _map = {
        Architecture.X86:    (CS_ARCH_X86,   CS_MODE_64 if bits == 64 else CS_MODE_32),
        Architecture.X86_64: (CS_ARCH_X86,   CS_MODE_64),
        Architecture.ARM:    (CS_ARCH_ARM,   CS_MODE_ARM),
        Architecture.ARM64:  (CS_ARCH_ARM64, CS_MODE_ARM),
    }
    pair = _map.get(arch)
    if pair is None:
        raise DisasmError(
            f"Architecture '{arch.value}' is not supported for disassembly yet.\n"
            f"Supported: x86, x86-64, ARM, AArch64."
        )
    return pair


# ═════════════════════════════════════════════════════════════════
# Data model
# ═════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Instruction:
    """
    A single decoded machine instruction.

    Attributes
    ──────────
    address     Virtual address of this instruction.
    mnemonic    Instruction mnemonic (e.g. ``"mov"``, ``"call"``).
    op_str      Operand string (e.g. ``"rax, rbx"``).  May be empty.
    raw         Raw bytes of the instruction.
    size        Length of the instruction in bytes.
    """

    address:  int
    mnemonic: str
    op_str:   str
    raw:      bytes
    size:     int = field(init=False)

    def __post_init__(self) -> None:
        # frozen dataclass: use object.__setattr__ to set derived field
        object.__setattr__(self, "size", len(self.raw))

    @property
    def text(self) -> str:
        """Full instruction text: ``mnemonic  op_str``."""
        if self.op_str:
            return f"{self.mnemonic:<10} {self.op_str}"
        return self.mnemonic

    def to_dict(self) -> dict:
        return {
            "address":  self.address,
            "mnemonic": self.mnemonic,
            "op_str":   self.op_str,
            "bytes":    self.raw.hex(),
            "size":     self.size,
        }

    def __repr__(self) -> str:
        return f"0x{self.address:x}: {self.text}"


# ═════════════════════════════════════════════════════════════════
# Errors
# ═════════════════════════════════════════════════════════════════


class DisasmError(Exception):
    """Raised when disassembly cannot proceed."""


# ═════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════


def disassemble_function(binary: Binary, func_name: str, count: int = 0) -> list[Instruction]:
    """
    Disassemble a function identified by symbol name.

    Parameters
    ──────────
    binary      Fully-parsed ``Binary`` object.
    func_name   Exact or case-insensitive substring match against
                symbol names.  Exact match is tried first.
    count       Maximum instructions to return (0 = entire function).

    Raises
    ──────
    DisasmError — symbol not found, or not an executable region.
    """
    sym = _resolve_symbol(binary, func_name)

    if sym.size > 0:
        # Known size: use it directly.
        code = binary.read_at_vaddr(sym.address, sym.size)
    else:
        # Unknown size: read to end of containing section or 4 KiB.
        section = _section_for_vaddr(binary, sym.address)
        if section is None:
            raise DisasmError(
                f"Symbol '{sym.name}' at {sym.address:#x} is not in any section."
            )
        max_bytes = min(section.end_vaddr - sym.address, 4096)
        code = binary.read_at_vaddr(sym.address, max_bytes)

    return _run_capstone(binary, code, sym.address, count)


def disassemble_at(
    binary:  Binary,
    address: int,
    count:   int = 50,
) -> list[Instruction]:
    """
    Disassemble *count* instructions starting at *address*.

    Raises
    ──────
    DisasmError — address is not mapped in any section.
    """
    section = _section_for_vaddr(binary, address)
    if section is None:
        raise DisasmError(
            f"Address {address:#x} is not mapped in any section."
        )
    if not section.is_executable:
        raise DisasmError(
            f"Address {address:#x} is in section '{section.name}' "
            f"which is not executable (flags: {section.flags_str()})."
        )

    max_bytes = min(section.end_vaddr - address, count * 15)   # x86 max 15 bytes/insn
    code = binary.read_at_vaddr(address, max_bytes)
    return _run_capstone(binary, code, address, count)


def disassemble_section(
    binary:  Binary,
    section: Section,
    count:   int = 0,
) -> list[Instruction]:
    """
    Disassemble an entire section (or up to *count* instructions).

    Raises
    ──────
    DisasmError — section is not executable or has no file bytes.
    """
    if not section.is_executable:
        raise DisasmError(
            f"Section '{section.name}' is not executable "
            f"(flags: {section.flags_str()})."
        )
    if section.size == 0:
        raise DisasmError(f"Section '{section.name}' is empty.")

    code = binary.read_at_offset(section.offset, section.size)
    return _run_capstone(binary, code, section.vaddr, count)


# ═════════════════════════════════════════════════════════════════
# Internal helpers
# ═════════════════════════════════════════════════════════════════


def _resolve_symbol(binary: Binary, name: str) -> Symbol:
    """
    Find a symbol by exact name, then case-insensitive substring.

    Raises ``DisasmError`` when nothing matches.
    """
    # 1. Exact match
    sym = binary.symbol_by_name(name)
    if sym is not None:
        return sym

    # 2. Case-insensitive exact
    name_lower = name.lower()
    for s in binary.symbols:
        if s.name.lower() == name_lower:
            return s

    # 3. Substring
    matches = binary.symbols_search(name)
    if not matches:
        raise DisasmError(
            f"Symbol '{name}' not found.\n"
            f"Tip: run `bytetrace symbols <binary> --search {name}` "
            f"to see available symbols."
        )
    if len(matches) == 1:
        return matches[0]

    # Multiple matches — prefer functions, then take shortest name.
    funcs = [m for m in matches if m.is_function]
    candidates = funcs if funcs else matches
    candidates.sort(key=lambda s: len(s.name))
    return candidates[0]


def _section_for_vaddr(binary: Binary, vaddr: int) -> Section | None:
    """Return the first executable section containing *vaddr*, or None."""
    # Prefer executable sections.
    for sec in binary.executable_sections:
        if sec.contains_vaddr(vaddr):
            return sec
    # Fall back to any section.
    for sec in binary.sections:
        if sec.contains_vaddr(vaddr):
            return sec
    return None


def _run_capstone(
    binary:  Binary,
    code:    bytes,
    base:    int,
    count:   int,
) -> list[Instruction]:
    """
    Invoke Capstone and collect up to *count* ``Instruction`` objects.

    ``count=0`` means decode all available bytes.
    """
    try:
        from capstone import Cs
    except ImportError as exc:
        raise DisasmError(
            "Capstone is required for disassembly.\n"
            "Install it with:  pip install capstone"
        ) from exc

    arch, mode = _get_cs_arch_mode(binary.arch, binary.bits)
    cs = Cs(arch, mode)

    instructions: list[Instruction] = []
    for raw_insn in cs.disasm(code, base):
        instructions.append(Instruction(
            address  = raw_insn.address,
            mnemonic = raw_insn.mnemonic,
            op_str   = raw_insn.op_str,
            raw      = bytes(raw_insn.bytes),
        ))
        if count and len(instructions) >= count:
            break

    if not instructions:
        raise DisasmError(
            f"No instructions decoded at {base:#x}. "
            f"The address may point to data, not code."
        )

    return instructions
