"""
Hex inspection analysis.

Converts a byte slice from a ``Binary`` into a sequence of
``HexLine`` objects suitable for rendering as a classic hexdump -C
style display.

No CLI or rendering logic lives in this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from bytetrace.core.binary import Binary


# ═════════════════════════════════════════════════════════════════
# Data model
# ═════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class HexLine:
    """
    One row of a hexdump display.

    Attributes
    ──────────
    offset      File offset of the first byte on this line.
    vaddr       Virtual address of the first byte (0 if unmapped).
    data        Raw bytes for this line (1–width bytes).
    width       Column width requested (typically 16).
    """

    offset: int
    vaddr:  int
    data:   bytes
    width:  int

    @property
    def hex_cols(self) -> list[str]:
        """Hex byte columns, padded to *width* entries."""
        cols = [f"{b:02x}" for b in self.data]
        cols += ["  "] * (self.width - len(cols))  # right-pad short last line
        return cols

    @property
    def ascii_col(self) -> str:
        """ASCII representation: printable bytes kept, others replaced by '.'."""
        return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in self.data)

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "vaddr":  self.vaddr,
            "hex":    " ".join(f"{b:02x}" for b in self.data),
            "ascii":  self.ascii_col,
            "bytes":  list(self.data),
        }


# ═════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════


class HexdumpError(Exception):
    """Raised when hexdump parameters are invalid."""


def hexdump_section(
    binary:       Binary,
    section_name: str,
    width:        int = 16,
    max_bytes:    int = 0,
) -> list[HexLine]:
    """
    Return hexdump lines for a named section.

    Parameters
    ──────────
    binary          Parsed ``Binary`` object.
    section_name    Name of the section to dump.
    width           Bytes per line (default 16).
    max_bytes       Maximum bytes to return (0 = entire section).

    Raises
    ──────
    HexdumpError — section not found.
    """
    section = binary.section_by_name(section_name)
    if section is None:
        raise HexdumpError(
            f"Section '{section_name}' not found.\n"
            f"Available sections: "
            + ", ".join(s.name for s in binary.sections)
        )
    size = section.size if not max_bytes else min(section.size, max_bytes)
    data = binary.read_at_offset(section.offset, size)
    return list(_lines(data, section.offset, section.vaddr, width))


def hexdump_offset(
    binary:  Binary,
    offset:  int,
    size:    int,
    width:   int = 16,
) -> list[HexLine]:
    """
    Return hexdump lines for *size* bytes starting at file *offset*.

    Parameters
    ──────────
    binary  Parsed ``Binary`` object.
    offset  File offset to start reading from.
    size    Number of bytes to read.
    width   Bytes per line (default 16).

    Raises
    ──────
    HexdumpError — offset or size out of range.
    """
    if offset < 0 or offset >= binary.size_bytes:
        raise HexdumpError(
            f"Offset {offset:#x} is out of range "
            f"(file size is {binary.size_bytes:#x})."
        )
    if size <= 0:
        raise HexdumpError("Size must be greater than zero.")

    # Clamp to file size
    actual_size = min(size, binary.size_bytes - offset)
    data = binary.read_at_offset(offset, actual_size)

    # Resolve virtual address for the offset, if mapped
    vaddr = _vaddr_for_offset(binary, offset)
    return list(_lines(data, offset, vaddr, width))


# ═════════════════════════════════════════════════════════════════
# Internal helpers
# ═════════════════════════════════════════════════════════════════


def _vaddr_for_offset(binary: Binary, offset: int) -> int:
    """Return the virtual address corresponding to *offset*, or 0."""
    for sec in binary.sections:
        if sec.size > 0 and sec.offset <= offset < sec.offset + sec.size:
            return sec.vaddr + (offset - sec.offset)
    return 0


def _lines(
    data:        bytes,
    base_offset: int,
    base_vaddr:  int,
    width:       int,
) -> Iterator[HexLine]:
    """Yield ``HexLine`` objects, one per *width* bytes."""
    if width < 1:
        width = 16
    for i in range(0, len(data), width):
        chunk  = data[i: i + width]
        vaddr  = (base_vaddr + i) if base_vaddr else 0
        yield HexLine(
            offset = base_offset + i,
            vaddr  = vaddr,
            data   = chunk,
            width  = width,
        )
