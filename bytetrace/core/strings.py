"""
String extraction analysis.

Scans raw bytes for runs of printable ASCII characters and returns
``ExtractedString`` objects.  No CLI or rendering logic lives here.

Definition of "printable ASCII"
────────────────────────────────
A byte is printable if it satisfies ``0x20 <= b <= 0x7E`` (space
through tilde) or is a common control character that appears in text
files: tab (0x09), newline (0x0A), carriage return (0x0D).

A run must reach *min_len* printable bytes before any non-printable
byte to qualify as a string.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from bytetrace.core.binary import Binary
from bytetrace.core.section import Section


# ── printable byte test ───────────────────────────────────────────

def _is_printable(b: int) -> bool:
    return (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0D)


# ═════════════════════════════════════════════════════════════════
# Data model
# ═════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ExtractedString:
    """
    A run of printable ASCII bytes found in a binary.

    Attributes
    ──────────
    value       The string text (decoded as ASCII, replacing unknowns).
    offset      File offset of the first byte.
    vaddr       Virtual address, or 0 if the region has no load address.
    section     Section name the string was found in, or empty string.
    length      Number of bytes (same as ``len(value)``).
    """

    value:   str
    offset:  int
    vaddr:   int
    section: str
    length:  int

    def to_dict(self) -> dict:
        return {
            "value":   self.value,
            "offset":  self.offset,
            "vaddr":   self.vaddr,
            "section": self.section,
            "length":  self.length,
        }

    def __repr__(self) -> str:
        return f"ExtractedString(offset={self.offset:#x}, {self.value!r})"


# ═════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════


def extract_strings(
    binary:      Binary,
    min_len:     int = 4,
    section_name: str | None = None,
) -> list[ExtractedString]:
    """
    Extract printable ASCII strings from *binary*.

    Parameters
    ──────────
    binary          Parsed ``Binary`` object.
    min_len         Minimum run length to qualify (default 4).
    section_name    If given, scan only this section; otherwise scan
                    the entire file, annotating each string with
                    whichever section it falls in (if any).

    Returns a list of ``ExtractedString`` objects sorted by file offset.

    Raises
    ──────
    ValueError — if *section_name* is specified but not found.
    """
    if min_len < 1:
        min_len = 1

    if section_name:
        section = binary.section_by_name(section_name)
        if section is None:
            raise ValueError(
                f"Section '{section_name}' not found.\n"
                f"Available sections: "
                + ", ".join(s.name for s in binary.sections)
            )
        return list(_scan_section(binary, section, min_len))

    # Whole-file scan
    return list(_scan_whole_file(binary, min_len))


# ═════════════════════════════════════════════════════════════════
# Internal scanners
# ═════════════════════════════════════════════════════════════════


def _scan_bytes(
    data:        bytes,
    base_offset: int,
    base_vaddr:  int,
    section_name: str,
    min_len:     int,
) -> Iterator[ExtractedString]:
    """
    Scan *data* for printable-ASCII runs of at least *min_len* bytes.

    *base_offset* is the file offset of data[0].
    *base_vaddr* is the virtual address of data[0] (0 if not mapped).
    """
    run_start: int | None = None
    run_chars: list[int] = []

    for i, byte in enumerate(data):
        if _is_printable(byte):
            if run_start is None:
                run_start = i
            run_chars.append(byte)
        else:
            if run_start is not None and len(run_chars) >= min_len:
                text = bytes(run_chars).decode("ascii", errors="replace")
                file_off = base_offset + run_start
                vaddr    = (base_vaddr + run_start) if base_vaddr else 0
                yield ExtractedString(
                    value   = text,
                    offset  = file_off,
                    vaddr   = vaddr,
                    section = section_name,
                    length  = len(run_chars),
                )
            run_start = None
            run_chars = []

    # Flush any trailing run
    if run_start is not None and len(run_chars) >= min_len:
        text = bytes(run_chars).decode("ascii", errors="replace")
        file_off = base_offset + run_start
        vaddr    = (base_vaddr + run_start) if base_vaddr else 0
        yield ExtractedString(
            value   = text,
            offset  = file_off,
            vaddr   = vaddr,
            section = section_name,
            length  = len(run_chars),
        )


def _scan_section(
    binary:  Binary,
    section: Section,
    min_len: int,
) -> Iterator[ExtractedString]:
    data = binary.read_at_offset(section.offset, section.size)
    yield from _scan_bytes(data, section.offset, section.vaddr,
                           section.name, min_len)


def _scan_whole_file(binary: Binary, min_len: int) -> Iterator[ExtractedString]:
    """
    Scan the entire raw file, annotating each string with its section.

    Builds a sorted list of (start_offset, end_offset, section) spans
    for fast O(log n) lookup, then scans the raw bytes once.
    """
    # Build offset-span → section mapping
    spans: list[tuple[int, int, Section]] = []
    for sec in binary.sections:
        if sec.size > 0 and sec.offset > 0:
            spans.append((sec.offset, sec.offset + sec.size, sec))
    spans.sort()

    def _section_at(offset: int) -> tuple[str, int]:
        """Return (section_name, vaddr_base) for *offset*, or ('', 0)."""
        lo, hi = 0, len(spans) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end, sec = spans[mid]
            if offset < start:
                hi = mid - 1
            elif offset >= end:
                lo = mid + 1
            else:
                return sec.name, sec.vaddr - sec.offset
        return "", 0

    # Single pass over all raw bytes; yield strings with proper section info.
    raw = binary.raw
    run_start: int | None = None
    run_chars: list[int] = []

    for i, byte in enumerate(raw):
        if _is_printable(byte):
            if run_start is None:
                run_start = i
            run_chars.append(byte)
        else:
            if run_start is not None and len(run_chars) >= min_len:
                sec_name, vaddr_delta = _section_at(run_start)
                vaddr = (run_start + vaddr_delta) if vaddr_delta else 0
                text  = bytes(run_chars).decode("ascii", errors="replace")
                yield ExtractedString(
                    value   = text,
                    offset  = run_start,
                    vaddr   = vaddr,
                    section = sec_name,
                    length  = len(run_chars),
                )
            run_start = None
            run_chars = []

    if run_start is not None and len(run_chars) >= min_len:
        sec_name, vaddr_delta = _section_at(run_start)
        vaddr = (run_start + vaddr_delta) if vaddr_delta else 0
        text  = bytes(run_chars).decode("ascii", errors="replace")
        yield ExtractedString(
            value   = text,
            offset  = run_start,
            vaddr   = vaddr,
            section = sec_name,
            length  = len(run_chars),
        )
