"""
Control Flow Graph builder.

Responsibilities
────────────────
• Accept a ``Binary`` object and a target (function name or address).
• Call the disassembler engine to obtain a flat instruction stream.
• Partition instructions into ``BasicBlock`` objects (leader detection).
• Classify inter-block edges: jump, cjump, call, fall-through.
• Return a ``CFGraph`` wrapping a ``networkx.DiGraph``.

This module is intentionally free of CLI and rendering logic.
It depends only on ``bytetrace.disasm`` and ``bytetrace.core``.

Edge type vocabulary
────────────────────
  "fall"    — sequential fall-through (no branch taken)
  "jump"    — unconditional direct jump
  "cjump"   — conditional jump (branch taken)
  "call"    — direct CALL instruction (informational, not a cfg edge)
  "ret"     — block ends in a return; no successor
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

import networkx as nx

from bytetrace.core.binary import Binary
from bytetrace.disasm.engine import (
    DisasmError,
    Instruction,
    disassemble_at,
    disassemble_function,
)


# ══════════════════════════════════════════════════════════════════
# Instruction classification helpers
# ══════════════════════════════════════════════════════════════════

# Mnemonics that unconditionally transfer control
_UNCOND_JUMPS: frozenset[str] = frozenset({
    "jmp", "ljmp",
})

# Mnemonics that conditionally transfer control
_COND_JUMPS: frozenset[str] = frozenset({
    "je",  "jne", "jz",  "jnz",
    "jl",  "jle", "jg",  "jge",
    "jb",  "jbe", "ja",  "jae",
    "js",  "jns", "jp",  "jnp",
    "jo",  "jno",
    "jrcxz", "jecxz",
    "loop", "loope", "loopne",
})

# Mnemonics that terminate a block without successors (in our model)
_TERMINATORS: frozenset[str] = frozenset({
    "ret", "retn", "retf", "hlt", "ud2",
})

# Call mnemonics — treated as pass-through (block does NOT split here)
_CALLS: frozenset[str] = frozenset({
    "call", "lcall",
})


def _is_direct_branch(insn: Instruction) -> tuple[bool, int | None]:
    """
    Return (is_direct, target_address).

    A "direct" branch has a plain hex address as its operand string,
    e.g. ``jne 0xde50``.  Indirect branches (``jmp [rax]``) return
    ``(True, None)`` — they still end the block but we cannot know
    the target statically.
    """
    mnem = insn.mnemonic
    if mnem not in (_UNCOND_JUMPS | _COND_JUMPS):
        return False, None
    op = insn.op_str.strip()
    if op.startswith("0x") or op.startswith("0X"):
        try:
            return True, int(op, 16)
        except ValueError:
            pass
    # Indirect or register operand
    return True, None


def _is_terminator(insn: Instruction) -> bool:
    return insn.mnemonic in _TERMINATORS


def _is_unconditional(insn: Instruction) -> bool:
    return insn.mnemonic in _UNCOND_JUMPS


def _is_conditional(insn: Instruction) -> bool:
    return insn.mnemonic in _COND_JUMPS


# ══════════════════════════════════════════════════════════════════
# Data models
# ══════════════════════════════════════════════════════════════════


@dataclass
class BasicBlock:
    """
    A maximal sequence of instructions with a single entry point and
    a single exit (the last instruction).

    Attributes
    ──────────
    start_address   Virtual address of the first instruction.
    instructions    Ordered list of ``Instruction`` objects.
    successors      Addresses of known successor blocks.
                    Empty for return/hlt/ud2 terminators.
    edge_kinds      Parallel list of edge kinds for each successor.
                    Values: ``"fall"`` | ``"jump"`` | ``"cjump"``.
    """

    start_address: int
    instructions:  list[Instruction] = field(default_factory=list)
    successors:    list[int]         = field(default_factory=list)
    edge_kinds:    list[str]         = field(default_factory=list)

    # ── derived properties ────────────────────────────────────────

    @property
    def end_address(self) -> int:
        """Address of the byte immediately after the last instruction."""
        if not self.instructions:
            return self.start_address
        last = self.instructions[-1]
        return last.address + last.size

    @property
    def size(self) -> int:
        """Total byte span of the block."""
        return self.end_address - self.start_address

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def last_instruction(self) -> Instruction | None:
        return self.instructions[-1] if self.instructions else None

    @property
    def is_return(self) -> bool:
        li = self.last_instruction
        return li is not None and li.mnemonic in _TERMINATORS

    def to_dict(self) -> dict:
        return {
            "start":        self.start_address,
            "end":          self.end_address,
            "size":         self.size,
            "instructions": [i.to_dict() for i in self.instructions],
            "successors":   self.successors,
            "edge_kinds":   self.edge_kinds,
            "is_return":    self.is_return,
        }

    def __hash__(self) -> int:
        return hash(self.start_address)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, BasicBlock) and self.start_address == other.start_address

    def __repr__(self) -> str:
        return (f"BasicBlock(start={self.start_address:#x}, "
                f"insns={self.instruction_count}, "
                f"succs={[hex(s) for s in self.successors]})")


# ══════════════════════════════════════════════════════════════════
# CFGraph wrapper
# ══════════════════════════════════════════════════════════════════


class CFGraph:
    """
    A Control Flow Graph for a single function.

    Wraps a ``networkx.DiGraph`` where:
    • Nodes are ``int`` start addresses.
    • Node attribute ``"block"`` holds the ``BasicBlock`` object.
    • Edge attribute ``"kind"`` is one of ``"fall"``, ``"jump"``, ``"cjump"``.

    Attributes
    ──────────
    entry           Start address of the function entry block.
    graph           The underlying ``nx.DiGraph``.
    """

    def __init__(self, entry: int) -> None:
        self.entry: int = entry
        self.graph: nx.DiGraph = nx.DiGraph()

    # ── block management ─────────────────────────────────────────

    def add_block(self, block: BasicBlock) -> None:
        self.graph.add_node(block.start_address, block=block)

    def add_edge(self, src: int, dst: int, kind: str = "fall") -> None:
        self.graph.add_edge(src, dst, kind=kind)

    def get_block(self, address: int) -> BasicBlock | None:
        data = self.graph.nodes.get(address)
        if data is None:
            return None
        return data.get("block")

    # ── iteration ────────────────────────────────────────────────

    def blocks(self) -> Iterator[BasicBlock]:
        """Yield all basic blocks in address order."""
        for addr in sorted(self.graph.nodes):
            blk = self.graph.nodes[addr].get("block")
            if blk is not None:
                yield blk

    def edges(self) -> Iterator[tuple[int, int, str]]:
        """Yield (src_addr, dst_addr, kind) tuples."""
        for u, v, data in self.graph.edges(data=True):
            yield u, v, data.get("kind", "?")

    # ── stats ────────────────────────────────────────────────────

    @property
    def block_count(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    @property
    def instruction_count(self) -> int:
        return sum(b.instruction_count for b in self.blocks())

    @property
    def cyclomatic_complexity(self) -> int:
        """
        McCabe's cyclomatic complexity: E − N + 2P
        For a single connected component, P=1.
        """
        e = self.graph.number_of_edges()
        n = self.graph.number_of_nodes()
        return max(1, e - n + 2)

    def to_dict(self) -> dict:
        return {
            "entry":                 self.entry,
            "block_count":           self.block_count,
            "edge_count":            self.edge_count,
            "instruction_count":     self.instruction_count,
            "cyclomatic_complexity": self.cyclomatic_complexity,
            "blocks": [b.to_dict() for b in self.blocks()],
            "edges":  [
                {"src": u, "dst": v, "kind": k}
                for u, v, k in self.edges()
            ],
        }


# ══════════════════════════════════════════════════════════════════
# Errors
# ══════════════════════════════════════════════════════════════════


class CFGError(Exception):
    """Raised when CFG construction cannot proceed."""


# ══════════════════════════════════════════════════════════════════
# Public builder API
# ══════════════════════════════════════════════════════════════════


def build_cfg_from_function(
    binary:    Binary,
    func_name: str,
    max_insns: int = 500,
) -> CFGraph:
    """
    Build a CFG for a function identified by symbol name.

    Parameters
    ──────────
    binary      Parsed ``Binary`` object.
    func_name   Symbol name (exact or substring match).
    max_insns   Safety limit on instructions to disassemble.

    Raises
    ──────
    CFGError — symbol not found or disassembly failed.
    """
    try:
        instructions = disassemble_function(binary, func_name, count=max_insns)
    except DisasmError as exc:
        raise CFGError(str(exc)) from exc

    if not instructions:
        raise CFGError(f"No instructions decoded for '{func_name}'.")

    return _build(instructions, instructions[0].address)


def build_cfg_from_address(
    binary:    Binary,
    address:   int,
    max_insns: int = 500,
) -> CFGraph:
    """
    Build a CFG starting at *address*.

    Parameters
    ──────────
    binary      Parsed ``Binary`` object.
    address     Entry virtual address.
    max_insns   Maximum instructions to decode.

    Raises
    ──────
    CFGError — address not mapped or disassembly failed.
    """
    try:
        instructions = disassemble_at(binary, address, count=max_insns)
    except DisasmError as exc:
        raise CFGError(str(exc)) from exc

    if not instructions:
        raise CFGError(f"No instructions decoded at {address:#x}.")

    return _build(instructions, address)


# ══════════════════════════════════════════════════════════════════
# Core algorithm
# ══════════════════════════════════════════════════════════════════


def _build(instructions: list[Instruction], entry: int) -> CFGraph:
    """
    Partition *instructions* into basic blocks and build the CFG.

    Algorithm
    ─────────
    Pass 1 — leader detection:
      An instruction is a "leader" (first instruction of a basic block)
      if it is:
        (a) the very first instruction, OR
        (b) the target of any branch, OR
        (c) the fall-through successor of a conditional/unconditional
            branch (i.e. the instruction immediately after a branch).

    Pass 2 — block construction:
      Partition instructions between consecutive leaders.  Each block
      ends at the instruction immediately before the next leader (or
      at the last instruction in the stream).

    Pass 3 — edge construction:
      For each block, inspect its last instruction:
        • Conditional jump  → cjump edge to target + fall edge to next
        • Unconditional jmp → jump edge to target (no fall-through)
        • Ret / hlt / ud2   → no outgoing edges
        • Otherwise         → fall-through edge to next block
    """
    cfg = CFGraph(entry=entry)

    # ── Pass 1: collect leader addresses ─────────────────────────
    addr_to_insn: dict[int, Instruction] = {i.address: i for i in instructions}
    leaders: set[int] = {instructions[0].address}

    for insn in instructions:
        is_branch, target = _is_direct_branch(insn)
        if is_branch:
            # The instruction after a branch is a leader (fall-through)
            fall_addr = insn.address + insn.size
            if fall_addr in addr_to_insn:
                leaders.add(fall_addr)
            # The branch target is a leader (only if within our range)
            if target is not None and target in addr_to_insn:
                leaders.add(target)
        elif _is_terminator(insn):
            # Instruction after a terminator is a leader
            fall_addr = insn.address + insn.size
            if fall_addr in addr_to_insn:
                leaders.add(fall_addr)

    leaders_sorted: list[int] = sorted(leaders)

    # ── Pass 2: build BasicBlock objects ─────────────────────────
    leader_set = set(leaders_sorted)
    blocks: dict[int, BasicBlock] = {}
    current_block: BasicBlock | None = None

    for insn in instructions:
        if insn.address in leader_set:
            current_block = BasicBlock(start_address=insn.address)
            blocks[insn.address] = current_block
        if current_block is not None:
            current_block.instructions.append(insn)

    # ── Pass 3: add edges ─────────────────────────────────────────
    for block in blocks.values():
        cfg.add_block(block)

    for block in blocks.values():
        last = block.last_instruction
        if last is None:
            continue

        fall_addr = last.address + last.size

        if _is_terminator(last):
            # ret / hlt / ud2 — no successors
            continue

        is_branch, target = _is_direct_branch(last)

        if is_branch:
            if _is_unconditional(last):
                # Unconditional: only the jump target
                if target is not None and target in blocks:
                    block.successors.append(target)
                    block.edge_kinds.append("jump")
                    cfg.add_edge(block.start_address, target, kind="jump")
                # (indirect jumps: no edge added — target unknown)
            else:
                # Conditional: branch-taken edge + fall-through edge
                if target is not None and target in blocks:
                    block.successors.append(target)
                    block.edge_kinds.append("cjump")
                    cfg.add_edge(block.start_address, target, kind="cjump")
                if fall_addr in blocks:
                    block.successors.append(fall_addr)
                    block.edge_kinds.append("fall")
                    cfg.add_edge(block.start_address, fall_addr, kind="fall")
        else:
            # Fall-through (including calls — they return here)
            if fall_addr in blocks:
                block.successors.append(fall_addr)
                block.edge_kinds.append("fall")
                cfg.add_edge(block.start_address, fall_addr, kind="fall")

    return cfg
