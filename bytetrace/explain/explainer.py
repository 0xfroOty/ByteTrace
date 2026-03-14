"""
Instruction explanation engine.

Public API
──────────
    from bytetrace.explain.explainer import explain_instruction, explain_instructions

``explain_instruction(mnemonic, op_str, sym_lookup)``
    Returns a short plain-English string for one instruction.

``explain_instructions(instructions, sym_lookup)``
    Returns a parallel list of strings, one per Instruction.

Design
──────
Resolution order:
  1. Operand-pattern match (most specific, context-aware).
  2. Mnemonic table lookup (covers all ~150 known mnemonics).
  3. Prefix-based fallback (catches jcc, setcc, cmovcc variants
     not explicitly listed).
  4. Generic "unknown instruction" fallback.

The engine is intentionally free of Click, Rich, and any other
bytetrace module beyond ``patterns.py``.
"""

from __future__ import annotations

from bytetrace.explain.patterns import MNEMONICS, _match_pattern


# ── Call target annotation helper ────────────────────────────────

def _annotate_call_target(op_str: str, sym_lookup: dict[int, str]) -> str | None:
    """
    If op_str is a known function address, return an explanation that
    names the callee.  Otherwise return None.
    """
    if not sym_lookup:
        return None
    stripped = op_str.strip()
    if stripped.startswith("0x"):
        try:
            addr = int(stripped, 16)
            name = sym_lookup.get(addr)
            if name:
                return f"Call {name}()"
        except ValueError:
            pass
    return None


# ── Prefix-based fallback table ───────────────────────────────────

_PREFIX_FALLBACKS: list[tuple[str, str]] = [
    ("cmov",   "Conditionally move if flag condition is met"),
    ("set",    "Set byte register to 0 or 1 based on flag condition"),
    ("j",      "Conditional jump based on flag state"),
    ("rep ",   "Repeat following string operation RCX times"),
    ("repe ",  "Repeat while equal (ZF=1) and RCX > 0"),
    ("repne ", "Repeat while not equal (ZF=0) and RCX > 0"),
]


def _fallback_by_prefix(mnemonic: str) -> str | None:
    m = mnemonic.lower()
    for prefix, explanation in _PREFIX_FALLBACKS:
        if m.startswith(prefix):
            return explanation
    return None


# ═════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════


def explain_instruction(
    mnemonic:   str,
    op_str:     str,
    sym_lookup: dict[int, str] | None = None,
) -> str:
    """
    Return a plain-English explanation for one instruction.

    Parameters
    ──────────
    mnemonic    Instruction mnemonic (e.g. ``"mov"``, ``"jne"``).
    op_str      Operand string (e.g. ``"rbp, rsp"``).  May be empty.
    sym_lookup  Optional ``{address: name}`` dict for annotating
                call/jump targets with symbol names.

    Resolution order
    ────────────────
    1. Call-target annotation (when mnemonic is ``call`` and target
       is a known symbol).
    2. Operand-context pattern match.
    3. Mnemonic table lookup.
    4. Prefix-based fallback (covers jcc/setcc/cmovcc families).
    5. Generic unknown fallback.
    """
    lookup = sym_lookup or {}

    # 1. Named call target
    if mnemonic.lower() in ("call",) and op_str:
        named = _annotate_call_target(op_str, lookup)
        if named:
            return named

    # 2. Operand-pattern match (most specific)
    pattern_hit = _match_pattern(mnemonic, op_str)
    if pattern_hit:
        return pattern_hit

    # 3. Mnemonic table
    table_hit = MNEMONICS.get(mnemonic.lower())
    if table_hit:
        return table_hit

    # 4. Prefix fallback (jcc, setcc, cmovcc, rep variants)
    prefix_hit = _fallback_by_prefix(mnemonic)
    if prefix_hit:
        return prefix_hit

    # 5. Generic
    return f"Machine instruction '{mnemonic}' — no explanation available"


def explain_instructions(
    instructions: "list",           # list[Instruction] — avoid circular import
    sym_lookup:   dict[int, str] | None = None,
) -> list[str]:
    """
    Return a parallel list of explanations for *instructions*.

    The returned list has exactly ``len(instructions)`` entries;
    index *i* corresponds to ``instructions[i]``.
    """
    lookup = sym_lookup or {}
    return [
        explain_instruction(insn.mnemonic, insn.op_str, lookup)
        for insn in instructions
    ]
