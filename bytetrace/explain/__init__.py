"""
ByteTrace instruction explanation engine.

Public API:
    from bytetrace.explain import explain_instruction, explain_instructions, MNEMONICS
"""
from bytetrace.explain.explainer import explain_instruction, explain_instructions
from bytetrace.explain.patterns import MNEMONICS

__all__ = ["explain_instruction", "explain_instructions", "MNEMONICS"]
