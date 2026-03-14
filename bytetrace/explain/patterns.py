"""
x86-64 instruction explanation patterns.

This module is a pure data layer — no imports from bytetrace,
no Click, no Rich.  It can be read, extended, and unit-tested in
complete isolation.

Structure
─────────
``MNEMONICS``
    dict[str, str] — mnemonic → one-line plain-English summary.
    Used when no operand context is available or for the default
    explanation in the engine.

``_OPERAND_PATTERNS``
    list of (re_mnemonic, re_ops, explanation) triples.
    Each triple matches a (mnemonic, op_str) pair and returns a
    richer, context-aware explanation.  Patterns are tried in order;
    the first match wins.

Extending
─────────
To add an instruction:
    1. Add an entry to ``MNEMONICS``.
    2. Optionally add one or more operand-specific patterns to
       ``_OPERAND_PATTERNS`` for richer explanations.
"""

from __future__ import annotations

# ═════════════════════════════════════════════════════════════════
# Mnemonic-level explanations  (mnemonic → summary string)
# ═════════════════════════════════════════════════════════════════

MNEMONICS: dict[str, str] = {

    # ── Stack ─────────────────────────────────────────────────────
    "push":   "Push value onto stack; decrements RSP by operand size",
    "pop":    "Pop top-of-stack value into register; increments RSP",
    "enter":  "Create stack frame: push RBP, set RBP=RSP, reserve local space",
    "leave":  "Tear down stack frame: MOV RSP,RBP then POP RBP",
    "pusha":  "Push all general-purpose registers (32-bit only)",
    "popa":   "Pop all general-purpose registers (32-bit only)",
    "pushfq": "Push RFLAGS register onto stack",
    "popfq":  "Pop top of stack into RFLAGS register",

    # ── Data movement ─────────────────────────────────────────────
    "mov":    "Copy value from source to destination (no flags affected)",
    "movzx":  "Move with zero-extension: copy smaller value, zero-fill upper bits",
    "movsx":  "Move with sign-extension: copy smaller value, sign-fill upper bits",
    "movsxd": "Sign-extend 32-bit register into 64-bit register",
    "lea":    "Load effective address: compute address expression, store pointer (no memory access)",
    "xchg":   "Atomically swap the two operands",
    "movs":   "Move string: copy one element from [RSI] to [RDI], advance both pointers",
    "movsb":  "Move byte from [RSI] to [RDI], advance both pointers",
    "movsw":  "Move word from [RSI] to [RDI], advance both pointers",
    "movsd":  "Move dword from [RSI] to [RDI]; or move scalar double-precision float",
    "movsq":  "Move qword from [RSI] to [RDI], advance both pointers",
    "rep movsb": "Repeat MOVSB RCX times: bulk byte copy (memcpy-style)",
    "rep movsq": "Repeat MOVSQ RCX times: bulk qword copy (memcpy-style)",
    "rep movsw": "Repeat MOVSW RCX times: bulk word copy",
    "rep movsd": "Repeat MOVSD RCX times: bulk dword copy",
    "rep stosb": "Repeat STOSB RCX times: bulk byte fill (memset-style)",
    "rep stosq": "Repeat STOSQ RCX times: bulk qword fill (memset-style)",
    "repe cmpsb": "Compare bytes at [RSI] and [RDI] while equal (string compare)",
    "repne scasb": "Scan [RDI] for AL byte while not equal (strlen/strchr-style)",
    "repe scasb": "Scan [RDI] for AL byte while equal",
    "cmov":   "Conditionally copy source to destination if flag condition is met",
    "cmove":  "Move if equal (ZF=1)",
    "cmovne": "Move if not equal (ZF=0)",
    "cmovz":  "Move if zero flag set (ZF=1)",
    "cmovnz": "Move if zero flag clear (ZF=0)",
    "cmovl":  "Move if less than (SF≠OF)",
    "cmovle": "Move if less than or equal (ZF=1 or SF≠OF)",
    "cmovg":  "Move if greater than (ZF=0 and SF=OF)",
    "cmovge": "Move if greater than or equal (SF=OF)",
    "cmovb":  "Move if below / carry set (CF=1) — unsigned less-than",
    "cmovnb": "Move if not below / carry clear (CF=0) — unsigned ≥",
    "cmova":  "Move if above (CF=0 and ZF=0) — unsigned greater-than",
    "cmovbe": "Move if below or equal (CF=1 or ZF=1) — unsigned ≤",
    "cmovc":  "Move if carry flag set",
    "cmovnc": "Move if carry flag clear",
    "cmovs":  "Move if sign flag set (negative result)",
    "cmovns": "Move if sign flag clear (non-negative result)",
    "cmovp":  "Move if parity flag set",
    "cmovnp": "Move if parity flag clear",
    "cmovo":  "Move if overflow flag set",
    "cmovno": "Move if overflow flag clear",

    # ── Arithmetic ────────────────────────────────────────────────
    "add":    "Add source to destination; sets CF/OF/SF/ZF/PF/AF",
    "sub":    "Subtract source from destination; sets CF/OF/SF/ZF/PF/AF",
    "mul":    "Unsigned multiply: RDX:RAX ← RAX × operand",
    "imul":   "Signed multiply; 1-operand form: RDX:RAX ← RAX × src",
    "div":    "Unsigned divide RDX:RAX by operand; quotient→RAX, remainder→RDX",
    "idiv":   "Signed divide RDX:RAX by operand; quotient→RAX, remainder→RDX",
    "inc":    "Increment operand by 1; does NOT affect CF",
    "dec":    "Decrement operand by 1; does NOT affect CF",
    "neg":    "Two's-complement negate: result = 0 − operand",
    "adc":    "Add with carry: destination += source + CF",
    "sbb":    "Subtract with borrow: destination −= source + CF",
    "cdqe":   "Sign-extend EAX into RAX (fill upper 32 bits with sign bit)",
    "cdq":    "Sign-extend EAX into EDX:EAX",
    "cqo":    "Sign-extend RAX into RDX:RAX (for IDIV setup)",
    "cwde":   "Sign-extend AX into EAX",

    # ── Logic & bit manipulation ──────────────────────────────────
    "and":    "Bitwise AND; clears CF/OF, sets SF/ZF/PF",
    "or":     "Bitwise OR; clears CF/OF, sets SF/ZF/PF",
    "xor":    "Bitwise XOR; clears CF/OF, sets SF/ZF/PF",
    "not":    "Bitwise NOT (one's complement); does not affect flags",
    "test":   "AND operands and set flags, discard result (non-destructive AND)",
    "cmp":    "Subtract operands and set flags, discard result (non-destructive SUB)",
    "bsf":    "Bit scan forward: find index of lowest set bit",
    "bsr":    "Bit scan reverse: find index of highest set bit",
    "bswap":  "Byte-swap register (reverse byte order for endianness conversion)",
    "bt":     "Bit test: copy bit N of operand into CF",
    "bts":    "Bit test and set: copy bit into CF, then set it",
    "btr":    "Bit test and reset: copy bit into CF, then clear it",
    "btc":    "Bit test and complement: copy bit into CF, then flip it",
    "popcnt": "Count number of set bits (population count / Hamming weight)",

    # ── Shifts and rotates ────────────────────────────────────────
    "shl":    "Shift left logical (same as SAL); fills low bits with zero",
    "sal":    "Shift arithmetic left; fills low bits with zero",
    "shr":    "Shift right logical; fills high bits with zero",
    "sar":    "Shift arithmetic right; fills high bits with sign bit",
    "rol":    "Rotate left through operand (no carry involvement)",
    "ror":    "Rotate right through operand (no carry involvement)",
    "rcl":    "Rotate left through carry flag",
    "rcr":    "Rotate right through carry flag",
    "shld":   "Double-precision shift left",
    "shrd":   "Double-precision shift right",

    # ── Control flow ──────────────────────────────────────────────
    "call":   "Call function: push return address (RIP+len) then jump to target",
    "ret":    "Return from function: pop saved return address into RIP",
    "retn":   "Near return from function",
    "retf":   "Far return (pop CS:RIP from stack)",
    "jmp":    "Unconditional jump: transfer control to target address",
    "je":     "Jump if equal / zero (ZF=1)",
    "jne":    "Jump if not equal / not zero (ZF=0)",
    "jz":     "Jump if zero flag set (ZF=1) — same as JE",
    "jnz":    "Jump if zero flag clear (ZF=0) — same as JNE",
    "jg":     "Jump if greater than, signed (ZF=0 and SF=OF)",
    "jge":    "Jump if greater than or equal, signed (SF=OF)",
    "jl":     "Jump if less than, signed (SF≠OF)",
    "jle":    "Jump if less than or equal, signed (ZF=1 or SF≠OF)",
    "ja":     "Jump if above, unsigned (CF=0 and ZF=0)",
    "jae":    "Jump if above or equal, unsigned (CF=0) — same as JNB",
    "jb":     "Jump if below, unsigned (CF=1) — same as JC",
    "jbe":    "Jump if below or equal, unsigned (CF=1 or ZF=1)",
    "jnb":    "Jump if not below (CF=0) — unsigned ≥ — same as JAE",
    "jnbe":   "Jump if not below or equal (CF=0 and ZF=0)",
    "jc":     "Jump if carry flag set (CF=1)",
    "jnc":    "Jump if carry flag clear (CF=0)",
    "js":     "Jump if sign flag set (result was negative)",
    "jns":    "Jump if sign flag clear (result was non-negative)",
    "jp":     "Jump if parity flag set (even number of set bits)",
    "jnp":    "Jump if parity flag clear (odd number of set bits)",
    "jo":     "Jump if overflow flag set",
    "jno":    "Jump if overflow flag clear",
    "jrcxz":  "Jump if RCX register is zero",
    "jecxz":  "Jump if ECX register is zero",
    "loop":   "Decrement RCX; jump to target if RCX ≠ 0",
    "loope":  "Decrement RCX; jump if RCX ≠ 0 and ZF=1",
    "loopne": "Decrement RCX; jump if RCX ≠ 0 and ZF=0",

    # ── SETcc ─────────────────────────────────────────────────────
    "sete":   "Set byte to 1 if equal (ZF=1), else 0",
    "setne":  "Set byte to 1 if not equal (ZF=0), else 0",
    "setg":   "Set byte to 1 if greater (signed), else 0",
    "setge":  "Set byte to 1 if greater or equal (signed), else 0",
    "setl":   "Set byte to 1 if less (signed), else 0",
    "setle":  "Set byte to 1 if less or equal (signed), else 0",
    "seta":   "Set byte to 1 if above (unsigned), else 0",
    "setae":  "Set byte to 1 if above or equal (unsigned), else 0",
    "setb":   "Set byte to 1 if below (unsigned), else 0",
    "setbe":  "Set byte to 1 if below or equal (unsigned), else 0",
    "sets":   "Set byte to 1 if sign flag set, else 0",
    "setns":  "Set byte to 1 if sign flag clear, else 0",
    "setz":   "Set byte to 1 if zero flag set, else 0",
    "setnz":  "Set byte to 1 if zero flag clear, else 0",
    "setc":   "Set byte to 1 if carry flag set, else 0",
    "setnc":  "Set byte to 1 if carry flag clear, else 0",
    "setp":   "Set byte to 1 if parity flag set, else 0",
    "setnp":  "Set byte to 1 if parity flag clear, else 0",
    "seto":   "Set byte to 1 if overflow flag set, else 0",
    "setno":  "Set byte to 1 if overflow flag clear, else 0",

    # ── String operations ─────────────────────────────────────────
    "stos":   "Store AL/AX/EAX/RAX at [RDI]; advance RDI",
    "stosb":  "Store AL byte at [RDI]; advance RDI by 1",
    "stosw":  "Store AX word at [RDI]; advance RDI by 2",
    "stosd":  "Store EAX dword at [RDI]; advance RDI by 4",
    "stosq":  "Store RAX qword at [RDI]; advance RDI by 8",
    "lods":   "Load [RSI] into AL/AX/EAX/RAX; advance RSI",
    "lodsb":  "Load byte at [RSI] into AL; advance RSI by 1",
    "scas":   "Compare AL/AX/EAX/RAX with [RDI]; advance RDI",
    "scasb":  "Compare AL with byte at [RDI]; advance RDI by 1",
    "cmps":   "Compare [RSI] with [RDI]; advance both pointers",
    "cmpsb":  "Compare byte at [RSI] with byte at [RDI]; advance both",

    # ── System / privileged ───────────────────────────────────────
    "syscall": "Invoke OS kernel: transfers to kernel using RCX/R11 for return state",
    "sysret":  "Return from kernel syscall to userspace",
    "int":     "Software interrupt: raise exception/trap vector",
    "int3":    "Debugger breakpoint trap (INT 3)",
    "iret":    "Interrupt return: restore RIP/CS/RFLAGS from stack",
    "hlt":     "Halt CPU until next interrupt (requires kernel privilege)",
    "ud2":     "Undefined instruction — always triggers #UD exception (used as hard trap)",
    "nop":     "No operation — does nothing; used for alignment or timing",
    "pause":   "Hint that this is a spin-wait loop; improves Hyper-Threading performance",
    "cpuid":   "Query CPU features and identification into EAX/EBX/ECX/EDX",
    "rdtsc":   "Read timestamp counter: low 32 bits → EAX, high 32 bits → EDX",
    "rdmsr":   "Read model-specific register ECX into EDX:EAX (kernel only)",
    "wrmsr":   "Write EDX:EAX to model-specific register ECX (kernel only)",
    "clc":     "Clear carry flag (CF ← 0)",
    "stc":     "Set carry flag (CF ← 1)",
    "cld":     "Clear direction flag — string ops advance forward (DF ← 0)",
    "std":     "Set direction flag — string ops advance backward (DF ← 1)",
    "cli":     "Clear interrupt flag — disable maskable hardware interrupts",
    "sti":     "Set interrupt flag — enable maskable hardware interrupts",
    "sahf":    "Store AH into low byte of RFLAGS (SF/ZF/AF/PF/CF)",
    "lahf":    "Load low byte of RFLAGS into AH",
    "pushfq":  "Push RFLAGS quad onto stack",
    "popfq":   "Pop quad from stack into RFLAGS",

    # ── x86-64 specific / CET ─────────────────────────────────────
    "endbr64": "End-branch marker for 64-bit code (Intel CET shadow stack guard)",
    "endbr32": "End-branch marker for 32-bit code (Intel CET shadow stack guard)",

    # ── Stub decoder fallback ─────────────────────────────────────
    "db":      "Raw data byte — decoder could not identify this instruction",
}


# ═════════════════════════════════════════════════════════════════
# Operand-pattern table
# ─────────────────────────────────────────────────────────────────
# Each entry is (mnemonic_substring, op_pattern_substring, explanation).
# The engine calls _match_pattern(mnemonic, op_str) which iterates this
# list and returns the first matching explanation.
# Matching: case-insensitive substring on both mnemonic and op_str.
# Most-specific patterns must come first.
# ═════════════════════════════════════════════════════════════════

_OPERAND_PATTERNS: list[tuple[str, str, str]] = [

    # ── Stack frame setup / teardown ─────────────────────────────
    ("push", "rbp",          "Save caller's base pointer — start of function prologue"),
    ("push", "ebp",          "Save caller's base pointer — start of function prologue"),
    ("mov",  "rbp, rsp",     "Set base pointer to current stack pointer — establish stack frame"),
    ("mov",  "ebp, esp",     "Set base pointer to current stack pointer — establish stack frame"),
    ("sub",  "rsp,",         "Reserve space on stack for local variables"),
    ("sub",  "esp,",         "Reserve space on stack for local variables"),
    ("add",  "rsp,",         "Release stack space (clean up locals / aligned reservation)"),
    ("add",  "esp,",         "Release stack space (clean up locals)"),
    ("leave","",             "Restore stack frame: MOV RSP,RBP then POP RBP — function epilogue"),
    ("pop",  "rbp",          "Restore caller's base pointer — function epilogue"),
    ("pop",  "ebp",          "Restore caller's base pointer — function epilogue"),

    # ── Common idioms ─────────────────────────────────────────────
    ("xor",  "eax, eax",     "Zero EAX — common zero-initialisation idiom (smaller than MOV EAX,0)"),
    ("xor",  "rax, rax",     "Zero RAX — common zero-initialisation idiom"),
    ("xor",  "ecx, ecx",     "Zero ECX — often zeroing a loop counter or argument"),
    ("xor",  "rcx, rcx",     "Zero RCX — often zeroing a loop counter or argument"),
    ("xor",  "edx, edx",     "Zero EDX — often zeroing before IDIV or a third argument"),
    ("xor",  "rdx, rdx",     "Zero RDX — often zeroing before IDIV or a third argument"),
    ("sub",  "eax, eax",     "Zero EAX — alternative to XOR EAX,EAX (affects flags differently)"),
    ("test", ", rax",        "Test RAX against itself — check if RAX is zero/non-zero"),
    ("test", "rax, rax",     "Test RAX against itself — check if RAX is zero/non-zero"),
    ("test", "eax, eax",     "Test EAX against itself — check if EAX is zero/non-zero"),
    ("cmp",  ", 0",          "Compare operand with zero — check for null/empty"),

    # ── Return values ─────────────────────────────────────────────
    ("mov",  "eax, 0",       "Set return value to 0 (success / false)"),
    ("mov",  "eax, 1",       "Set return value to 1 (success / true)"),
    ("xor",  "eax,",         "Zero EAX — set function return value to 0"),

    # ── Argument passing (System V AMD64 ABI) ─────────────────────
    ("mov",  "rdi,",         "Load first argument (RDI) for upcoming function call"),
    ("mov",  "rsi,",         "Load second argument (RSI) for upcoming function call"),
    ("mov",  "rdx,",         "Load third argument (RDX) for upcoming function call"),
    ("mov",  "rcx,",         "Load fourth argument (RCX) for upcoming function call"),
    ("mov",  "r8,",          "Load fifth argument (R8) for upcoming function call"),
    ("mov",  "r9,",          "Load sixth argument (R9) for upcoming function call"),

    # ── Memory loads ─────────────────────────────────────────────
    ("mov",  "[rsp",         "Write value to stack (local variable or spill)"),
    ("mov",  "[rbp-",        "Write to local variable at negative RBP offset"),
    ("mov",  "[rbp+",        "Write to stack argument at positive RBP offset"),
    ("mov",  "qword ptr [",  "Load 64-bit value from memory"),
    ("mov",  "dword ptr [",  "Load 32-bit value from memory"),
    ("mov",  "word ptr [",   "Load 16-bit value from memory"),
    ("mov",  "byte ptr [",   "Load 8-bit value from memory"),
    ("lea",  "[rip+",        "Load RIP-relative address — typically a global variable or string"),

    # ── Calls ─────────────────────────────────────────────────────
    ("call", "plt",          "Call PLT stub — dynamic-linked external function"),
    ("call", "qword ptr [",  "Indirect call through function pointer or vtable slot"),
    ("call", "0x",           "Call function at absolute address"),

    # ── Conditionals ─────────────────────────────────────────────
    ("jne",  "",             "Branch if last comparison was not equal (ZF=0)"),
    ("je",   "",             "Branch if last comparison was equal (ZF=1)"),
    ("jz",   "",             "Branch if result was zero (ZF=1)"),
    ("jnz",  "",             "Branch if result was non-zero (ZF=0)"),
    ("jg",   "",             "Branch if last signed comparison: greater-than"),
    ("jl",   "",             "Branch if last signed comparison: less-than"),
    ("jge",  "",             "Branch if last signed comparison: greater-than or equal"),
    ("jle",  "",             "Branch if last signed comparison: less-than or equal"),
    ("ja",   "",             "Branch if last unsigned comparison: above"),
    ("jb",   "",             "Branch if last unsigned comparison: below (carry set)"),
    ("jae",  "",             "Branch if unsigned: above or equal (carry clear)"),
    ("jbe",  "",             "Branch if unsigned: below or equal"),
    ("jnb",  "",             "Branch if unsigned: not below (carry clear) — same as JAE"),

    # ── Misc patterns ─────────────────────────────────────────────
    ("endbr64", "",          "Control-flow enforcement: valid indirect branch target"),
    ("nop",  "",             "No operation — padding for alignment or pipeline timing"),
    ("ret",  "",             "Return to caller; pops return address from stack"),
]


def _match_pattern(mnemonic: str, op_str: str) -> str | None:
    """
    Return an operand-context explanation for (*mnemonic*, *op_str*),
    or ``None`` if no pattern matches.
    """
    m = mnemonic.lower()
    o = op_str.lower()
    for pat_m, pat_o, explanation in _OPERAND_PATTERNS:
        if pat_m in m and pat_o in o:
            return explanation
    return None
