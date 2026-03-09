"""
Minimal capstone-compatible stub for offline development.

Implements the exact API surface consumed by ByteTrace:
    from capstone import Cs, CsInsn, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    for insn in cs.disasm(code_bytes, base_address):
        print(insn.address, insn.mnemonic, insn.op_str)

Replace this entire stub directory with `pip install capstone` in production.
"""

from __future__ import annotations
import struct
from typing import Iterator


# ── Architecture and mode constants (mirrors capstone) ────────────
CS_ARCH_X86   = 3
CS_ARCH_ARM   = 1
CS_ARCH_ARM64 = 2

CS_MODE_32    = 1 << 2   # 32-bit
CS_MODE_64    = 1 << 3   # 64-bit
CS_MODE_THUMB = 1 << 4   # ARM Thumb


# ── Instruction result object ─────────────────────────────────────

class CsInsn:
    """Mirrors capstone's CsInsn object."""
    __slots__ = ("address", "mnemonic", "op_str", "bytes", "size")

    def __init__(self, address: int, mnemonic: str, op_str: str, raw: bytes) -> None:
        self.address  = address
        self.mnemonic = mnemonic
        self.op_str   = op_str
        self.bytes    = raw
        self.size     = len(raw)

    def __repr__(self) -> str:
        return f"0x{self.address:x}:\t{self.mnemonic}\t{self.op_str}"


# ═════════════════════════════════════════════════════════════════
# x86-64 decoder tables
# ═════════════════════════════════════════════════════════════════

# REX prefix bits
_REX_W = 0x08
_REX_R = 0x04
_REX_X = 0x02
_REX_B = 0x01

# General-purpose register names indexed by [rex_b][modrm_reg or opcode_reg]
_REG64 = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
          "r8", "r9", "r10","r11","r12","r13","r14","r15"]
_REG32 = ["eax","ecx","edx","ebx","esp","ebp","esi","edi",
          "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"]
_REG16 = ["ax","cx","dx","bx","sp","bp","si","di",
          "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"]
_REG8  = ["al","cl","dl","bl","ah","ch","dh","bh",
          "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"]
_REG8R = ["al","cl","dl","bl","spl","bpl","sil","dil",    # with REX prefix
          "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"]

_SEG  = ["es","cs","ss","ds","fs","gs","",""]


def _reg64(n: int, rex_b: bool = False) -> str:
    return _REG64[(8 if rex_b else 0) + (n & 7)]

def _reg32(n: int, rex_b: bool = False) -> str:
    return _REG32[(8 if rex_b else 0) + (n & 7)]

def _regrx(n: int, rex_w: bool, rex_b: bool) -> str:
    idx = (8 if rex_b else 0) + (n & 7)
    return _REG64[idx] if rex_w else _REG32[idx]


# ═════════════════════════════════════════════════════════════════
# ModRM / SIB memory operand decoder
# ═════════════════════════════════════════════════════════════════

def _modrm_mem(buf: bytes, pos: int, rex: int, addr_size: int = 64) -> tuple[str, int]:
    """
    Decode a ModRM-encoded memory operand starting at *pos*.
    Returns (operand_string, bytes_consumed).
    Only handles mod != 3 (memory operand) cases.
    """
    if pos >= len(buf):
        return "?", 1

    byte  = buf[pos]
    mod   = (byte >> 6) & 3
    rm    = byte & 7
    reg_r = (byte >> 3) & 7

    rex_b = bool(rex & _REX_B)
    rex_x = bool(rex & _REX_X)
    base_reg_idx = (8 if rex_b else 0) + rm

    consumed = 1  # ModRM byte itself

    if mod == 3:
        # Register, not memory — caller handles
        return "", 1

    # SIB byte?
    if rm == 4:  # SIB follows
        if pos + 1 >= len(buf):
            return "[?]", 2
        sib = buf[pos + 1]
        consumed += 1
        scale = 1 << ((sib >> 6) & 3)
        idx   = (sib >> 3) & 7
        base  = sib & 7
        idx_r = (8 if rex_x else 0) + idx
        base_r= (8 if rex_b else 0) + base

        parts: list[str] = []
        if not (base == 5 and mod == 0):
            parts.append(_REG64[base_r])
        if idx != 4:
            parts.append(f"{_REG64[idx_r]}*{scale}" if scale > 1 else _REG64[idx_r])

        if mod == 0 and base == 5:
            disp32 = struct.unpack_from("<i", buf, pos + consumed)[0]
            consumed += 4
            if parts:
                disp_str = f"+{disp32:#x}" if disp32 >= 0 else f"{disp32:#x}"
                return f"[{'+'.join(parts)}{disp_str}]", consumed
            else:
                return f"[{disp32:#x}]", consumed

        if mod == 1:
            disp = struct.unpack_from("<b", buf, pos + consumed)[0]
            consumed += 1
            disp_str = f"+{disp:#x}" if disp >= 0 else f"-{-disp:#x}"
            return f"[{'+'.join(parts)}{disp_str}]", consumed
        elif mod == 2:
            disp = struct.unpack_from("<i", buf, pos + consumed)[0]
            consumed += 4
            disp_str = f"+{disp:#x}" if disp >= 0 else f"{disp:#x}"
            return f"[{'+'.join(parts)}{disp_str}]", consumed
        else:
            return f"[{'+'.join(parts)}]", consumed

    # Non-SIB
    if mod == 0 and rm == 5:
        # RIP-relative
        disp = struct.unpack_from("<i", buf, pos + consumed)[0]
        consumed += 4
        return f"[rip+{disp:#x}]", consumed

    base_name = _REG64[base_reg_idx]

    if mod == 0:
        return f"[{base_name}]", consumed
    elif mod == 1:
        disp = struct.unpack_from("<b", buf, pos + consumed)[0]
        consumed += 1
        disp_str = f"{disp:#x}" if disp >= 0 else f"-{-disp:#x}"
        return f"[{base_name}+{disp_str}]" if disp >= 0 else f"[{base_name}{disp_str}]", consumed
    else:  # mod == 2
        disp = struct.unpack_from("<i", buf, pos + consumed)[0]
        consumed += 4
        disp_str = f"{disp:#x}" if disp >= 0 else f"{disp:#x}"
        return f"[{base_name}+{disp_str}]" if disp >= 0 else f"[{base_name}{disp_str}]", consumed


# ═════════════════════════════════════════════════════════════════
# Core decoder: one instruction at a time
# ═════════════════════════════════════════════════════════════════

def _decode_one(buf: bytes, ip: int) -> tuple[str, str, int] | None:
    """
    Decode one x86-64 instruction.
    Returns (mnemonic, op_str, length) or None if undecipherable.
    ip is used for relative branch target calculation.
    """
    if not buf:
        return None

    pos   = 0
    rex   = 0
    pfx66 = False  # operand-size override
    pfx67 = False  # address-size override
    pfxF3 = False  # REP / REPE
    pfxF2 = False  # REPNE

    # Consume legacy prefixes
    while pos < len(buf) and pos < 4:
        b = buf[pos]
        if b == 0x66:   pfx66 = True;  pos += 1
        elif b == 0x67: pfx67 = True;  pos += 1
        elif b == 0xF3: pfxF3 = True;  pos += 1
        elif b == 0xF2: pfxF2 = True;  pos += 1
        elif b in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65):  # segment override
            pos += 1
        else:
            break

    # REX prefix (40-4F)
    if pos < len(buf) and 0x40 <= buf[pos] <= 0x4F:
        rex = buf[pos] & 0x0F
        pos += 1

    rex_w = bool(rex & _REX_W)
    rex_r = bool(rex & _REX_R)
    rex_b = bool(rex & _REX_B)

    if pos >= len(buf):
        return None

    op = buf[pos]; pos += 1

    # ── Two-byte escape (0F xx) ────────────────────────────────────
    if op == 0x0F:
        if pos >= len(buf):
            return None
        op2 = buf[pos]; pos += 1

        # ENDBR64 / ENDBR32 (F3 0F 1E F*/FA)
        if pfxF3 and op2 == 0x1E:
            if pos < len(buf) and buf[pos] == 0xFA:
                return "endbr64", "", pos + 1
            if pos < len(buf) and buf[pos] == 0xFB:
                return "endbr32", "", pos + 1
            return "endbr64", "", pos

        # NOP variants: 0F 1F /0
        if op2 == 0x1F:
            mem, mc = _modrm_mem(buf, pos, rex)
            return "nop", f"dword ptr {mem}", pos + mc

        # SYSCALL
        if op2 == 0x05:
            return "syscall", "", pos

        # SYSRET
        if op2 == 0x07:
            return "sysret", "", pos

        # WRMSR / RDMSR
        if op2 == 0x30: return "wrmsr", "", pos
        if op2 == 0x32: return "rdmsr", "", pos
        if op2 == 0x33: return "rdpmc", "", pos

        # RDTSC
        if op2 == 0x31: return "rdtsc", "", pos

        # CMOVcc
        if 0x40 <= op2 <= 0x4F:
            cond = ["o","no","b","nb","e","ne","be","a",
                    "s","ns","p","np","l","nl","le","g"][op2 & 0xF]
            if pos >= len(buf): return f"cmov{cond}", "?", pos
            mrm = buf[pos]
            mod = (mrm >> 6) & 3; rm = mrm & 7
            r = (8 if rex_r else 0) + ((mrm >> 3) & 7)
            dst = _regrx(r, rex_w, False)
            if mod == 3:
                src = _regrx((8 if rex_b else 0) + rm, rex_w, False)
                return f"cmov{cond}", f"{dst}, {src}", pos + 1
            src_m, mc = _modrm_mem(buf, pos, rex)
            return f"cmov{cond}", f"{dst}, {src_m}", pos + mc

        # Jcc near (0F 8x)
        if 0x80 <= op2 <= 0x8F:
            cond = ["o","no","b","nb","e","ne","be","a",
                    "s","ns","p","np","l","nl","le","g"][op2 & 0xF]
            if pos + 4 > len(buf): return f"j{cond}", "?", pos
            rel = struct.unpack_from("<i", buf, pos)[0]
            target = ip + pos + 4 + rel
            return f"j{cond}", f"{target:#x}", pos + 4

        # SETcc
        if 0x90 <= op2 <= 0x9F:
            cond = ["o","no","b","nb","e","ne","be","a",
                    "s","ns","p","np","l","nl","le","g"][op2 & 0xF]
            if pos >= len(buf): return f"set{cond}", "?", pos
            mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
            if mod == 3:
                dst = _REG8R[(8 if rex_b else 0) + rm]
                return f"set{cond}", dst, pos + 1
            mem, mc = _modrm_mem(buf, pos, rex)
            return f"set{cond}", f"byte ptr {mem}", pos + mc

        # IMUL r64, r/m64, imm32
        if op2 == 0xAF:
            if pos >= len(buf): return "imul", "?", pos
            mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
            r = (8 if rex_r else 0) + ((mrm >> 3) & 7)
            dst = _regrx(r, rex_w, False)
            if mod == 3:
                src = _regrx((8 if rex_b else 0) + rm, rex_w, False)
                return "imul", f"{dst}, {src}", pos + 1
            src_m, mc = _modrm_mem(buf, pos, rex)
            return "imul", f"{dst}, {src_m}", pos + mc

        # MOVZX / MOVSX
        if op2 in (0xB6, 0xB7, 0xBE, 0xBF):
            names = {0xB6:"movzx", 0xB7:"movzx", 0xBE:"movsx", 0xBF:"movsx"}
            widths = {0xB6:"byte", 0xB7:"word", 0xBE:"byte", 0xBF:"word"}
            mnm = names[op2]; w = widths[op2]
            if pos >= len(buf): return mnm, "?", pos
            mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
            r = (8 if rex_r else 0) + ((mrm >> 3) & 7)
            dst = _regrx(r, rex_w, False)
            if mod == 3:
                if w == "byte":
                    src = _REG8R[(8 if rex_b else 0) + rm] if rex else _REG8[(8 if rex_b else 0) + rm]
                else:
                    src = _REG16[(8 if rex_b else 0) + rm]
                return mnm, f"{dst}, {src}", pos + 1
            src_m, mc = _modrm_mem(buf, pos, rex)
            return mnm, f"{dst}, {w} ptr {src_m}", pos + mc

        # XCHG, BSF, BSR
        if op2 == 0xBC:
            if pos >= len(buf): return "bsf", "?", pos
            mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
            r = (8 if rex_r else 0) + ((mrm >> 3) & 7)
            dst = _regrx(r, rex_w, False)
            if mod == 3:
                src = _regrx((8 if rex_b else 0) + rm, rex_w, False)
            else:
                src, _ = _modrm_mem(buf, pos, rex)
            mc = 1 if mod == 3 else _modrm_mem(buf, pos, rex)[1]
            return "bsf", f"{dst}, {src}", pos + mc

        # MOV r/m, r (0F moves for xmm etc, just emit generic)
        return f"0f_{op2:02x}", "", pos

    # ── Single-byte opcodes ────────────────────────────────────────

    # PUSH/POP r64 (50-5F)
    if 0x50 <= op <= 0x57:
        r = (8 if rex_b else 0) + (op & 7)
        return "push", _REG64[r], pos
    if 0x58 <= op <= 0x5F:
        r = (8 if rex_b else 0) + (op & 7)
        return "pop", _REG64[r], pos

    # RET
    if op == 0xC3: return "ret", "", pos
    if op == 0xC2:
        if pos + 2 > len(buf): return "ret", "?", pos
        imm = struct.unpack_from("<H", buf, pos)[0]
        return "ret", f"{imm:#x}", pos + 2

    # NOP
    if op == 0x90: return "nop", "", pos

    # INT3 / INT n
    if op == 0xCC: return "int3", "", pos
    if op == 0xCD:
        if pos >= len(buf): return "int", "?", pos
        return "int", f"{buf[pos]:#x}", pos + 1

    # HLT
    if op == 0xF4: return "hlt", "", pos

    # LEAVE
    if op == 0xC9: return "leave", "", pos

    # CALL rel32
    if op == 0xE8:
        if pos + 4 > len(buf): return "call", "?", pos
        rel = struct.unpack_from("<i", buf, pos)[0]
        target = ip + pos + 4 + rel
        return "call", f"{target:#x}", pos + 4

    # JMP rel32
    if op == 0xE9:
        if pos + 4 > len(buf): return "jmp", "?", pos
        rel = struct.unpack_from("<i", buf, pos)[0]
        target = ip + pos + 4 + rel
        return "jmp", f"{target:#x}", pos + 4

    # JMP rel8
    if op == 0xEB:
        if pos >= len(buf): return "jmp", "?", pos
        rel = struct.unpack_from("<b", buf, pos)[0]
        target = ip + pos + 1 + rel
        return "jmp", f"{target:#x}", pos + 1

    # Jcc short (70-7F)
    if 0x70 <= op <= 0x7F:
        cond = ["o","no","b","nb","e","ne","be","a",
                "s","ns","p","np","l","nl","le","g"][op & 0xF]
        if pos >= len(buf): return f"j{cond}", "?", pos
        rel = struct.unpack_from("<b", buf, pos)[0]
        target = ip + pos + 1 + rel
        return f"j{cond}", f"{target:#x}", pos + 1

    # LOOP / LOOPE / LOOPNE
    if op == 0xE2:
        rel = struct.unpack_from("<b", buf, pos)[0]
        return "loop", f"{ip+pos+1+rel:#x}", pos + 1
    if op == 0xE1:
        rel = struct.unpack_from("<b", buf, pos)[0]
        return "loope", f"{ip+pos+1+rel:#x}", pos + 1
    if op == 0xE0:
        rel = struct.unpack_from("<b", buf, pos)[0]
        return "loopne", f"{ip+pos+1+rel:#x}", pos + 1

    # CALL r/m64 (FF /2), JMP r/m64 (FF /4), PUSH r/m64 (FF /6)
    if op == 0xFF:
        if pos >= len(buf): return "jmp", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        reg_op = (mrm >> 3) & 7
        if mod == 3:
            r = _REG64[(8 if rex_b else 0) + rm]
            if reg_op == 2: return "call", r, pos + 1
            if reg_op == 4: return "jmp",  r, pos + 1
            if reg_op == 6: return "push", r, pos + 1
            if reg_op == 0:
                r2 = _regrx((8 if rex_b else 0) + rm, rex_w, False)
                return "inc", r2, pos + 1
            if reg_op == 1:
                r2 = _regrx((8 if rex_b else 0) + rm, rex_w, False)
                return "dec", r2, pos + 1
        else:
            mem, mc = _modrm_mem(buf, pos, rex)
            if reg_op == 2: return "call", f"qword ptr {mem}", pos + mc
            if reg_op == 4: return "jmp",  f"qword ptr {mem}", pos + mc
            if reg_op == 6: return "push", f"qword ptr {mem}", pos + mc

    # MOV r64, imm64 (B8+rd io)
    if 0xB8 <= op <= 0xBF:
        r = (8 if rex_b else 0) + (op & 7)
        if rex_w:
            if pos + 8 > len(buf): return "mov", "?", pos
            imm = struct.unpack_from("<Q", buf, pos)[0]
            return "mov", f"{_REG64[r]}, {imm:#x}", pos + 8
        else:
            if pos + 4 > len(buf): return "mov", "?", pos
            imm = struct.unpack_from("<I", buf, pos)[0]
            return "mov", f"{_REG32[r]}, {imm:#x}", pos + 4

    # MOV r/m, imm (C6 /0 imm8, C7 /0 imm32)
    if op == 0xC7:
        if pos >= len(buf): return "mov", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        if mod == 3:
            r = _regrx((8 if rex_b else 0) + rm, rex_w, False)
            if pos + 5 > len(buf): return "mov", "?", pos
            imm = struct.unpack_from("<i", buf, pos + 1)[0]
            return "mov", f"{r}, {imm:#x}", pos + 5
        mem, mc = _modrm_mem(buf, pos, rex)
        imm = struct.unpack_from("<i", buf, pos + mc)[0]
        w = "qword" if rex_w else "dword"
        return "mov", f"{w} ptr {mem}, {imm:#x}", pos + mc + 4

    if op == 0xC6:
        if pos >= len(buf): return "mov", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        if mod == 3:
            r = _REG8R[(8 if rex_b else 0) + rm] if rex else _REG8[rm]
            imm = buf[pos + 1] if pos + 1 < len(buf) else 0
            return "mov", f"{r}, {imm:#x}", pos + 2
        mem, mc = _modrm_mem(buf, pos, rex)
        imm = buf[pos + mc] if pos + mc < len(buf) else 0
        return "mov", f"byte ptr {mem}, {imm:#x}", pos + mc + 1

    # MOV r/m ↔ r (88-8B)
    if op in (0x88, 0x89, 0x8A, 0x8B):
        if pos >= len(buf): return "mov", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        r = (8 if rex_r else 0) + ((mrm >> 3) & 7)
        to_mem = op in (0x88, 0x89)
        byte_op = op in (0x88, 0x8A)

        if mod == 3:
            if byte_op:
                a = _REG8R[r] if rex else _REG8[r & 7]
                b = _REG8R[(8 if rex_b else 0) + rm] if rex else _REG8[rm]
            else:
                a = _regrx(r, rex_w, False)
                b = _regrx((8 if rex_b else 0) + rm, rex_w, False)
            return "mov", (f"{b}, {a}" if to_mem else f"{a}, {b}"), pos + 1

        mem_s, mc = _modrm_mem(buf, pos, rex)
        reg_s = (_REG8R[r] if rex else _REG8[r & 7]) if byte_op else _regrx(r, rex_w, False)
        w = "byte" if byte_op else ("qword" if rex_w else "dword")
        if to_mem:
            return "mov", f"{w} ptr {mem_s}, {reg_s}", pos + mc
        else:
            return "mov", f"{reg_s}, {w} ptr {mem_s}", pos + mc

    # MOV r, r/m for 16-bit (66 8B)
    if op == 0x8D:  # LEA
        if pos >= len(buf): return "lea", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        r = (8 if rex_r else 0) + ((mrm >> 3) & 7)
        dst = _regrx(r, rex_w, False)
        if mod == 3:
            return "lea", f"{dst}, {_regrx((8 if rex_b else 0)+rm, rex_w, False)}", pos + 1
        mem_s, mc = _modrm_mem(buf, pos, rex)
        return "lea", f"{dst}, {mem_s}", pos + mc

    # ADD / OR / ADC / SBB / AND / SUB / XOR / CMP (00-3F, family)
    _alu_ops = {
        0x00:"add",0x01:"add",0x02:"add",0x03:"add",
        0x08:"or", 0x09:"or", 0x0A:"or", 0x0B:"or",
        0x10:"adc",0x11:"adc",0x12:"adc",0x13:"adc",
        0x18:"sbb",0x19:"sbb",0x1A:"sbb",0x1B:"sbb",
        0x20:"and",0x21:"and",0x22:"and",0x23:"and",
        0x28:"sub",0x29:"sub",0x2A:"sub",0x2B:"sub",
        0x30:"xor",0x31:"xor",0x32:"xor",0x33:"xor",
        0x38:"cmp",0x39:"cmp",0x3A:"cmp",0x3B:"cmp",
    }
    if op in _alu_ops:
        mnm = _alu_ops[op]
        to_mem = (op & 2) == 0
        byte_op = (op & 1) == 0
        if pos >= len(buf): return mnm, "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        r = (8 if rex_r else 0) + ((mrm >> 3) & 7)
        if mod == 3:
            if byte_op:
                a = _REG8R[r] if rex else _REG8[r & 7]
                b = _REG8R[(8 if rex_b else 0)+rm] if rex else _REG8[rm]
            else:
                a = _regrx(r, rex_w, False)
                b = _regrx((8 if rex_b else 0)+rm, rex_w, False)
            if to_mem: return mnm, f"{b}, {a}", pos + 1
            else:      return mnm, f"{a}, {b}", pos + 1
        mem_s, mc = _modrm_mem(buf, pos, rex)
        w = "byte" if byte_op else ("qword" if rex_w else "dword")
        reg_s = (_REG8R[r] if rex else _REG8[r&7]) if byte_op else _regrx(r, rex_w, False)
        if to_mem: return mnm, f"{w} ptr {mem_s}, {reg_s}", pos + mc
        else:      return mnm, f"{reg_s}, {w} ptr {mem_s}", pos + mc

    # ALU immediate: 80/81/83
    _grp1 = {0:"add",1:"or",2:"adc",3:"sbb",4:"and",5:"sub",6:"xor",7:"cmp"}
    if op in (0x80, 0x81, 0x83):
        if pos >= len(buf): return "alu", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        grp = (mrm >> 3) & 7
        mnm = _grp1.get(grp, "alu")
        byte_op = op == 0x80

        if mod == 3:
            if byte_op:
                dst = _REG8R[(8 if rex_b else 0)+rm] if rex else _REG8[rm]
                imm = struct.unpack_from("<b", buf, pos+1)[0] if pos+1 < len(buf) else 0
                return mnm, f"{dst}, {imm:#x}", pos + 2
            else:
                dst = _regrx((8 if rex_b else 0)+rm, rex_w, False)
                if op == 0x83:
                    imm = struct.unpack_from("<b", buf, pos+1)[0] if pos+1 < len(buf) else 0
                    return mnm, f"{dst}, {imm:#x}", pos + 2
                else:
                    if pos + 5 > len(buf): return mnm, "?", pos
                    imm = struct.unpack_from("<i", buf, pos+1)[0]
                    return mnm, f"{dst}, {imm:#x}", pos + 5
        mem_s, mc = _modrm_mem(buf, pos, rex)
        w = "byte" if byte_op else ("qword" if rex_w else "dword")
        if op == 0x83:
            imm = struct.unpack_from("<b", buf, pos+mc)[0] if pos+mc < len(buf) else 0
            return mnm, f"{w} ptr {mem_s}, {imm:#x}", pos + mc + 1
        elif byte_op:
            imm = buf[pos+mc] if pos+mc < len(buf) else 0
            return mnm, f"byte ptr {mem_s}, {imm:#x}", pos + mc + 1
        else:
            imm = struct.unpack_from("<i", buf, pos+mc)[0] if pos+mc+4 <= len(buf) else 0
            return mnm, f"{w} ptr {mem_s}, {imm:#x}", pos + mc + 4

    # TEST r/m, r (84/85)
    if op in (0x84, 0x85):
        if pos >= len(buf): return "test", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        r = (8 if rex_r else 0) + ((mrm >> 3) & 7)
        byte_op = op == 0x84
        if mod == 3:
            if byte_op:
                a = _REG8R[r] if rex else _REG8[r & 7]
                b = _REG8R[(8 if rex_b else 0)+rm] if rex else _REG8[rm]
            else:
                a = _regrx(r, rex_w, False)
                b = _regrx((8 if rex_b else 0)+rm, rex_w, False)
            return "test", f"{b}, {a}", pos + 1
        mem_s, mc = _modrm_mem(buf, pos, rex)
        w = "byte" if byte_op else ("qword" if rex_w else "dword")
        reg_s = (_REG8R[r] if rex else _REG8[r&7]) if byte_op else _regrx(r, rex_w, False)
        return "test", f"{w} ptr {mem_s}, {reg_s}", pos + mc

    # TEST rAX, imm (A8/A9)
    if op == 0xA8:
        imm = buf[pos] if pos < len(buf) else 0
        return "test", f"al, {imm:#x}", pos + 1
    if op == 0xA9:
        imm = struct.unpack_from("<i", buf, pos)[0] if pos+4 <= len(buf) else 0
        reg = "rax" if rex_w else "eax"
        return "test", f"{reg}, {imm:#x}", pos + 4

    # INC/DEC (FE/F7 group)
    if op in (0xFE, 0xF7):
        if pos >= len(buf): return "inc", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        grp = (mrm >> 3) & 7
        byte_op = op == 0xFE
        mnm_map = {0:"inc",1:"dec",2:"call",3:"call",4:"jmp",5:"jmp",6:"push",7:"?"}
        if grp in (2,3,4,5,6):  # handled above by 0xFF
            mnm = mnm_map[grp]
        elif grp in (0, 1):
            mnm = mnm_map[grp]
        else:
            mnm = {0xF7:{6:"div",7:"idiv",4:"mul",5:"imul",2:"not",3:"neg",0:"test",1:"test"}}.get(op,{}).get(grp, "alu")
            # F7 /6 = div, /7 = idiv, /4 = mul, /5 = imul, /2 = not, /3 = neg
            mnm = {0:"test",1:"test",2:"not",3:"neg",4:"mul",5:"imul",6:"div",7:"idiv"}.get(grp, "alu")
        if mod == 3:
            if byte_op:
                r = _REG8R[(8 if rex_b else 0)+rm] if rex else _REG8[rm]
            else:
                r = _regrx((8 if rex_b else 0)+rm, rex_w, False)
            # TEST immediate case for F7 /0
            if grp in (0, 1) and op == 0xF7:
                imm = struct.unpack_from("<i", buf, pos+1)[0] if pos+5 <= len(buf) else 0
                return mnm, f"{r}, {imm:#x}", pos + 5
            return mnm, r, pos + 1
        mem_s, mc = _modrm_mem(buf, pos, rex)
        w = "byte" if byte_op else ("qword" if rex_w else "dword")
        return mnm, f"{w} ptr {mem_s}", pos + mc

    # XCHG rAX, r64 (90+rd — but 90 = NOP)
    if 0x91 <= op <= 0x97:
        r = (8 if rex_b else 0) + (op & 7)
        reg = "rax" if rex_w else "eax"
        return "xchg", f"{reg}, {_REG64[r]}", pos

    # MOV rAX, [moffs] / MOV [moffs], rAX (A0-A3)
    if op in (0xA0, 0xA1, 0xA2, 0xA3):
        if pos + 8 > len(buf): return "mov", "?", pos
        addr = struct.unpack_from("<Q", buf, pos)[0]
        reg = "rax" if rex_w else "eax"
        if op in (0xA0, 0xA1): return "mov", f"{reg}, [{addr:#x}]", pos + 8
        else:                   return "mov", f"[{addr:#x}], {reg}", pos + 8

    # PUSH imm8 / PUSH imm32
    if op == 0x6A:
        imm = struct.unpack_from("<b", buf, pos)[0] if pos < len(buf) else 0
        return "push", f"{imm:#x}", pos + 1
    if op == 0x68:
        imm = struct.unpack_from("<i", buf, pos)[0] if pos+4 <= len(buf) else 0
        return "push", f"{imm:#x}", pos + 4

    # IMUL r, r/m, imm8 (6B) / imm32 (69)
    if op in (0x69, 0x6B):
        if pos >= len(buf): return "imul", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        r = (8 if rex_r else 0) + ((mrm >> 3) & 7)
        dst = _regrx(r, rex_w, False)
        if mod == 3:
            src = _regrx((8 if rex_b else 0)+rm, rex_w, False)
        else:
            src, _ = _modrm_mem(buf, pos, rex)
        mc = 1 if mod == 3 else _modrm_mem(buf, pos, rex)[1]
        if op == 0x6B:
            imm = struct.unpack_from("<b", buf, pos+mc)[0] if pos+mc < len(buf) else 0
            return "imul", f"{dst}, {src}, {imm:#x}", pos + mc + 1
        else:
            imm = struct.unpack_from("<i", buf, pos+mc)[0] if pos+mc+4 <= len(buf) else 0
            return "imul", f"{dst}, {src}, {imm:#x}", pos + mc + 4

    # CDQE / CDQ / CQO / CBW
    if op == 0x99: return ("cqo" if rex_w else "cdq"), "", pos
    if op == 0x98: return ("cdqe" if rex_w else "cwde"), "", pos

    # REP MOVS/STOS/SCAS/LODS
    if pfxF3:
        if op == 0xA4: return "rep movsb", "", pos
        if op == 0xA5: return ("rep movsq" if rex_w else "rep movsd"), "", pos
        if op == 0xAA: return "rep stosb", "", pos
        if op == 0xAB: return ("rep stosq" if rex_w else "rep stosd"), "", pos
        if op == 0xA6: return "repe cmpsb", "", pos
        if op == 0xAE: return "repe scasb", "", pos
    if pfxF2:
        if op == 0xAE: return "repne scasb", "", pos
        if op == 0xA6: return "repne cmpsb", "", pos

    # Shift group (D0-D3, C0-C1)
    _shift_names = {0:"rol",1:"ror",2:"rcl",3:"rcr",4:"shl",5:"shr",6:"sal",7:"sar"}
    if op in (0xD0, 0xD1, 0xD2, 0xD3, 0xC0, 0xC1):
        if pos >= len(buf): return "shl", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        grp = (mrm >> 3) & 7
        mnm = _shift_names.get(grp, "shl")
        byte_op = op in (0xD0, 0xD2, 0xC0)
        cl_op   = op in (0xD2, 0xD3)
        imm_op  = op in (0xC0, 0xC1)
        if mod == 3:
            dst = (_REG8R[(8 if rex_b else 0)+rm] if rex else _REG8[rm]) if byte_op else _regrx((8 if rex_b else 0)+rm, rex_w, False)
            if cl_op:  return mnm, f"{dst}, cl", pos + 1
            if imm_op:
                imm = buf[pos+1] if pos+1 < len(buf) else 1
                return mnm, f"{dst}, {imm}", pos + 2
            return mnm, f"{dst}, 1", pos + 1
        mem_s, mc = _modrm_mem(buf, pos, rex)
        w = "byte" if byte_op else ("qword" if rex_w else "dword")
        if cl_op:  return mnm, f"{w} ptr {mem_s}, cl", pos + mc
        if imm_op:
            imm = buf[pos+mc] if pos+mc < len(buf) else 1
            return mnm, f"{w} ptr {mem_s}, {imm}", pos + mc + 1
        return mnm, f"{w} ptr {mem_s}, 1", pos + mc

    # ADD/SUB/XOR/etc rAX, imm (04,05,0C,0D,14,15,1C,1D,24,25,2C,2D,34,35,3C,3D)
    _rax_alu = {
        0x04:"add",0x05:"add",0x0C:"or",0x0D:"or",
        0x14:"adc",0x15:"adc",0x1C:"sbb",0x1D:"sbb",
        0x24:"and",0x25:"and",0x2C:"sub",0x2D:"sub",
        0x34:"xor",0x35:"xor",0x3C:"cmp",0x3D:"cmp",
    }
    if op in _rax_alu:
        mnm = _rax_alu[op]
        byte_op = (op & 1) == 0
        reg = "al" if byte_op else ("rax" if rex_w else "eax")
        if byte_op:
            imm = buf[pos] if pos < len(buf) else 0
            return mnm, f"{reg}, {imm:#x}", pos + 1
        else:
            imm = struct.unpack_from("<i", buf, pos)[0] if pos+4 <= len(buf) else 0
            return mnm, f"{reg}, {imm:#x}", pos + 4

    # XCHG r/m, r (86/87)
    if op in (0x86, 0x87):
        if pos >= len(buf): return "xchg", "?", pos
        mrm = buf[pos]; mod = (mrm >> 6) & 3; rm = mrm & 7
        r = (8 if rex_r else 0) + ((mrm >> 3) & 7)
        byte_op = op == 0x86
        if mod == 3:
            a = (_REG8R[r] if rex else _REG8[r&7]) if byte_op else _regrx(r, rex_w, False)
            b = (_REG8R[(8 if rex_b else 0)+rm] if rex else _REG8[rm]) if byte_op else _regrx((8 if rex_b else 0)+rm, rex_w, False)
            return "xchg", f"{a}, {b}", pos + 1
        mem_s, mc = _modrm_mem(buf, pos, rex)
        reg_s = (_REG8R[r] if rex else _REG8[r&7]) if byte_op else _regrx(r, rex_w, False)
        return "xchg", f"{reg_s}, {mem_s}", pos + mc

    # UD2
    if op == 0x0F and pos < len(buf) and buf[pos] == 0x0B:
        return "ud2", "", pos + 1

    # PUSHFQ / POPFQ
    if op == 0x9C: return "pushfq", "", pos
    if op == 0x9D: return "popfq", "", pos

    # SAHF / LAHF
    if op == 0x9E: return "sahf", "", pos
    if op == 0x9F: return "lahf", "", pos

    # CLC / STC / CLD / STD / CLI / STI
    if op == 0xF8: return "clc", "", pos
    if op == 0xF9: return "stc", "", pos
    if op == 0xFC: return "cld", "", pos
    if op == 0xFD: return "std", "", pos
    if op == 0xFA: return "cli", "", pos
    if op == 0xFB: return "sti", "", pos

    # PAUSE (F3 90)
    if pfxF3 and op == 0x90:
        return "pause", "", pos

    # Fallback: emit db byte
    return f"db", f"{op:#04x}", pos


# ═════════════════════════════════════════════════════════════════
# Public Cs class — mirrors capstone API
# ═════════════════════════════════════════════════════════════════

class Cs:
    """Minimal capstone-compatible disassembler (x86-64 only)."""

    def __init__(self, arch: int, mode: int) -> None:
        self.arch = arch
        self.mode = mode
        self._detail = False

    @property
    def detail(self) -> bool:
        return self._detail

    @detail.setter
    def detail(self, value: bool) -> None:
        self._detail = value

    def disasm(self, code: bytes, offset: int) -> Iterator[CsInsn]:
        """
        Disassemble *code* starting at virtual address *offset*.
        Yields CsInsn objects one at a time.
        """
        if self.arch != CS_ARCH_X86:
            # Non-x86: emit placeholder instructions
            pos = 0
            while pos < len(code):
                size = min(4, len(code) - pos)
                raw  = code[pos: pos + size]
                yield CsInsn(offset + pos, "??", "", raw)
                pos += size
            return

        pos = 0
        while pos < len(code):
            remaining = code[pos:]
            result = _decode_one(remaining, offset + pos)
            if result is None or result[2] == 0:
                # Undecoded: emit single-byte db
                raw = code[pos: pos + 1]
                yield CsInsn(offset + pos, "db", f"{code[pos]:#04x}", raw)
                pos += 1
                continue

            mnemonic, op_str, length = result
            if length <= 0:
                length = 1
            raw = code[pos: pos + length]
            yield CsInsn(offset + pos, mnemonic, op_str, raw)
            pos += length


# ── Version info ──────────────────────────────────────────────────

def cs_version() -> tuple[int, int]:
    """Return (major, minor) stub version."""
    return (5, 0)
