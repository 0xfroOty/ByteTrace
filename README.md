# ByteTrace

**Binary analysis for humans.**

ByteTrace is an open-source command-line tool for exploring and understanding compiled binaries. It is designed to be approachable for beginners while remaining useful for experienced reverse engineers — every command produces clean, readable output, and the `--explain` flag adds inline educational annotations that teach you what the binary is doing as you explore it.

```
$ bytetrace disasm ./crackme --func main --explain

  0x00000000000054f0  endbr64              ; Control-flow enforcement: valid indirect branch target
  0x00000000000054f4  push    rbp          ; Save caller's base pointer — start of function prologue
  0x00000000000054f5  mov     rbp, rsp     ; Set base pointer to current stack pointer — establish stack frame
  0x00000000000054f8  sub     rsp, 0x10    ; Reserve space on stack for local variables
  0x00000000000054fc  mov     rdi, 0x...   ; Load first argument (RDI) for upcoming function call
  0x0000000000005503  call    0x4040       ; Call puts()
  0x0000000000005508  xor     eax, eax     ; Zero EAX — set function return value to 0
  0x000000000000550a  ret                  ; Return to caller; pops return address from stack
```

---

## Features

| Command    | Description                                           |
|------------|-------------------------------------------------------|
| `info`     | Binary overview: format, architecture, entry point, section and symbol counts |
| `sections` | Section header table with flags, sizes, and descriptions |
| `symbols`  | Static and dynamic symbol listing with filtering and search |
| `disasm`   | Disassemble a function or address range with syntax highlighting |
| `cfg`      | Build and display the Control Flow Graph of a function |
| `strings`  | Extract printable ASCII strings, optionally scoped to a section |
| `hexdump`  | Raw byte inspection in classic `hexdump -C` style |

**Global flags** that work on every command:

| Flag          | Effect                                              |
|---------------|-----------------------------------------------------|
| `--explain`   | Add inline educational annotations to the output    |
| `--json`      | Emit structured JSON for scripting and automation   |
| `--quiet`/`-q`| Minimal output — suppress headers and decorations   |
| `--no-color`  | Strip all ANSI colour codes (also reads `$NO_COLOR`)|

---

## Installation

**Requirements:** Python 3.10 or later.

```bash
# 1. Clone the repository
git clone https://github.com/0xfroOty/ByteTrace.git
cd bytetrace

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install ByteTrace and its dependencies
pip install -e .
```

**Runtime dependencies** (installed automatically):

| Package      | Purpose                        |
|--------------|--------------------------------|
| `click`      | CLI framework                  |
| `rich`       | Terminal tables and colours    |
| `capstone`   | Disassembly engine             |
| `pyelftools` | ELF format parsing             |
| `networkx`   | Control flow graph algorithms  |

---

## Quick Demo

```bash
# Overview of a binary
bytetrace info /bin/ls

# Section table
bytetrace sections /bin/ls

# List all functions, sorted by size (largest first)
bytetrace symbols /bin/ls --filter functions --sort size

# Search for a symbol
bytetrace symbols /bin/ls --search malloc

# Disassemble 10 instructions at an address, with explanations
bytetrace disasm /bin/ls --addr 0x54f0 --count 10 --explain

# Disassemble a function by name
bytetrace disasm /bin/ls --func main

# Control flow graph of a function
bytetrace cfg /bin/ls --func main

# Extract strings from the read-only data section
bytetrace strings /bin/ls --section .rodata

# Extract long strings (≥ 12 characters) from the whole binary
bytetrace strings /bin/ls --min-len 12

# Hexdump the first 128 bytes of .rodata
bytetrace hexdump /bin/ls --section .rodata --size 128

# Hexdump from a specific file offset
bytetrace hexdump /bin/ls --offset 0x1000 --size 64

# Machine-readable output for scripting
bytetrace symbols /bin/ls --json | jq '.symbols[] | select(.sym_type == "FUNC") | .name'

# Pipe-safe output (no colour codes)
bytetrace strings /bin/ls --quiet | grep -i password
```

---

## Command Reference

### `bytetrace info`

Shows a high-level overview of a binary: format, architecture, word size, endianness, entry point, dynamic linker path, and whether the binary is stripped or position-independent.

```bash
bytetrace info ./target
bytetrace info ./target --explain
bytetrace info ./target --json
```

---

### `bytetrace sections`

Lists every section in the binary with its offset, virtual address, size, permission flags, and a plain-English description of its purpose.

```bash
bytetrace sections ./target
bytetrace sections ./target --filter exec      # executable sections only
bytetrace sections ./target --filter write     # writable sections only
bytetrace sections ./target --explain
bytetrace sections ./target --json
```

**Filter values:** `exec`, `write`, `alloc`, `tls`

---

### `bytetrace symbols`

Lists symbols from the static symbol table (`.symtab`) and the dynamic symbol table (`.dynsym`), with type, binding, address, and size.

```bash
bytetrace symbols ./target
bytetrace symbols ./target --filter functions
bytetrace symbols ./target --filter dynamic
bytetrace symbols ./target --filter undefined
bytetrace symbols ./target --search memcpy
bytetrace symbols ./target --sort size          # largest functions first
bytetrace symbols ./target --json
```

**Filter values:** `functions`, `objects`, `dynamic`, `undefined`  
**Sort values:** `name`, `address`, `size`, `type`

---

### `bytetrace disasm`

Disassembles a function by symbol name or a sequence of instructions starting at a given address. With `--explain`, each instruction is annotated with a plain-English description.

```bash
bytetrace disasm ./target --func main
bytetrace disasm ./target --func main --explain
bytetrace disasm ./target --func main --count 20
bytetrace disasm ./target --addr 0x401234
bytetrace disasm ./target --addr 0x401234 --count 30
bytetrace disasm ./target --func main --json
bytetrace disasm ./target --func main --quiet
```

---

### `bytetrace cfg`

Builds and displays the Control Flow Graph of a function. Detects basic blocks, classifies edges (fall-through, conditional jump, unconditional jump), and reports cyclomatic complexity.

```bash
bytetrace cfg ./target --func main
bytetrace cfg ./target --func main --max-insns 300
bytetrace cfg ./target --addr 0x401234
bytetrace cfg ./target --func main --json
bytetrace cfg ./target --func main --quiet
```

**JSON output** includes a complete block and edge list suitable for further processing or visualisation.

---

### `bytetrace strings`

Scans raw binary bytes for contiguous runs of printable ASCII characters of at least `--min-len` bytes. Results are annotated with file offset, virtual address, and containing section.

```bash
bytetrace strings ./target
bytetrace strings ./target --section .rodata
bytetrace strings ./target --min-len 8
bytetrace strings ./target --no-offset           # hide file offset column
bytetrace strings ./target --json
bytetrace strings ./target --quiet               # one string per line, tab-separated
```

---

### `bytetrace hexdump`

Displays raw bytes in the classic `hexdump -C` layout: file offset, hex columns split at the midpoint, and an ASCII view with non-printable bytes replaced by `.`.

```bash
bytetrace hexdump ./target --section .rodata
bytetrace hexdump ./target --section .text --size 64
bytetrace hexdump ./target --offset 0x0 --size 16    # ELF header
bytetrace hexdump ./target --offset 0x2000 --size 256 --width 8
bytetrace hexdump ./target --section .interp --json
bytetrace hexdump ./target --offset 0x0 --size 16 --quiet   # classic format
```

---

## Architecture

ByteTrace follows a strict layered architecture. Each layer has a single responsibility and depends only on the layer below it.

```
┌────────────────────────────────────────────┐
│  CLI  (bytetrace/cli/)                     │  Parses arguments, validates input,
│  commands/  options.py  main.py            │  calls the analysis layer, passes
└─────────────────────┬──────────────────────┘  results to the renderer.
                      │
┌─────────────────────▼──────────────────────┐
│  Renderer  (bytetrace/output/)             │  Formats results for the terminal
│  tables.py  console.py                     │  (Rich or plain ANSI), JSON, or
└─────────────────────┬──────────────────────┘  quiet tab-separated output.
                      │
┌─────────────────────▼──────────────────────┐
│  Analysis  (bytetrace/core/  disasm/        │  Pure Python analysis modules:
│            cfg/  explain/  formats/)        │  no Click, no Rich, no I/O.
└────────────────────────────────────────────┘  Receives Binary, returns models.
```

### Module layout

```
bytetrace/
├── cli/
│   ├── main.py            Root Click group; registers all commands
│   ├── options.py         Shared decorators: --json, --explain, --quiet, …
│   └── commands/          One file per command
│       ├── info.py        bytetrace info
│       ├── sections.py    bytetrace sections
│       ├── symbols.py     bytetrace symbols
│       ├── disasm.py      bytetrace disasm
│       ├── cfg.py         bytetrace cfg
│       ├── strings.py     bytetrace strings
│       └── hexdump.py     bytetrace hexdump
│
├── core/
│   ├── binary.py          Binary dataclass (frozen): the central model
│   ├── section.py         Section dataclass
│   ├── symbol.py          Symbol dataclass
│   ├── enums.py           BinaryFormat, Architecture, Endianness, …
│   ├── strings.py         String extraction analysis
│   └── hexdump.py         Hexdump analysis
│
├── formats/
│   ├── base.py            BaseParser ABC + ParseError
│   └── elf.py             ELF parser (pyelftools backend)
│
├── disasm/
│   └── engine.py          Capstone wrapper; Instruction model; symbol resolution
│
├── cfg/
│   └── graph.py           BasicBlock + CFGraph; three-pass builder algorithm
│
├── explain/
│   ├── patterns.py        ~150-mnemonic table + 50 operand-context patterns
│   └── explainer.py       Four-tier resolution engine (pure Python, no deps)
│
└── output/
    ├── console.py         RichConsole / FallbackConsole factory
    └── tables.py          All render_*() functions
```

### Key design principles

- **Immutable models.** `Binary`, `Section`, `Symbol`, and `Instruction` are all `frozen=True` dataclasses. They are hashable and safe to pass between threads.
- **Rendering is decoupled.** Analysis modules return data objects. They never call `print()` or import Rich. The renderer layer owns all display decisions.
- **JSON is a first-class output.** Every command emits a stable JSON schema via `--json`. Field names are part of the public contract and will not change between minor versions.
- **Graceful Rich degradation.** If Rich is not installed, every command falls back to a plain ANSI renderer with identical structure. No crashes, no missing output.

---

## Supported Formats

| Format  | Status      | Parser       |
|---------|-------------|--------------|
| ELF     | ✅ Supported | `pyelftools` |
| PE      | 🔜 Planned  | —            |
| Mach-O  | 🔜 Planned  | —            |

Adding a new format requires creating one file in `bytetrace/formats/` that implements the `BaseParser` ABC and registering it in `bytetrace/formats/__init__.py`. No other code changes are needed.

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. **Fork** the repository and create a branch from `main`.
2. **Write tests** for any new analysis logic. Unit tests live alongside the module they test; integration tests live in `tests/`.
3. **Follow the architecture.** Analysis logic belongs in `core/`, `disasm/`, `cfg/`, or `explain/`. CLI changes belong in `cli/commands/`. Rendering changes belong in `output/tables.py`.
4. **Keep the layers clean.** Analysis modules must not import Click or Rich. CLI commands must not perform analysis directly.
5. **Run the test suite** before opening a pull request:
   ```bash
   pip install -e ".[dev]"
   pytest
   ```
6. Open a pull request with a clear description of what changed and why.

### Adding an instruction explanation

Open `bytetrace/explain/patterns.py` and add an entry to `MNEMONICS`:

```python
MNEMONICS: dict[str, str] = {
    # ...
    "vzeroupper": "Zero upper 128 bits of all YMM registers (AVX/SSE transition penalty avoidance)",
}
```

For a context-aware explanation tied to specific operands, prepend a triple to `_OPERAND_PATTERNS`:

```python
_OPERAND_PATTERNS = [
    ("vmaskmovps", "[", "Conditionally store packed floats to memory under mask"),
    # ... existing patterns ...
]
```

### Adding a format parser

1. Create `bytetrace/formats/pe.py` implementing `BaseParser`.
2. Add an instance to the `_PARSERS` list in `bytetrace/formats/__init__.py`.
3. All existing commands automatically gain PE support.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
