# IronView

`IronView` is a Python desktop application for inspecting binaries on Linux.
It combines four pieces:

- `libbfd` for section metadata and raw section bytes
- `PySide6` for the Qt GUI
- `radare2` through `r2pipe` for disassembly and function discovery
- GNU toolchain helpers like `addr2line`, `c++filt`, `nm`, `readelf`, and `gdb`

The project supports both GUI and CLI workflows.

## Current Features

- Open a binary and inspect section metadata
- Detect whether the loaded binary is `ELF`, `PE/COFF`, or `Mach-O`
- Preview raw section bytes as formatted hex
- Export the selected section to disk
- Filter sections by name, index, size, or address
- Preview section-level radare2 disassembly
- Browse radare2-discovered functions
- Browse radare2-discovered strings
- Browse radare2 imports
- Browse radare2 exports
- Browse radare2 relocations
- Browse radare2 symbols across `ELF`, `PE/COFF`, and `Mach-O`
- Inspect radare2 function CFGs
- Filter functions by name, address, type, or signature
- Filter strings by value, address, section, or type
- Filter imports by name, PLT address, bind, or type
- Filter symbols by raw name, demangled name, address, or type
- Preview full function disassembly for a selected function
- Preview a function-level HLL-style view through radare2 decompilation backends with fallback across `pdg`, `pdd`, and `pdc`
- Track HLL backend metadata, fallback state, warnings, and line/address correlations when radare2 exposes them
- Click jump and call targets directly from section and function disassembly
- Inspect xrefs to selected strings and jump from xrefs into functions
- Inspect callers of imported functions and jump from callers into functions
- Correlate exports and relocations to loaded symbols, imports, and functions when possible
- Inspect xrefs to selected exports and relocations and jump from those xrefs into functions
- Resolve demangled names with `c++filt`
- Resolve source locations with `addr2line` for ELF binaries when debug data is available
- Inspect cross-format binary metadata and linked libraries for `ELF`, `PE/COFF`, and `Mach-O`
- Switch between light and dark themes
- View a bottom system console with runtime events and analysis activity
- Run Linux shell commands from the bottom console
- Launch `codex` in an external terminal from the GUI
- Launch `gdb` in an external terminal for the current binary

## Requirements

- Python `3.14+`
- `uv`
- A working `libbfd` shared library on the host
- `radare2` available in `PATH`
- optional radare2 decompiler plugins such as `r2ghidra` (`pdg`) or `r2dec` (`pdd`) for richer HLL output
- GNU userland tools: `addr2line`, `c++filt`, `nm`, `readelf`, and optionally `gdb`
- A Linux desktop session for the GUI

Project dependencies are managed in [`pyproject.toml`](/home/gary/PycharmProjects/IronView/pyproject.toml).

## Install

From the project root:

```bash
cd /home/gary/PycharmProjects/IronView
uv sync
```

If the project environment does not exist yet, `uv sync` will create it and install:

- `PySide6`
- `pytest`
- `r2pipe`

## Run

Launch the GUI:

```bash
cd /home/gary/PycharmProjects/IronView
uv run python -m src.main
```

Launch the GUI with a binary preloaded:

```bash
uv run python -m src.main --gui /bin/ls
```

Run the CLI JSON output mode:

```bash
uv run python -m src.main /bin/ls
```

Dump one section as hex in CLI mode:

```bash
uv run python -m src.main /bin/ls --section .text
```

## GUI Workflow

1. Start the app.
2. Open a binary with `Ctrl+O` or the `Open Binary` button.
3. Use the `Sections` pane to inspect raw sections.
4. Use the lower browser tabs for `Functions`, `Strings`, `Imports`, `Exports`, `Relocations`, and `Symbols`.
5. Switch between the `Section`, `Function`, `String`, `Import`, `Export`, `Relocation`, `Symbol`, and `Binary` inspector tabs on the right.
6. Use the `Hex` and `Disassembly` tabs inside the section inspector for byte and instruction views, and click linked jump or call targets to navigate.
7. Select a string to load xrefs, then double-click an xref row to jump to the referenced function when available.
8. Select an import to load callers, then double-click a caller row to jump to the referenced function when available.
9. Select an export or relocation to load correlated context and xrefs.
10. Double-click an export or relocation row to jump toward the matching symbol, import, or function when available.
11. Double-click an export or relocation xref row to jump to the referenced function when available.
12. Select a function or symbol to load demangling and, for ELF binaries, source-location metadata.
13. Use the `HLL` sub-tab inside the function inspector to review the best available radare2 decompilation backend output.
14. Use the `CFG` sub-tab inside the function inspector to review basic blocks and click a block to jump into disassembly.
15. Use the `Binary` tab to inspect the current binary through a radare2-backed metadata report and linked-library view.
16. Use the bottom `System Console` to watch loads, exports, errors, and analysis activity.
17. Enter Linux commands in the console input and run them in the project directory.
18. Use `Run Codex` to launch `codex` in an external terminal with a real TTY.
19. Use `Run GDB` to launch `gdb` for the current binary in an external terminal.

## CLI Behavior

[`src/main.py`](/home/gary/PycharmProjects/IronView/src/main.py) currently behaves like this:

- No positional `path`: launch the Qt GUI
- `path` only: print JSON with path, file format, format detail, architecture size, and sections
- `path --section NAME`: print the section bytes as hex
- `--gui [path]`: force GUI mode

## Architecture

Implementation details are documented in [`docs/architecture.md`](/home/gary/PycharmProjects/IronView/docs/architecture.md).

At a high level:

- [`src/binary_loader.py`](/home/gary/PycharmProjects/IronView/src/binary_loader.py) wraps `libbfd`
- [`src/disassembler.py`](/home/gary/PycharmProjects/IronView/src/disassembler.py) wraps `radare2`
- [`src/gnu_toolchain.py`](/home/gary/PycharmProjects/IronView/src/gnu_toolchain.py) wraps GNU binutils helpers
- [`src/gui.py`](/home/gary/PycharmProjects/IronView/src/gui.py) implements the Qt application
- [`src/main.py`](/home/gary/PycharmProjects/IronView/src/main.py) is the CLI/GUI entrypoint

## Verification

Run the test suite:

```bash
cd /home/gary/PycharmProjects/IronView
QT_QPA_PLATFORM=offscreen uv run pytest
```

Run a syntax check:

```bash
python3 -m py_compile src/gnu_toolchain.py src/disassembler.py src/gui.py src/main.py src/binary_loader.py src/test_main.py
```

## Known Limits

- The app is currently Linux-oriented.
- `libbfd` must be available at runtime or section loading will fail.
- radare2 is used for read-only analysis only.
- `ELF` is the most complete format today.
- `PE/COFF` and `Mach-O` currently use the `libbfd` and radare2 paths, while GNU `addr2line` source lookup remains intentionally disabled for them.
- Source mapping depends on debug info being present in or reachable from the binary.
- The current radare2 integration covers sections, strings, imports, exports, relocations, symbols, functions, xrefs/callers, disassembly, HLL-style output through `pdg`/`pdd`/`pdc` fallback, and first-pass CFG views.
