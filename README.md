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
- Preview raw section bytes as formatted hex
- Export the selected section to disk
- Filter sections by name, index, size, or address
- Preview section-level radare2 disassembly
- Browse radare2-discovered functions
- Browse radare2-discovered strings
- Browse radare2 imports
- Browse GNU `nm` symbols
- Filter functions by name, address, type, or signature
- Filter strings by value, address, section, or type
- Filter imports by name, PLT address, bind, or type
- Filter symbols by raw name, demangled name, address, or type
- Preview full function disassembly for a selected function
- Click jump and call targets directly from section and function disassembly
- Inspect xrefs to selected strings and jump from xrefs into functions
- Inspect callers of imported functions and jump from callers into functions
- Resolve demangled names with `c++filt`
- Resolve source locations with `addr2line` when debug data is available
- Inspect ELF headers, program headers, and sections through `readelf`
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
- GNU userland tools: `addr2line`, `c++filt`, `nm`, `readelf`, and optionally `gdb`
- A Linux desktop session for the GUI

Project dependencies are managed in [`pyproject.toml`](/home/gary/PycharmProjects/new_app/pyproject.toml).

## Install

From the project root:

```bash
cd /home/gary/PycharmProjects/new_app
uv sync
```

If the project environment does not exist yet, `uv sync` will create it and install:

- `PySide6`
- `pytest`
- `r2pipe`

## Run

Launch the GUI:

```bash
cd /home/gary/PycharmProjects/new_app
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
4. Use the lower browser tabs for `Functions`, `Strings`, `Imports`, and `Symbols`.
5. Switch between the `Section`, `Function`, `String`, `Import`, `Symbol`, and `ELF` inspector tabs on the right.
6. Use the `Hex` and `Disassembly` tabs inside the section inspector for byte and instruction views, and click linked jump or call targets to navigate.
7. Select a string to load xrefs, then double-click an xref row to jump to the referenced function when available.
8. Select an import to load callers, then double-click a caller row to jump to the referenced function when available.
9. Select a function or symbol to load GNU demangling and source-location metadata.
10. Use the `ELF` tab to inspect the current binary through `readelf`.
11. Use the bottom `System Console` to watch loads, exports, errors, and analysis activity.
12. Enter Linux commands in the console input and run them in the project directory.
13. Use `Run Codex` to launch `codex` in an external terminal with a real TTY.
14. Use `Run GDB` to launch `gdb` for the current binary in an external terminal.

## CLI Behavior

[`src/main.py`](/home/gary/PycharmProjects/new_app/src/main.py) currently behaves like this:

- No positional `path`: launch the Qt GUI
- `path` only: print JSON with path, architecture size, and sections
- `path --section NAME`: print the section bytes as hex
- `--gui [path]`: force GUI mode

## Architecture

Implementation details are documented in [`docs/architecture.md`](/home/gary/PycharmProjects/new_app/docs/architecture.md).

At a high level:

- [`src/binary_loader.py`](/home/gary/PycharmProjects/new_app/src/binary_loader.py) wraps `libbfd`
- [`src/disassembler.py`](/home/gary/PycharmProjects/new_app/src/disassembler.py) wraps `radare2`
- [`src/gnu_toolchain.py`](/home/gary/PycharmProjects/new_app/src/gnu_toolchain.py) wraps GNU binutils helpers
- [`src/gui.py`](/home/gary/PycharmProjects/new_app/src/gui.py) implements the Qt application
- [`src/main.py`](/home/gary/PycharmProjects/new_app/src/main.py) is the CLI/GUI entrypoint

## Verification

Run the test suite:

```bash
cd /home/gary/PycharmProjects/new_app
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
- Source mapping depends on debug info being present in or reachable from the binary.
- The current radare2 integration covers sections, strings, imports, functions, xrefs/callers, and disassembly, but not yet graph views.
