# Architecture

This document describes the project structure after the initial GUI and radare2 integration.

## Overview

The application has three analysis backends and one presentation layer:

- `libbfd` for object/section inspection
- `radare2` for disassembly and function discovery
- GNU binutils helpers for symbols, demangling, source lookup, and ELF reporting
- `PySide6` for the desktop UI

The CLI and GUI share the same binary inspection primitives.

## Module Layout

### [`src/main.py`](/home/gary/PycharmProjects/IronView/src/main.py)

Entry point for both CLI and GUI usage.

Responsibilities:

- parse command-line arguments
- select GUI mode or CLI mode
- print section metadata in JSON form for CLI usage
- dump a section as hex in CLI mode

### [`src/binary_loader.py`](/home/gary/PycharmProjects/IronView/src/binary_loader.py)

`libbfd` wrapper implemented with `ctypes`.

Responsibilities:

- open a binary
- validate object format
- enumerate sections
- read raw section bytes
- expose immutable data objects for sections and the full image

Primary public types:

- `BinaryLoader`
- `BinaryImage`
- `SectionInfo`
- `BinaryLoaderError`

### [`src/disassembler.py`](/home/gary/PycharmProjects/IronView/src/disassembler.py)

Read-only `radare2` integration through `r2pipe`.

Responsibilities:

- open `radare2` with conservative flags
- run `aa`
- return structured linear disassembly for a section
- enumerate functions with `aflj`
- enumerate strings with `izj`
- enumerate imports with `iij`
- enumerate xrefs with `axtj`
- return full function disassembly with `pdfj`
- return function CFGs with `agfj`

Primary public types:

- `Radare2Disassembler`
- `DisassemblyResult`
- `FunctionInfo`
- `FunctionDisassemblyResult`
- `Radare2DisassemblerError`

Current radare2 open flags:

```text
-N -2 -e scr.color=0 -e bin.relocs.apply=true
```

These are intended to keep sessions predictable, quiet, and read-only.

### [`src/gnu_toolchain.py`](/home/gary/PycharmProjects/IronView/src/gnu_toolchain.py)

GNU toolchain wrapper implemented with `subprocess`.

Responsibilities:

- demangle names with `c++filt`
- resolve source locations with `addr2line`
- enumerate symbols with `nm`
- capture ELF structure reports with `readelf`
- expose a small typed interface to the GUI

### [`src/gui.py`](/home/gary/PycharmProjects/IronView/src/gui.py)

Qt desktop application built with `PySide6`.

Responsibilities:

- present sections and functions in filterable tables
- present strings and xrefs in filterable tables
- present imports and callers in filterable tables
- present GNU symbols in a filterable table
- load section bytes in the background
- load section and function disassembly in the background
- load string xrefs in the background
- load import callers in the background
- load GNU symbol lists, ELF reports, and source metadata in the background
- show section details, hex preview, and disassembly preview
- show function metadata, demangled names, source locations, and full function disassembly
- show string metadata and callers/xrefs
- show import metadata and callers
- show symbol metadata and source locations
- show `readelf` output for the current binary
- record runtime activity in a bottom system console
- run shell commands through a `QProcess` command runner
- launch `codex` in an external terminal session
- launch `gdb` in an external terminal session
- manage export, theme switching, and application shutdown

## GUI Layout

The current window is organized as:

- Top header: title, subtitle, open button
- Overview group: path, architecture, section count
- Left vertical split:
  - Sections browser
  - Browser tabs:
    - Functions browser
    - Strings browser
    - Imports browser
    - Symbols browser
- Right inspector tabs:
  - Section
  - Function
  - String
  - Import
  - Symbol
  - ELF
- Bottom console:
  - timestamped runtime and analysis log
  - shell command input and command output
  - external `codex` launcher
  - external `gdb` launcher

Section inspector:

- metadata form
- `Hex` tab
- `Disassembly` tab
- clickable jump and call target links rendered inside the disassembly view

Function inspector:

- metadata form
- GNU demangled/source fields
- full function disassembly preview
- CFG tab with clickable basic blocks
- clickable target links that navigate within the current function or into another loaded function

String inspector:

- metadata form
- xrefs table
- double-click xref navigation into the function browser

Import inspector:

- metadata form
- callers table
- double-click caller navigation into the function browser

Symbol inspector:

- metadata form
- demangled name
- source location

ELF inspector:

- raw `readelf -h -l -S --wide` output

## Background Work Model

The UI uses `QRunnable` workers and a local `QThreadPool`.

Current worker types:

- `ImageLoadWorker`
- `SectionLoadWorker`
- `DisassemblyLoadWorker`
- `FunctionListWorker`
- `FunctionDisassemblyWorker`
- `FunctionGraphWorker`
- `StringListWorker`
- `XrefLoadWorker`
- `ImportListWorker`
- `ImportXrefLoadWorker`
- `SymbolListWorker`
- `ElfReportWorker`
- `AddressMetadataWorker`

Why this matters:

- the GUI remains responsive while reading binaries
- radare2 analysis does not block the event loop
- shutdown is safer because worker results are emitted through guarded signal helpers

## Data Flow

### Section Flow

1. User selects a binary.
2. `BinaryLoader` opens it and returns section metadata.
3. Sections are shown in the table.
4. User selects a section.
5. Two background tasks start:
   - raw section read through `BinaryLoader`
   - linear disassembly through `Radare2Disassembler`
6. The section inspector updates when results arrive.

### Function Flow

1. After image load, radare2 function enumeration starts.
2. `aflj` results populate the function table.
3. User selects a function.
4. `pdfj @ <addr>` and `agfj @ <addr>` run in the background.
5. The function inspector updates with metadata, formatted disassembly, and a clickable control-flow graph.

### String Flow

1. After image load, radare2 string enumeration starts.
2. `izj` results populate the string table.
3. User selects a string.
4. `axtj @ <addr>` runs in the background.
5. The string inspector updates with xrefs.
6. Double-clicking a referenced xref selects the matching function when one is loaded.

### Import Flow

1. After image load, radare2 import enumeration starts.
2. `iij` results populate the import table.
3. User selects an import.
4. `axtj @ sym.imp.<name>` runs in the background.
5. The import inspector updates with callers.
6. Double-clicking a caller selects the matching function when one is loaded.

### GNU Flow

1. After image load, GNU symbol enumeration starts through `nm`.
2. The symbols tab populates with raw and demangled names.
3. A `readelf` report loads into the `ELF` inspector tab.
4. When a function or symbol is selected, `c++filt` and `addr2line` run in the background.
5. The active inspector updates with demangled names and source-location metadata.
6. `Run GDB` launches an external debugger session for the current binary.

## Error Handling

Errors are surfaced as application-level messages rather than uncaught worker failures.

Current strategy:

- backend wrappers raise typed runtime errors
- workers catch backend errors and emit GUI signals
- stale worker results are ignored if selection or file context changed
- signal emission is guarded so late worker completion during shutdown does not crash the app

## Tests

Current test coverage in [`src/test_main.py`](/home/gary/PycharmProjects/IronView/src/test_main.py) covers:

- section listing
- section reads
- missing-section errors
- CLI launch behavior
- section filtering helpers
- export path generation
- radare2 section disassembly
- radare2 function listing and function disassembly
- radare2 function CFG loading
- radare2 string listing and xrefs
- radare2 import listing and callers
- GNU symbol listing
- GNU ELF report loading
- GUI section filter state
- GUI function filter state
- GUI string filter state
- GUI import filter state
- GUI symbol filter state

## Current Limitations

Not implemented yet:

- symbol rename/comment persistence
- patching or write-mode analysis

Those are the natural next steps if the project continues to grow into a broader reverse-engineering workbench.
