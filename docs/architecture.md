# Architecture

This document describes the project structure after the initial GUI and radare2 integration.

## Overview

The application has four analysis backends and one presentation layer:

- `libbfd` for object/section inspection
- `radare2` for disassembly and function discovery
- optional `Ghidra` for external GUI work and headless analysis reports
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
- detect the container format from on-disk signatures
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

Documented baseline: `radare2 6.1.1` on Linux.

Responsibilities:

- open `radare2` with conservative flags
- run `aa`
- return structured linear disassembly for a section
- enumerate functions with `aflj`
- enumerate strings with `izj`
- enumerate imports with `iij`
- enumerate exports with `iEj`
- enumerate relocations with `irj`
- enumerate xrefs with `axtj`
- return full function disassembly with `pdfj`
- detect available radare2 decompilation backends and decompile through `pdg`, `pdd`, or `pdc`
- capture backend metadata, fallback state, warnings, and line/address correlations for HLL output when available
- apply display-side `Clean HLL` heuristics for import thunks, static registration, fini teardown, stack-canary scaffolding, stack probes, scoped stack-object wrappers, and declaration noise
- return function CFGs with `agfj`
- build a cross-format binary metadata report from `ij`, `iSj`, `iej`, `ilj`, and `iij`

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

These helpers are currently treated as ELF-oriented in the GUI. For `PE/COFF`
and `Mach-O`, the app keeps the `libbfd` and radare2 paths enabled and
intentionally disables GNU report/source features.

### [`src/ghidra_toolchain.py`](/home/gary/PycharmProjects/IronView/src/ghidra_toolchain.py)

Optional Ghidra integration implemented with `subprocess`.

Responsibilities:

- detect `ghidra` and `analyzeHeadless` on the host
- capture the locally installed Ghidra package version
- build a deterministic `analyzeHeadless` command for the current binary
- run on-demand headless analysis and return a textual report for the GUI

### [`src/gui.py`](/home/gary/PycharmProjects/IronView/src/gui.py)

Qt desktop application built with `PySide6`.

Responsibilities:

- present sections and functions in filterable tables
- present strings and xrefs in filterable tables
- present imports and callers in filterable tables
- present exports in a filterable table
- present relocations in a filterable table
- present radare2 symbols in a filterable table across supported formats
- load section bytes in the background
- load section and function disassembly in the background
- load string xrefs in the background
- load import callers in the background
- load export xrefs in the background
- load relocation xrefs in the background
- load radare2 symbol lists, radare2 binary reports, and GNU source metadata when supported
- run optional Ghidra headless analysis in the background
- show section details, hex preview, and disassembly preview
- show function metadata, demangled names, source locations, and full function disassembly
- show string metadata and callers/xrefs
- show import metadata and callers
- show export metadata and matched symbol/function context
- show export xrefs and navigate from them into functions
- show relocation metadata and matched import/function context
- show relocation xrefs and navigate from them into functions
- show symbol metadata and source locations
- show a cross-format radare2 metadata report for the current binary
- show optional Ghidra headless analysis output for the current binary
- record runtime activity in a bottom system console
- run shell commands through a `QProcess` command runner
- launch `codex` in an external terminal session
- launch `gdb` in an external terminal session
- launch `Ghidra` as an external GUI application
- manage export, theme switching, and application shutdown

## GUI Layout

The current window is organized as:

- Top header: title, subtitle, open button
- Overview group: path, format, format detail, architecture, section count
- Left vertical split:
  - Sections browser
  - Browser tabs:
    - Functions browser
    - Strings browser
    - Imports browser
    - Exports browser
    - Relocations browser
    - Symbols browser
- Right inspector tabs:
  - Section
  - Function
  - String
  - Import
  - Export
  - Relocation
  - Symbol
  - Binary
- Bottom console:
  - timestamped runtime and analysis log
  - shell command input and command output
  - external `codex` launcher
  - external `gdb` launcher
  - external `Ghidra` launcher
- View controls:
  - collapsible browser pane
  - collapsible console pane

Section inspector:

- metadata form
- `Hex` tab
- `Disassembly` tab
- clickable jump and call target links rendered inside the disassembly view

Function inspector:

- metadata form
- GNU demangled/source fields
- full function disassembly preview
- HLL-style decompilation tab backed by the best available radare2 decompilation backend
- backend/fallback status and correlation-aware metadata derived from decompiler output
- HLL backend selector, reload control, and `Clean HLL` toggle
- clickable HLL line links that navigate into disassembly when line/address mappings are available
- correlated HLL context table for matched functions, imports, strings, and symbols
- inline semantic HLL links for matched functions, imports, strings, and symbols when the text match is unambiguous
- HLL call summary and extracted argument/local declaration summary
- backend JSON-aware HLL extraction for calls and declarations, with text parsing fallback
- display-side HLL cleanup that can collapse import thunks, static registration, fini teardown, stack-canary scaffolding, stack probes, scoped stack-object wrappers, and leading temp declarations into a single summary block even when the decompiler inserts blank lines between the signature and function body
- CFG tab with clickable basic blocks
- clickable target links that navigate within the current function or into another loaded function
- thicker splitter handles, minimum pane sizes, browser/console visibility toggles, and a `Reset Layout` action to recover from cramped layouts

String inspector:

- metadata form
- xrefs table
- double-click xref navigation into the function browser

Import inspector:

- metadata form
- callers table
- double-click caller navigation into the function browser

Export inspector:

- metadata form
- xrefs table
- double-click xref navigation into the function browser

Relocation inspector:

- metadata form
- xrefs table
- double-click xref navigation into the function browser

Symbol inspector:

- metadata form
- demangled name
- source location when supported

Binary inspector:

- cross-format metadata summary
- section, entrypoint, library, and import listings from radare2
- linked-library table
- `Ghidra` availability summary
- `Launch Ghidra` action
- `Run Headless Analysis` action
- text report area for Ghidra headless output

## Background Work Model

The UI uses `QRunnable` workers and a local `QThreadPool`.

Current worker types:

- `ImageLoadWorker`
- `SectionLoadWorker`
- `DisassemblyLoadWorker`
- `FunctionListWorker`
- `FunctionDisassemblyWorker`
- `FunctionDecompilationWorker`
- `FunctionGraphWorker`
- `StringListWorker`
- `XrefLoadWorker`
- `ImportListWorker`
- `ExportListWorker`
- `RelocationListWorker`
- `ImportXrefLoadWorker`
- `ExportXrefLoadWorker`
- `RelocationXrefLoadWorker`
- `SymbolListWorker`
- `BinaryReportWorker`
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
4. `pdfj @ <addr>`, the selected or best available decompilation command from `pdg`/`pdd`/`pdc`, and `agfj @ <addr>` run in the background.
5. The function inspector updates with metadata, formatted disassembly, an HLL-style view with backend status, an optional `Clean HLL` presentation layer, optional clickable line/address mappings, inline semantic links, extracted declaration and call summaries, a correlated context table, and a clickable control-flow graph. The cleaned view can condense mixed real/temp leading declaration blocks into a single summary comment instead of repeating multiple `/* temporaries omitted */` markers.

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

### Export / Relocation Flow

1. After image load, radare2 export and relocation enumeration start.
2. `iEj` results populate the export table, and `irj` results populate the relocation table.
3. User selects an export or relocation.
4. `axtj @ <addr>` runs in the background for the selected export or relocation.
5. The matching inspector tab updates with metadata, xrefs, and correlated symbol/import/function context when available.
6. Double-clicking an export or relocation row attempts to jump into the matching function, symbol, or import context.
7. Double-clicking an export or relocation xref row selects the matching function when one is loaded.

### Metadata Flow

1. After image load, radare2 symbol enumeration starts through `isj`.
2. The symbols tab populates with raw names and origin/type data across supported formats.
3. A radare2 binary metadata report loads into the `Binary` inspector tab.
4. When a function or symbol is selected, `c++filt` runs in the background, and `addr2line` joins in for ELF binaries.
5. The active inspector updates with demangled names and source-location metadata when available.
6. `Run GDB` launches an external debugger session for the current binary.

### Ghidra Flow

1. The GUI detects `ghidra` / `analyzeHeadless` availability once at startup.
2. The `Binary` inspector surfaces Ghidra availability and exposes launch actions.
3. `Launch Ghidra` starts the external Ghidra GUI without blocking the Qt event loop.
4. `Run Headless Analysis` starts a background worker that invokes `analyzeHeadless` for the current binary.
5. The `Binary` inspector updates with the resulting headless report text or a structured failure message.

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
- radare2 function decompilation, backend fallback, and HLL metadata/correlation parsing
- clean-mode HLL rendering heuristics for the current display-side simplification layer
- resilient splitter/layout defaults and reset behavior for the main GUI work areas
- radare2 function CFG loading
- radare2 string listing and xrefs
- radare2 import listing and callers
- radare2 export listing
- radare2 relocation listing
- radare2 export xref loading
- radare2 relocation xref loading
- radare2 symbol listing
- radare2 binary metadata reporting
- Ghidra headless command construction and reporting
- linked-library population in the binary inspector
- GNU ELF report loading
- GUI section filter state
- GUI function filter state
- GUI string filter state
- GUI import filter state
- GUI export filter state
- GUI export xref display and navigation
- GUI relocation filter state
- GUI relocation xref display and navigation
- GUI symbol filter state

## Current Limitations

Not implemented yet:

- symbol rename/comment persistence
- patching or write-mode analysis
- deeper Ghidra type/name/decompiler import back into the main analysis views

Those are the natural next steps if the project continues to grow into a broader reverse-engineering workbench.
