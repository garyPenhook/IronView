from __future__ import annotations

import os
import shlex
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence

from PySide6.QtCore import QObject, QPointF, QProcess, QRunnable, Qt, QThreadPool, QUrl, Signal
from PySide6.QtGui import (
    QAction,
    QActionGroup,
    QBrush,
    QCloseEvent,
    QColor,
    QFontDatabase,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsTextItem,
    QGraphicsView,
    QGroupBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from src.binary_loader import BinaryImage, BinaryLoader, BinaryLoaderError, SectionInfo
from src.disassembler import (
    ControlFlowBlock,
    ControlFlowEdge,
    DEFAULT_INSTRUCTION_LIMIT,
    DisassemblyResult,
    FunctionDecompilationResult,
    FunctionDisassemblyResult,
    FunctionGraphResult,
    FunctionInfo,
    ImportInfo,
    Radare2Disassembler,
    Radare2DisassemblerError,
    StringInfo,
    XrefInfo,
    format_disassembly_html,
    format_function_disassembly_html,
)
from src.gnu_toolchain import ElfReport, GnuToolchain, GnuToolchainError, SourceLocation, SymbolInfo

HEX_PREVIEW_LIMIT = 8192
LIGHT_THEME = "light"
DARK_THEME = "dark"
SECTION_COLUMNS = (
    "Name",
    "Index",
    "Size",
    "VMA",
    "LMA",
    "Flags",
    "Align",
    "File Offset",
)
FUNCTION_COLUMNS = (
    "Name",
    "Address",
    "Size",
    "Instr",
    "Type",
)
STRING_COLUMNS = (
    "Value",
    "Address",
    "Length",
    "Section",
    "Type",
)
IMPORT_COLUMNS = (
    "Name",
    "PLT",
    "Bind",
    "Type",
)
SYMBOL_COLUMNS = (
    "Name",
    "Demangled",
    "Address",
    "Type",
    "Origin",
)
XREF_COLUMNS = (
    "From",
    "Function",
    "Type",
    "Opcode",
)
APP_NAME = "IronView"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKDIR = PROJECT_ROOT


def _format_int(value: int) -> str:
    return f"{value:,}"


def _format_hex(value: int) -> str:
    return f"0x{value:X}"


def _format_preview(data: bytes, *, max_bytes: int = HEX_PREVIEW_LIMIT) -> str:
    visible = data[:max_bytes]
    lines: list[str] = []
    for offset in range(0, len(visible), 16):
        chunk = visible[offset : offset + 16]
        hex_bytes = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_bytes = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:08X}  {hex_bytes:<47}  {ascii_bytes}")
    if len(data) > max_bytes:
        hidden = len(data) - max_bytes
        lines.append("")
        lines.append(f"... truncated {hidden:,} additional bytes")
    return "\n".join(lines)


def _matches_section_filter(section: SectionInfo, query: str) -> bool:
    normalized = query.strip().lower()
    if not normalized:
        return True
    haystacks = (
        section.name,
        str(section.index),
        str(section.size),
        _format_hex(section.vma),
        _format_hex(section.lma),
        _format_hex(section.flags),
        str(section.alignment_power),
        _format_hex(section.file_offset),
    )
    return any(normalized in value.lower() for value in haystacks)


def _matches_function_filter(function: FunctionInfo, query: str) -> bool:
    normalized = query.strip().lower()
    if not normalized:
        return True
    haystacks = (
        function.name,
        _format_hex(function.address),
        str(function.size),
        str(function.instruction_count),
        function.kind,
        function.signature,
    )
    return any(normalized in value.lower() for value in haystacks)


def _matches_string_filter(string: StringInfo, query: str) -> bool:
    normalized = query.strip().lower()
    if not normalized:
        return True
    haystacks = (
        string.value,
        _format_hex(string.address),
        str(string.length),
        string.section,
        string.kind,
    )
    return any(normalized in value.lower() for value in haystacks)


def _matches_import_filter(imp: ImportInfo, query: str) -> bool:
    normalized = query.strip().lower()
    if not normalized:
        return True
    haystacks = (
        imp.name,
        _format_hex(imp.plt_address),
        imp.bind,
        imp.kind,
    )
    return any(normalized in value.lower() for value in haystacks)


def _matches_symbol_filter(symbol: SymbolInfo, query: str) -> bool:
    normalized = query.strip().lower()
    if not normalized:
        return True
    haystacks = (
        symbol.name,
        symbol.demangled_name,
        _format_hex(symbol.address),
        symbol.kind,
        "dynamic" if symbol.is_dynamic else "regular",
    )
    return any(normalized in value.lower() for value in haystacks)


def _build_export_path(binary_path: Path, section_name: str) -> Path:
    safe_name = section_name.lstrip(".").replace("/", "_") or "section"
    return binary_path.with_name(f"{binary_path.name}.{safe_name}.bin")


def _function_contains_address(function: FunctionInfo, address: int) -> bool:
    if function.address == address:
        return True
    return function.size > 0 and function.address <= address < function.address + function.size


def _address_anchor(address: int) -> str:
    return f"addr-{address:X}"


def _source_text(source_location: SourceLocation | None) -> str:
    if source_location is None:
        return "Unavailable"
    return source_location.display_text


def _cfg_block_contains_address(block: ControlFlowBlock, address: int) -> bool:
    if block.address == address:
        return True
    return block.size > 0 and block.address <= address < block.address + block.size


def _find_cfg_block_address(blocks: tuple[ControlFlowBlock, ...], address: int) -> int | None:
    for block in blocks:
        if _cfg_block_contains_address(block, address):
            return block.address
    return None


def _cfg_preview_text(block: ControlFlowBlock, *, limit: int = 4) -> str:
    lines = [f"{_format_hex(block.address)}  ({len(block.instructions)} instr)"]
    for instruction in block.instructions[:limit]:
        lines.append(f"{instruction.address:08X}  {instruction.text}")
    if len(block.instructions) > limit:
        lines.append("...")
    return "\n".join(lines)


def _shell_path() -> str:
    return os.environ.get("SHELL") or "/bin/sh"


def _terminal_command() -> str | None:
    for candidate in ("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal"):
        resolved = shutil.which(candidate)
        if resolved is not None:
            return resolved
    return None


def _theme_stylesheet(theme: str) -> str:
    if theme != DARK_THEME:
        return ""
    return """
QWidget {
    background: #14181d;
    color: #eef2f7;
}
QMainWindow, QMenuBar, QMenu, QToolBar, QStatusBar {
    background: #11151a;
}
QGroupBox {
    border: 1px solid #2e3947;
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 12px;
    background: #192029;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 4px;
    color: #9db3c8;
}
QTableWidget, QPlainTextEdit, QTextBrowser, QGraphicsView, QLineEdit {
    background: #0f141a;
    border: 1px solid #314152;
    border-radius: 6px;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
}
QHeaderView::section {
    background: #1b2430;
    color: #dce6f2;
    border: 0;
    border-right: 1px solid #2f3d4c;
    border-bottom: 1px solid #2f3d4c;
    padding: 6px;
}
QPushButton {
    background: #1e5bb8;
    border: 0;
    border-radius: 6px;
    color: white;
    padding: 8px 14px;
}
QPushButton:hover {
    background: #2b6ed3;
}
QPushButton:disabled {
    background: #445061;
    color: #b5bdc8;
}
QLabel[role="muted"] {
    color: #9db3c8;
}
"""


@dataclass(frozen=True, slots=True)
class LoadedImage:
    path: Path
    image: BinaryImage


@dataclass(frozen=True, slots=True)
class LoadedDisassembly:
    path: Path
    section_name: str
    result: DisassemblyResult | None
    message: str = ""


@dataclass(frozen=True, slots=True)
class LoadedFunctions:
    path: Path
    functions: tuple[FunctionInfo, ...]


@dataclass(frozen=True, slots=True)
class LoadedFunctionDisassembly:
    path: Path
    function_address: int
    result: FunctionDisassemblyResult | None
    message: str = ""


@dataclass(frozen=True, slots=True)
class LoadedFunctionDecompilation:
    path: Path
    function_address: int
    result: FunctionDecompilationResult | None
    message: str = ""


@dataclass(frozen=True, slots=True)
class LoadedFunctionGraph:
    path: Path
    function_address: int
    result: FunctionGraphResult | None
    message: str = ""


@dataclass(frozen=True, slots=True)
class LoadedStrings:
    path: Path
    strings: tuple[StringInfo, ...]


@dataclass(frozen=True, slots=True)
class LoadedXrefs:
    path: Path
    string_address: int
    xrefs: tuple[XrefInfo, ...]


@dataclass(frozen=True, slots=True)
class LoadedImports:
    path: Path
    imports: tuple[ImportInfo, ...]


@dataclass(frozen=True, slots=True)
class LoadedImportXrefs:
    path: Path
    import_name: str
    xrefs: tuple[XrefInfo, ...]


@dataclass(frozen=True, slots=True)
class LoadedSymbols:
    path: Path
    symbols: tuple[SymbolInfo, ...]


@dataclass(frozen=True, slots=True)
class LoadedElfReport:
    path: Path
    report: ElfReport | None
    message: str = ""


@dataclass(frozen=True, slots=True)
class LoadedAddressMetadata:
    path: Path
    subject: str
    address: int
    raw_name: str
    demangled_name: str
    source_location: SourceLocation | None


@dataclass(frozen=True, slots=True)
class ErrorInfo:
    title: str
    message: str


class WorkerSignals(QObject):
    loaded_image = Signal(object)
    loaded_section = Signal(str, bytes)
    loaded_disassembly = Signal(object)
    loaded_functions = Signal(object)
    loaded_function_disassembly = Signal(object)
    loaded_function_decompilation = Signal(object)
    loaded_function_graph = Signal(object)
    loaded_strings = Signal(object)
    loaded_xrefs = Signal(object)
    loaded_imports = Signal(object)
    loaded_import_xrefs = Signal(object)
    loaded_symbols = Signal(object)
    loaded_elf_report = Signal(object)
    loaded_address_metadata = Signal(object)
    error = Signal(object)


def _safe_emit(signal: Signal, *args: object) -> bool:
    try:
        signal.emit(*args)
    except RuntimeError:
        return False
    return True


def _emit_error(signals: WorkerSignals, title: str, message: str) -> bool:
    return _safe_emit(signals.error, ErrorInfo(title=title, message=message))


class FunctionGraphView(QGraphicsView):
    blockActivated = Signal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)

    def mousePressEvent(self, event) -> None:  # type: ignore[override]
        item = self.itemAt(event.position().toPoint())
        while item is not None:
            address = item.data(0)
            if isinstance(address, int):
                self.blockActivated.emit(address)
                break
            item = item.parentItem()
        super().mousePressEvent(event)


class ImageLoadWorker(QRunnable):
    def __init__(self, path: Path, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.signals = signals

    def run(self) -> None:
        try:
            with BinaryLoader(self.path) as loader:
                image = loader.image()
        except BinaryLoaderError as exc:
            _emit_error(self.signals, "Binary Loader Error", str(exc))
            return
        _safe_emit(self.signals.loaded_image, LoadedImage(self.path, image))


class SectionLoadWorker(QRunnable):
    def __init__(self, path: Path, section_name: str, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.section_name = section_name
        self.signals = signals

    def run(self) -> None:
        try:
            with BinaryLoader(self.path) as loader:
                section_bytes = loader.read_section(self.section_name)
        except BinaryLoaderError as exc:
            _emit_error(self.signals, "Binary Loader Error", str(exc))
            return
        _safe_emit(self.signals.loaded_section, self.section_name, section_bytes)


class DisassemblyLoadWorker(QRunnable):
    def __init__(self, path: Path, section: SectionInfo, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.section = section
        self.signals = signals

    def run(self) -> None:
        if self.section.size == 0:
            _safe_emit(
                self.signals.loaded_disassembly,
                LoadedDisassembly(
                    path=self.path,
                    section_name=self.section.name,
                    result=None,
                    message="This section is empty.",
                )
            )
            return
        start_address = self.section.vma if self.section.vma > 0 else self.section.file_offset
        fallback_address = self.section.file_offset if self.section.file_offset > 0 else None
        try:
            with Radare2Disassembler(self.path) as disassembler:
                result = disassembler.disassemble_section(
                    self.section.name,
                    start_address=start_address,
                    fallback_address=fallback_address,
                    instruction_limit=DEFAULT_INSTRUCTION_LIMIT,
                )
        except Radare2DisassemblerError as exc:
            _safe_emit(
                self.signals.loaded_disassembly,
                LoadedDisassembly(
                    path=self.path,
                    section_name=self.section.name,
                    result=None,
                    message=str(exc),
                )
            )
            return
        _safe_emit(
            self.signals.loaded_disassembly,
            LoadedDisassembly(path=self.path, section_name=self.section.name, result=result)
        )


class FunctionListWorker(QRunnable):
    def __init__(self, path: Path, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.signals = signals

    def run(self) -> None:
        try:
            with Radare2Disassembler(self.path) as disassembler:
                functions = disassembler.list_functions()
        except Radare2DisassemblerError as exc:
            _emit_error(self.signals, "Radare2 Error", str(exc))
            return
        _safe_emit(self.signals.loaded_functions, LoadedFunctions(path=self.path, functions=functions))


class FunctionDisassemblyWorker(QRunnable):
    def __init__(self, path: Path, function: FunctionInfo, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.function = function
        self.signals = signals

    def run(self) -> None:
        try:
            with Radare2Disassembler(self.path) as disassembler:
                result = disassembler.disassemble_function(self.function)
        except Radare2DisassemblerError as exc:
            _safe_emit(
                self.signals.loaded_function_disassembly,
                LoadedFunctionDisassembly(
                    path=self.path,
                    function_address=self.function.address,
                    result=None,
                    message=str(exc),
                ),
            )
            return
        _safe_emit(
            self.signals.loaded_function_disassembly,
            LoadedFunctionDisassembly(
                path=self.path,
                function_address=self.function.address,
                result=result,
            ),
        )


class FunctionDecompilationWorker(QRunnable):
    def __init__(self, path: Path, function: FunctionInfo, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.function = function
        self.signals = signals

    def run(self) -> None:
        try:
            with Radare2Disassembler(self.path) as disassembler:
                result = disassembler.decompile_function(self.function)
        except Radare2DisassemblerError as exc:
            _safe_emit(
                self.signals.loaded_function_decompilation,
                LoadedFunctionDecompilation(
                    path=self.path,
                    function_address=self.function.address,
                    result=None,
                    message=str(exc),
                ),
            )
            return
        _safe_emit(
            self.signals.loaded_function_decompilation,
            LoadedFunctionDecompilation(
                path=self.path,
                function_address=self.function.address,
                result=result,
            ),
        )


class FunctionGraphWorker(QRunnable):
    def __init__(self, path: Path, function: FunctionInfo, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.function = function
        self.signals = signals

    def run(self) -> None:
        try:
            with Radare2Disassembler(self.path) as disassembler:
                result = disassembler.analyze_function_graph(self.function)
        except Radare2DisassemblerError as exc:
            _safe_emit(
                self.signals.loaded_function_graph,
                LoadedFunctionGraph(
                    path=self.path,
                    function_address=self.function.address,
                    result=None,
                    message=str(exc),
                ),
            )
            return
        _safe_emit(
            self.signals.loaded_function_graph,
            LoadedFunctionGraph(
                path=self.path,
                function_address=self.function.address,
                result=result,
            ),
        )


class StringListWorker(QRunnable):
    def __init__(self, path: Path, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.signals = signals

    def run(self) -> None:
        try:
            with Radare2Disassembler(self.path) as disassembler:
                strings = disassembler.list_strings()
        except Radare2DisassemblerError as exc:
            _emit_error(self.signals, "Radare2 Error", str(exc))
            return
        _safe_emit(self.signals.loaded_strings, LoadedStrings(path=self.path, strings=strings))


class XrefLoadWorker(QRunnable):
    def __init__(self, path: Path, string: StringInfo, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.string = string
        self.signals = signals

    def run(self) -> None:
        try:
            with Radare2Disassembler(self.path) as disassembler:
                xrefs = disassembler.list_xrefs_to(self.string.address)
        except Radare2DisassemblerError as exc:
            _emit_error(self.signals, "Radare2 Error", str(exc))
            return
        _safe_emit(
            self.signals.loaded_xrefs,
            LoadedXrefs(path=self.path, string_address=self.string.address, xrefs=xrefs),
        )


class ImportListWorker(QRunnable):
    def __init__(self, path: Path, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.signals = signals

    def run(self) -> None:
        try:
            with Radare2Disassembler(self.path) as disassembler:
                imports = disassembler.list_imports()
        except Radare2DisassemblerError as exc:
            _emit_error(self.signals, "Radare2 Error", str(exc))
            return
        _safe_emit(self.signals.loaded_imports, LoadedImports(path=self.path, imports=imports))


class ImportXrefLoadWorker(QRunnable):
    def __init__(self, path: Path, imp: ImportInfo, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.imp = imp
        self.signals = signals

    def run(self) -> None:
        try:
            with Radare2Disassembler(self.path) as disassembler:
                xrefs = disassembler.list_xrefs_to_import(self.imp.name)
        except Radare2DisassemblerError as exc:
            _emit_error(self.signals, "Radare2 Error", str(exc))
            return
        _safe_emit(
            self.signals.loaded_import_xrefs,
            LoadedImportXrefs(path=self.path, import_name=self.imp.name, xrefs=xrefs),
        )


class SymbolListWorker(QRunnable):
    def __init__(self, path: Path, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.signals = signals

    def run(self) -> None:
        try:
            symbols = GnuToolchain(self.path).list_symbols()
        except GnuToolchainError as exc:
            _emit_error(self.signals, "GNU Toolchain Error", str(exc))
            return
        _safe_emit(self.signals.loaded_symbols, LoadedSymbols(path=self.path, symbols=symbols))


class ElfReportWorker(QRunnable):
    def __init__(self, path: Path, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.signals = signals

    def run(self) -> None:
        try:
            report = GnuToolchain(self.path).read_elf_report()
        except GnuToolchainError as exc:
            _safe_emit(self.signals.loaded_elf_report, LoadedElfReport(path=self.path, report=None, message=str(exc)))
            return
        _safe_emit(self.signals.loaded_elf_report, LoadedElfReport(path=self.path, report=report))


class AddressMetadataWorker(QRunnable):
    def __init__(self, path: Path, raw_name: str, address: int, subject: str, signals: WorkerSignals) -> None:
        super().__init__()
        self.path = path
        self.raw_name = raw_name
        self.address = address
        self.subject = subject
        self.signals = signals

    def run(self) -> None:
        toolchain = GnuToolchain(self.path)
        try:
            demangled_name = toolchain.demangle(self.raw_name)
            source_location = toolchain.lookup_source(self.address) if self.address > 0 else None
        except GnuToolchainError as exc:
            _emit_error(self.signals, "GNU Toolchain Error", str(exc))
            return
        _safe_emit(
            self.signals.loaded_address_metadata,
            LoadedAddressMetadata(
                path=self.path,
                subject=self.subject,
                address=self.address,
                raw_name=self.raw_name,
                demangled_name=demangled_name,
                source_location=source_location,
            ),
        )


class MainWindow(QMainWindow):
    def __init__(self, initial_path: str | Path | None = None) -> None:
        super().__init__()
        self._thread_pool = QThreadPool(self)
        self._command_process = QProcess(self)
        self._signals = WorkerSignals()
        self._signals.loaded_image.connect(self._on_image_loaded)
        self._signals.loaded_section.connect(self._on_section_loaded)
        self._signals.loaded_disassembly.connect(self._on_disassembly_loaded)
        self._signals.loaded_functions.connect(self._on_functions_loaded)
        self._signals.loaded_function_disassembly.connect(self._on_function_disassembly_loaded)
        self._signals.loaded_function_decompilation.connect(self._on_function_decompilation_loaded)
        self._signals.loaded_function_graph.connect(self._on_function_graph_loaded)
        self._signals.loaded_strings.connect(self._on_strings_loaded)
        self._signals.loaded_xrefs.connect(self._on_xrefs_loaded)
        self._signals.loaded_imports.connect(self._on_imports_loaded)
        self._signals.loaded_import_xrefs.connect(self._on_import_xrefs_loaded)
        self._signals.loaded_symbols.connect(self._on_symbols_loaded)
        self._signals.loaded_elf_report.connect(self._on_elf_report_loaded)
        self._signals.loaded_address_metadata.connect(self._on_address_metadata_loaded)
        self._signals.error.connect(self._show_error)
        self._current_path: Path | None = None
        self._current_image: BinaryImage | None = None
        self._functions: tuple[FunctionInfo, ...] = ()
        self._strings: tuple[StringInfo, ...] = ()
        self._imports: tuple[ImportInfo, ...] = ()
        self._symbols: tuple[SymbolInfo, ...] = ()
        self._readelf_report: str = ""
        self._current_section_disassembly: DisassemblyResult | None = None
        self._current_function_disassembly: FunctionDisassemblyResult | None = None
        self._current_function_decompilation: FunctionDecompilationResult | None = None
        self._current_function_graph: FunctionGraphResult | None = None
        self._pending_function_scroll_address: int | None = None
        self._selected_section: str | None = None
        self._selected_function_address: int | None = None
        self._selected_string_address: int | None = None
        self._selected_import_name: str | None = None
        self._selected_symbol_address: int | None = None
        self._selected_symbol_name: str | None = None
        self._selected_section_bytes = b""
        self._cfg_block_items: dict[int, QGraphicsRectItem] = {}
        self._selected_cfg_block_address: int | None = None
        self._loading_image = False
        self._theme = LIGHT_THEME
        self._command_process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._command_process.readyReadStandardOutput.connect(self._append_command_output)
        self._command_process.finished.connect(self._on_command_finished)
        self._command_process.errorOccurred.connect(self._on_command_error)

        self.setWindowTitle(APP_NAME)
        self.resize(1360, 840)
        self._build_actions()
        self._build_menu()
        self._build_toolbar()
        self._build_status_bar()
        self._build_central_widget()
        self._set_loaded_state(False)

        if initial_path is not None:
            self.load_binary(Path(initial_path))

    def _build_actions(self) -> None:
        self.open_action = QAction("Open...", self)
        self.open_action.setShortcut("Ctrl+O")
        self.open_action.triggered.connect(self.open_binary_dialog)

        self.reload_action = QAction("Reload", self)
        self.reload_action.setShortcut("F5")
        self.reload_action.triggered.connect(self.reload_binary)

        self.exit_action = QAction("Exit", self)
        self.exit_action.setShortcut("Ctrl+Q")
        self.exit_action.triggered.connect(self.close)

        self.about_action = QAction("About", self)
        self.about_action.triggered.connect(self.show_about_dialog)

        self.export_action = QAction("Export Section...", self)
        self.export_action.setShortcut("Ctrl+S")
        self.export_action.triggered.connect(self.export_selected_section)

        self.run_codex_action = QAction("Run Codex", self)
        self.run_codex_action.triggered.connect(self.launch_codex_terminal)

        self.run_gdb_action = QAction("Run GDB", self)
        self.run_gdb_action.triggered.connect(self.launch_gdb_terminal)

        self.light_theme_action = QAction("Light", self)
        self.light_theme_action.setCheckable(True)
        self.light_theme_action.triggered.connect(lambda: self.set_theme(LIGHT_THEME))

        self.dark_theme_action = QAction("Dark", self)
        self.dark_theme_action.setCheckable(True)
        self.dark_theme_action.triggered.connect(lambda: self.set_theme(DARK_THEME))

        self.theme_action_group = QActionGroup(self)
        self.theme_action_group.setExclusive(True)
        self.theme_action_group.addAction(self.light_theme_action)
        self.theme_action_group.addAction(self.dark_theme_action)
        self.light_theme_action.setChecked(True)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("File")
        file_menu.addAction(self.open_action)
        file_menu.addAction(self.reload_action)
        file_menu.addAction(self.export_action)
        file_menu.addAction(self.run_codex_action)
        file_menu.addAction(self.run_gdb_action)
        file_menu.addSeparator()
        file_menu.addAction(self.exit_action)

        view_menu = self.menuBar().addMenu("View")
        theme_menu = view_menu.addMenu("Theme")
        theme_menu.addAction(self.light_theme_action)
        theme_menu.addAction(self.dark_theme_action)

        help_menu = self.menuBar().addMenu("Help")
        help_menu.addAction(self.about_action)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main Toolbar", self)
        toolbar.setMovable(False)
        toolbar.addAction(self.open_action)
        toolbar.addAction(self.reload_action)
        toolbar.addAction(self.export_action)
        toolbar.addAction(self.run_codex_action)
        toolbar.addAction(self.run_gdb_action)
        self.addToolBar(toolbar)

    def _build_status_bar(self) -> None:
        status = QStatusBar(self)
        status.showMessage("Ready")
        self.setStatusBar(status)

    def _build_central_widget(self) -> None:
        root = QWidget(self)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(14, 14, 14, 14)
        root_layout.setSpacing(12)

        header_row = QHBoxLayout()
        header_row.setSpacing(12)

        title = QLabel(APP_NAME)
        title_font = title.font()
        title_font.setPointSize(title_font.pointSize() + 6)
        title_font.setBold(True)
        title.setFont(title_font)

        subtitle = QLabel("Inspect sections, metadata, and raw bytes through libbfd")
        subtitle.setProperty("role", "muted")

        title_column = QVBoxLayout()
        title_column.addWidget(title)
        title_column.addWidget(subtitle)
        title_column.setSpacing(2)

        open_button = QPushButton("Open Binary")
        open_button.clicked.connect(self.open_binary_dialog)
        open_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        header_row.addLayout(title_column)
        header_row.addStretch(1)
        header_row.addWidget(open_button)

        summary_group = QGroupBox("Overview")
        summary_layout = QFormLayout(summary_group)
        summary_layout.setContentsMargins(12, 12, 12, 12)
        self.path_value = QLabel("Not loaded")
        self.path_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.arch_value = QLabel("Not loaded")
        self.section_count_value = QLabel("0")
        summary_layout.addRow("Path", self.path_value)
        summary_layout.addRow("Architecture", self.arch_value)
        summary_layout.addRow("Sections", self.section_count_value)

        left_splitter = QSplitter(Qt.Orientation.Vertical, self)
        left_splitter.addWidget(self._build_sections_group())
        left_splitter.addWidget(self._build_browser_group())
        left_splitter.setStretchFactor(0, 3)
        left_splitter.setStretchFactor(1, 2)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.addWidget(left_splitter)
        splitter.addWidget(self._build_details_group())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        body_splitter = QSplitter(Qt.Orientation.Vertical, self)
        body_splitter.addWidget(splitter)
        body_splitter.addWidget(self._build_console_group())
        body_splitter.setStretchFactor(0, 6)
        body_splitter.setStretchFactor(1, 2)

        root_layout.addLayout(header_row)
        root_layout.addWidget(summary_group)
        root_layout.addWidget(body_splitter, stretch=1)
        self.setCentralWidget(root)
        self._log_message("Application ready.")

    def _build_console_group(self) -> QWidget:
        group = QGroupBox("System Console")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        header_row = QHBoxLayout()
        header_label = QLabel("Runtime events, analysis activity, and errors.")
        header_label.setProperty("role", "muted")
        self.command_input = QLineEdit(group)
        self.command_input.setPlaceholderText("Run a Linux command in the project directory")
        self.command_input.returnPressed.connect(self.execute_console_command)
        self.run_command_button = QPushButton("Run Command")
        self.run_command_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.run_command_button.clicked.connect(self.execute_console_command)
        self.stop_command_button = QPushButton("Stop")
        self.stop_command_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.stop_command_button.clicked.connect(self.stop_console_command)
        self.run_codex_button = QPushButton("Run Codex")
        self.run_codex_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.run_codex_button.clicked.connect(self.launch_codex_terminal)
        self.run_gdb_button = QPushButton("Run GDB")
        self.run_gdb_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.run_gdb_button.clicked.connect(self.launch_gdb_terminal)
        clear_button = QPushButton("Clear")
        clear_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        clear_button.clicked.connect(self._clear_console)
        header_row.addWidget(header_label)
        header_row.addStretch(1)
        header_row.addWidget(self.command_input, stretch=1)
        header_row.addWidget(self.run_command_button)
        header_row.addWidget(self.stop_command_button)
        header_row.addWidget(self.run_codex_button)
        header_row.addWidget(self.run_gdb_button)
        header_row.addWidget(clear_button)

        self.console = QPlainTextEdit(group)
        self.console.setReadOnly(True)
        fixed_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.console.setFont(fixed_font)
        self.console.setPlaceholderText("System events will appear here.")

        layout.addLayout(header_row)
        layout.addWidget(self.console)
        self._update_command_controls()
        return group

    def _build_sections_group(self) -> QWidget:
        group = QGroupBox("Sections")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        filter_row = QHBoxLayout()
        filter_label = QLabel("Filter")
        self.filter_input = QLineEdit(group)
        self.filter_input.setPlaceholderText("Type a section name, index, size, or address")
        self.filter_input.textChanged.connect(self._apply_section_filter)
        self.visible_count_label = QLabel("0 shown")
        self.visible_count_label.setProperty("role", "muted")
        filter_row.addWidget(filter_label)
        filter_row.addWidget(self.filter_input, stretch=1)
        filter_row.addWidget(self.visible_count_label)

        self.sections_table = QTableWidget(0, len(SECTION_COLUMNS), group)
        self.sections_table.setHorizontalHeaderLabels(SECTION_COLUMNS)
        self.sections_table.setAlternatingRowColors(True)
        self.sections_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sections_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.sections_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sections_table.setSortingEnabled(True)
        self.sections_table.verticalHeader().setVisible(False)
        header = self.sections_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.sections_table.itemSelectionChanged.connect(self._on_section_selection_changed)

        layout.addLayout(filter_row)
        layout.addWidget(self.sections_table)
        return group

    def _build_functions_group(self) -> QWidget:
        group = QGroupBox("Functions")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        filter_row = QHBoxLayout()
        filter_label = QLabel("Filter")
        self.function_filter_input = QLineEdit(group)
        self.function_filter_input.setPlaceholderText("Type a function name, address, or type")
        self.function_filter_input.textChanged.connect(self._apply_function_filter)
        self.function_count_label = QLabel("0 shown")
        self.function_count_label.setProperty("role", "muted")
        filter_row.addWidget(filter_label)
        filter_row.addWidget(self.function_filter_input, stretch=1)
        filter_row.addWidget(self.function_count_label)

        self.functions_table = QTableWidget(0, len(FUNCTION_COLUMNS), group)
        self.functions_table.setHorizontalHeaderLabels(FUNCTION_COLUMNS)
        self.functions_table.setAlternatingRowColors(True)
        self.functions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.functions_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.functions_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.functions_table.setSortingEnabled(True)
        self.functions_table.verticalHeader().setVisible(False)
        header = self.functions_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.functions_table.itemSelectionChanged.connect(self._on_function_selection_changed)

        layout.addLayout(filter_row)
        layout.addWidget(self.functions_table)
        return group

    def _build_strings_group(self) -> QWidget:
        group = QGroupBox("Strings")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        filter_row = QHBoxLayout()
        filter_label = QLabel("Filter")
        self.string_filter_input = QLineEdit(group)
        self.string_filter_input.setPlaceholderText("Type a string value, address, section, or type")
        self.string_filter_input.textChanged.connect(self._apply_string_filter)
        self.string_count_label = QLabel("0 shown")
        self.string_count_label.setProperty("role", "muted")
        filter_row.addWidget(filter_label)
        filter_row.addWidget(self.string_filter_input, stretch=1)
        filter_row.addWidget(self.string_count_label)

        self.strings_table = QTableWidget(0, len(STRING_COLUMNS), group)
        self.strings_table.setHorizontalHeaderLabels(STRING_COLUMNS)
        self.strings_table.setAlternatingRowColors(True)
        self.strings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.strings_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.strings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.strings_table.setSortingEnabled(True)
        self.strings_table.verticalHeader().setVisible(False)
        header = self.strings_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.strings_table.itemSelectionChanged.connect(self._on_string_selection_changed)

        layout.addLayout(filter_row)
        layout.addWidget(self.strings_table)
        return group

    def _build_imports_group(self) -> QWidget:
        group = QGroupBox("Imports")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        filter_row = QHBoxLayout()
        filter_label = QLabel("Filter")
        self.import_filter_input = QLineEdit(group)
        self.import_filter_input.setPlaceholderText("Type an import name, PLT address, bind, or type")
        self.import_filter_input.textChanged.connect(self._apply_import_filter)
        self.import_count_label = QLabel("0 shown")
        self.import_count_label.setProperty("role", "muted")
        filter_row.addWidget(filter_label)
        filter_row.addWidget(self.import_filter_input, stretch=1)
        filter_row.addWidget(self.import_count_label)

        self.imports_table = QTableWidget(0, len(IMPORT_COLUMNS), group)
        self.imports_table.setHorizontalHeaderLabels(IMPORT_COLUMNS)
        self.imports_table.setAlternatingRowColors(True)
        self.imports_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.imports_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.imports_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.imports_table.setSortingEnabled(True)
        self.imports_table.verticalHeader().setVisible(False)
        header = self.imports_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.imports_table.itemSelectionChanged.connect(self._on_import_selection_changed)

        layout.addLayout(filter_row)
        layout.addWidget(self.imports_table)
        return group

    def _build_symbols_group(self) -> QWidget:
        group = QGroupBox("Symbols")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        filter_row = QHBoxLayout()
        filter_label = QLabel("Filter")
        self.symbol_filter_input = QLineEdit(group)
        self.symbol_filter_input.setPlaceholderText("Type a symbol name, demangled name, address, or type")
        self.symbol_filter_input.textChanged.connect(self._apply_symbol_filter)
        self.symbol_count_label = QLabel("0 shown")
        self.symbol_count_label.setProperty("role", "muted")
        filter_row.addWidget(filter_label)
        filter_row.addWidget(self.symbol_filter_input, stretch=1)
        filter_row.addWidget(self.symbol_count_label)

        self.symbols_table = QTableWidget(0, len(SYMBOL_COLUMNS), group)
        self.symbols_table.setHorizontalHeaderLabels(SYMBOL_COLUMNS)
        self.symbols_table.setAlternatingRowColors(True)
        self.symbols_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.symbols_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.symbols_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.symbols_table.setSortingEnabled(True)
        self.symbols_table.verticalHeader().setVisible(False)
        header = self.symbols_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.symbols_table.itemSelectionChanged.connect(self._on_symbol_selection_changed)
        self.symbols_table.itemDoubleClicked.connect(self._navigate_selected_symbol)

        layout.addLayout(filter_row)
        layout.addWidget(self.symbols_table)
        return group

    def _build_browser_group(self) -> QWidget:
        tabs = QTabWidget(self)
        tabs.addTab(self._build_functions_group(), "Functions")
        tabs.addTab(self._build_strings_group(), "Strings")
        tabs.addTab(self._build_imports_group(), "Imports")
        tabs.addTab(self._build_symbols_group(), "Symbols")
        return tabs

    def _build_details_group(self) -> QWidget:
        group = QGroupBox("Inspector")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)
        self.details_tabs = QTabWidget(group)
        self.details_tabs.addTab(self._build_section_details_tab(group), "Section")
        self.details_tabs.addTab(self._build_function_details_tab(group), "Function")
        self.details_tabs.addTab(self._build_string_details_tab(group), "String")
        self.details_tabs.addTab(self._build_import_details_tab(group), "Import")
        self.details_tabs.addTab(self._build_symbol_details_tab(group), "Symbol")
        self.details_tabs.addTab(self._build_elf_details_tab(group), "ELF")
        layout.addWidget(self.details_tabs, stretch=1)
        return group

    def _build_section_details_tab(self, parent: QWidget) -> QWidget:
        tab = QWidget(parent)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        detail_form = QFormLayout()
        self.detail_name = QLabel("No section selected")
        self.detail_index = QLabel("-")
        self.detail_size = QLabel("-")
        self.detail_vma = QLabel("-")
        self.detail_lma = QLabel("-")
        self.detail_flags = QLabel("-")
        self.detail_alignment = QLabel("-")
        self.detail_offset = QLabel("-")
        for label in (
            self.detail_name,
            self.detail_index,
            self.detail_size,
            self.detail_vma,
            self.detail_lma,
            self.detail_flags,
            self.detail_alignment,
            self.detail_offset,
        ):
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        detail_form.addRow("Name", self.detail_name)
        detail_form.addRow("Index", self.detail_index)
        detail_form.addRow("Size", self.detail_size)
        detail_form.addRow("VMA", self.detail_vma)
        detail_form.addRow("LMA", self.detail_lma)
        detail_form.addRow("Flags", self.detail_flags)
        detail_form.addRow("Alignment", self.detail_alignment)
        detail_form.addRow("File Offset", self.detail_offset)

        preview_label = QLabel("Hex Preview")
        preview_font = preview_label.font()
        preview_font.setBold(True)
        preview_label.setFont(preview_font)

        action_row = QHBoxLayout()
        self.export_button = QPushButton("Export Section")
        self.export_button.clicked.connect(self.export_selected_section)
        self.export_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.preview_hint = QLabel("Save the current section bytes to disk.")
        self.preview_hint.setProperty("role", "muted")
        action_row.addWidget(self.export_button)
        action_row.addStretch(1)
        action_row.addWidget(self.preview_hint)

        self.preview = QPlainTextEdit(parent)
        self.preview.setReadOnly(True)
        fixed_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.preview.setFont(fixed_font)
        self.preview.setPlaceholderText("Select a section to preview its bytes.")

        disassembly_label = QLabel("Radare2 Disassembly")
        disassembly_label.setFont(preview_font)
        self.disassembly_summary = QLabel(
            f"Previewing up to {DEFAULT_INSTRUCTION_LIMIT} instructions with radare2."
        )
        self.disassembly_summary.setProperty("role", "muted")
        self.disassembly_preview = QTextBrowser(parent)
        self.disassembly_preview.setReadOnly(True)
        self.disassembly_preview.setFont(fixed_font)
        self.disassembly_preview.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.disassembly_preview.setOpenExternalLinks(False)
        self.disassembly_preview.setOpenLinks(False)
        self.disassembly_preview.anchorClicked.connect(self._navigate_section_disassembly_target)
        self.disassembly_preview.setPlaceholderText("Select a section to preview its disassembly.")

        hex_tab = QWidget(parent)
        hex_layout = QVBoxLayout(hex_tab)
        hex_layout.setContentsMargins(0, 0, 0, 0)
        hex_layout.setSpacing(8)
        hex_layout.addWidget(preview_label)
        hex_layout.addLayout(action_row)
        hex_layout.addWidget(self.preview)

        disassembly_tab = QWidget(parent)
        disassembly_layout = QVBoxLayout(disassembly_tab)
        disassembly_layout.setContentsMargins(0, 0, 0, 0)
        disassembly_layout.setSpacing(8)
        disassembly_layout.addWidget(disassembly_label)
        disassembly_layout.addWidget(self.disassembly_summary)
        disassembly_layout.addWidget(self.disassembly_preview)

        self.preview_tabs = QTabWidget(parent)
        self.preview_tabs.addTab(hex_tab, "Hex")
        self.preview_tabs.addTab(disassembly_tab, "Disassembly")

        layout.addLayout(detail_form)
        layout.addWidget(self.preview_tabs, stretch=1)
        return tab

    def _build_function_details_tab(self, parent: QWidget) -> QWidget:
        tab = QWidget(parent)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        detail_form = QFormLayout()
        self.function_name_value = QLabel("No function selected")
        self.function_address_value = QLabel("-")
        self.function_size_value = QLabel("-")
        self.function_instr_count_value = QLabel("-")
        self.function_type_value = QLabel("-")
        self.function_signature_value = QLabel("-")
        self.function_demangled_value = QLabel("-")
        self.function_source_value = QLabel("-")
        self.function_signature_value.setWordWrap(True)
        self.function_demangled_value.setWordWrap(True)
        self.function_source_value.setWordWrap(True)
        for label in (
            self.function_name_value,
            self.function_address_value,
            self.function_size_value,
            self.function_instr_count_value,
            self.function_type_value,
            self.function_signature_value,
            self.function_demangled_value,
            self.function_source_value,
        ):
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        detail_form.addRow("Name", self.function_name_value)
        detail_form.addRow("Address", self.function_address_value)
        detail_form.addRow("Size", self.function_size_value)
        detail_form.addRow("Instructions", self.function_instr_count_value)
        detail_form.addRow("Type", self.function_type_value)
        detail_form.addRow("Signature", self.function_signature_value)
        detail_form.addRow("Demangled", self.function_demangled_value)
        detail_form.addRow("Source", self.function_source_value)

        self.function_disassembly_summary = QLabel(
            "Select a radare2 function to preview its full disassembly."
        )
        self.function_disassembly_summary.setProperty("role", "muted")
        self.function_disassembly_preview = QTextBrowser(parent)
        self.function_disassembly_preview.setReadOnly(True)
        fixed_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.function_disassembly_preview.setFont(fixed_font)
        self.function_disassembly_preview.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.function_disassembly_preview.setOpenExternalLinks(False)
        self.function_disassembly_preview.setOpenLinks(False)
        self.function_disassembly_preview.anchorClicked.connect(self._navigate_function_disassembly_target)
        self.function_disassembly_preview.setPlaceholderText(
            "Select a function from the radare2 browser to preview its disassembly."
        )

        self.function_decompilation_summary = QLabel(
            "Select a radare2 function to preview its HLL-style decompilation."
        )
        self.function_decompilation_summary.setProperty("role", "muted")
        self.function_decompilation_preview = QPlainTextEdit(parent)
        self.function_decompilation_preview.setReadOnly(True)
        self.function_decompilation_preview.setFont(fixed_font)
        self.function_decompilation_preview.setPlaceholderText(
            "Select a function from the radare2 browser to preview its decompilation."
        )

        disassembly_tab = QWidget(parent)
        disassembly_layout = QVBoxLayout(disassembly_tab)
        disassembly_layout.setContentsMargins(0, 0, 0, 0)
        disassembly_layout.setSpacing(8)
        disassembly_layout.addWidget(self.function_disassembly_summary)
        disassembly_layout.addWidget(self.function_disassembly_preview, stretch=1)

        decompilation_tab = QWidget(parent)
        decompilation_layout = QVBoxLayout(decompilation_tab)
        decompilation_layout.setContentsMargins(0, 0, 0, 0)
        decompilation_layout.setSpacing(8)
        decompilation_layout.addWidget(self.function_decompilation_summary)
        decompilation_layout.addWidget(self.function_decompilation_preview, stretch=1)

        self.function_cfg_summary = QLabel("Select a radare2 function to preview its control-flow graph.")
        self.function_cfg_summary.setProperty("role", "muted")
        self.function_cfg_scene = QGraphicsScene(parent)
        self.function_cfg_view = FunctionGraphView(parent)
        self.function_cfg_view.setScene(self.function_cfg_scene)
        self.function_cfg_view.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.function_cfg_view.blockActivated.connect(self._on_function_cfg_block_activated)

        cfg_tab = QWidget(parent)
        cfg_layout = QVBoxLayout(cfg_tab)
        cfg_layout.setContentsMargins(0, 0, 0, 0)
        cfg_layout.setSpacing(8)
        cfg_layout.addWidget(self.function_cfg_summary)
        cfg_layout.addWidget(self.function_cfg_view, stretch=1)

        self.function_preview_tabs = QTabWidget(parent)
        self.function_preview_tabs.addTab(disassembly_tab, "Disassembly")
        self.function_preview_tabs.addTab(decompilation_tab, "HLL")
        self.function_preview_tabs.addTab(cfg_tab, "CFG")

        layout.addLayout(detail_form)
        layout.addWidget(self.function_preview_tabs, stretch=1)
        return tab

    def _build_string_details_tab(self, parent: QWidget) -> QWidget:
        tab = QWidget(parent)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        detail_form = QFormLayout()
        self.string_value_label = QLabel("No string selected")
        self.string_value_label.setWordWrap(True)
        self.string_address_label = QLabel("-")
        self.string_length_label = QLabel("-")
        self.string_section_label = QLabel("-")
        self.string_type_label = QLabel("-")
        for label in (
            self.string_value_label,
            self.string_address_label,
            self.string_length_label,
            self.string_section_label,
            self.string_type_label,
        ):
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        detail_form.addRow("Value", self.string_value_label)
        detail_form.addRow("Address", self.string_address_label)
        detail_form.addRow("Length", self.string_length_label)
        detail_form.addRow("Section", self.string_section_label)
        detail_form.addRow("Type", self.string_type_label)

        xref_label = QLabel("Xrefs")
        xref_font = xref_label.font()
        xref_font.setBold(True)
        xref_label.setFont(xref_font)

        self.xref_summary_label = QLabel("Select a string to load xrefs.")
        self.xref_summary_label.setProperty("role", "muted")
        self.xrefs_table = QTableWidget(0, len(XREF_COLUMNS), parent)
        self.xrefs_table.setHorizontalHeaderLabels(XREF_COLUMNS)
        self.xrefs_table.setAlternatingRowColors(True)
        self.xrefs_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.xrefs_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.xrefs_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.xrefs_table.setSortingEnabled(True)
        self.xrefs_table.verticalHeader().setVisible(False)
        header = self.xrefs_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.xrefs_table.itemDoubleClicked.connect(self._navigate_selected_xref)

        layout.addLayout(detail_form)
        layout.addWidget(xref_label)
        layout.addWidget(self.xref_summary_label)
        layout.addWidget(self.xrefs_table, stretch=1)
        return tab

    def _build_import_details_tab(self, parent: QWidget) -> QWidget:
        tab = QWidget(parent)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        detail_form = QFormLayout()
        self.import_name_label = QLabel("No import selected")
        self.import_plt_label = QLabel("-")
        self.import_bind_label = QLabel("-")
        self.import_type_label = QLabel("-")
        for label in (
            self.import_name_label,
            self.import_plt_label,
            self.import_bind_label,
            self.import_type_label,
        ):
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        detail_form.addRow("Name", self.import_name_label)
        detail_form.addRow("PLT", self.import_plt_label)
        detail_form.addRow("Bind", self.import_bind_label)
        detail_form.addRow("Type", self.import_type_label)

        xref_label = QLabel("Import Callers")
        xref_font = xref_label.font()
        xref_font.setBold(True)
        xref_label.setFont(xref_font)

        self.import_xref_summary_label = QLabel("Select an import to load callers.")
        self.import_xref_summary_label.setProperty("role", "muted")
        self.import_xrefs_table = QTableWidget(0, len(XREF_COLUMNS), parent)
        self.import_xrefs_table.setHorizontalHeaderLabels(XREF_COLUMNS)
        self.import_xrefs_table.setAlternatingRowColors(True)
        self.import_xrefs_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.import_xrefs_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.import_xrefs_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.import_xrefs_table.setSortingEnabled(True)
        self.import_xrefs_table.verticalHeader().setVisible(False)
        header = self.import_xrefs_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.import_xrefs_table.itemDoubleClicked.connect(self._navigate_selected_import_xref)

        layout.addLayout(detail_form)
        layout.addWidget(xref_label)
        layout.addWidget(self.import_xref_summary_label)
        layout.addWidget(self.import_xrefs_table, stretch=1)
        return tab

    def _build_symbol_details_tab(self, parent: QWidget) -> QWidget:
        tab = QWidget(parent)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        detail_form = QFormLayout()
        self.symbol_name_label = QLabel("No symbol selected")
        self.symbol_demangled_label = QLabel("-")
        self.symbol_address_label = QLabel("-")
        self.symbol_type_label = QLabel("-")
        self.symbol_origin_label = QLabel("-")
        self.symbol_source_label = QLabel("-")
        self.symbol_demangled_label.setWordWrap(True)
        self.symbol_source_label.setWordWrap(True)
        for label in (
            self.symbol_name_label,
            self.symbol_demangled_label,
            self.symbol_address_label,
            self.symbol_type_label,
            self.symbol_origin_label,
            self.symbol_source_label,
        ):
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        detail_form.addRow("Name", self.symbol_name_label)
        detail_form.addRow("Demangled", self.symbol_demangled_label)
        detail_form.addRow("Address", self.symbol_address_label)
        detail_form.addRow("Type", self.symbol_type_label)
        detail_form.addRow("Origin", self.symbol_origin_label)
        detail_form.addRow("Source", self.symbol_source_label)

        layout.addLayout(detail_form)
        return tab

    def _build_elf_details_tab(self, parent: QWidget) -> QWidget:
        tab = QWidget(parent)
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.elf_summary_label = QLabel("Loading readelf report...")
        self.elf_summary_label.setProperty("role", "muted")
        self.elf_report_view = QPlainTextEdit(parent)
        self.elf_report_view.setReadOnly(True)
        fixed_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.elf_report_view.setFont(fixed_font)
        self.elf_report_view.setPlaceholderText("GNU readelf output will appear here.")

        layout.addWidget(self.elf_summary_label)
        layout.addWidget(self.elf_report_view, stretch=1)
        return tab

    def open_binary_dialog(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Open Binary",
            str(self._current_path.parent if self._current_path else Path.home()),
        )
        if filename:
            self.load_binary(Path(filename))

    def reload_binary(self) -> None:
        if self._current_path is None:
            return
        self.load_binary(self._current_path)

    def load_binary(self, path: Path) -> None:
        self._loading_image = True
        self._current_path = path.resolve()
        self._current_image = None
        self._functions = ()
        self._strings = ()
        self._imports = ()
        self._symbols = ()
        self._readelf_report = ""
        self._current_section_disassembly = None
        self._current_function_disassembly = None
        self._current_function_decompilation = None
        self._current_function_graph = None
        self._pending_function_scroll_address = None
        self._selected_section = None
        self._selected_function_address = None
        self._selected_string_address = None
        self._selected_import_name = None
        self._selected_symbol_address = None
        self._selected_symbol_name = None
        self._selected_section_bytes = b""
        self._selected_cfg_block_address = None
        self._cfg_block_items.clear()
        self._set_loaded_state(False)
        self.path_value.setText(str(self._current_path))
        self.preview.setPlainText("")
        self.section_count_value.setText("0")
        self.arch_value.setText("Loading...")
        self.function_count_label.setText("0 shown")
        self.functions_table.setRowCount(0)
        self.string_count_label.setText("0 shown")
        self.strings_table.setRowCount(0)
        self.import_count_label.setText("0 shown")
        self.imports_table.setRowCount(0)
        self.symbol_count_label.setText("0 shown")
        self.symbols_table.setRowCount(0)
        self.elf_summary_label.setText("Loading readelf report...")
        self.elf_report_view.setPlainText("")
        self.disassembly_summary.setText(
            f"Previewing up to {DEFAULT_INSTRUCTION_LIMIT} instructions with radare2."
        )
        self.disassembly_preview.setPlainText("")
        self._clear_function_details()
        self._clear_string_details()
        self._clear_import_details()
        self._clear_symbol_details()
        self._set_status(f"Loading {self._current_path}...")
        self._thread_pool.start(ImageLoadWorker(self._current_path, self._signals))

    def _on_image_loaded(self, loaded: LoadedImage) -> None:
        if self._current_path != loaded.path:
            return
        self._loading_image = False
        self._current_image = loaded.image
        self._populate_sections_table(loaded.image.sections)
        self.path_value.setText(str(loaded.image.path))
        self.arch_value.setText(f"{loaded.image.arch_size}-bit")
        self.section_count_value.setText(_format_int(len(loaded.image.sections)))
        self._set_loaded_state(True)
        self._clear_details()
        self._apply_section_filter(self.filter_input.text())
        self._thread_pool.start(FunctionListWorker(self._current_path, self._signals))
        self._thread_pool.start(StringListWorker(self._current_path, self._signals))
        self._thread_pool.start(ImportListWorker(self._current_path, self._signals))
        self._thread_pool.start(SymbolListWorker(self._current_path, self._signals))
        self._thread_pool.start(ElfReportWorker(self._current_path, self._signals))
        self._set_status(f"Loaded {loaded.image.path}", 4000)
        self.setWindowTitle(f"{APP_NAME} - {loaded.image.path.name}")
        self._select_first_visible_row(self.sections_table)

    def _on_section_loaded(self, section_name: str, section_bytes: bytes) -> None:
        if self._selected_section != section_name:
            return
        self._selected_section_bytes = section_bytes
        self.preview.setPlainText(_format_preview(section_bytes))
        self.export_action.setEnabled(True)
        self.export_button.setEnabled(True)
        self._set_status(f"Loaded {section_name} preview ({len(section_bytes):,} bytes)", 4000)

    def _on_disassembly_loaded(self, loaded: LoadedDisassembly) -> None:
        if self._current_path != loaded.path or self._selected_section != loaded.section_name:
            return
        if loaded.result is None:
            self._current_section_disassembly = None
            self.disassembly_summary.setText(loaded.message)
            self.disassembly_preview.setPlainText("")
            self._set_status(loaded.message, 4000)
            return
        self._current_section_disassembly = loaded.result
        self.disassembly_summary.setText(
            f"{loaded.result.architecture} {loaded.result.bits}-bit disassembly from {_format_hex(loaded.result.start_address)}. Click jump targets to navigate."
        )
        self.disassembly_preview.setHtml(format_disassembly_html(loaded.result))
        self._set_status(f"Loaded disassembly for section {loaded.section_name}", 4000)

    def _on_functions_loaded(self, loaded: LoadedFunctions) -> None:
        if self._current_path != loaded.path:
            return
        self._functions = loaded.functions
        self._populate_functions_table(loaded.functions)
        self._apply_function_filter(self.function_filter_input.text())
        self._set_status(f"Loaded {len(loaded.functions):,} radare2 functions", 4000)

    def _on_function_disassembly_loaded(self, loaded: LoadedFunctionDisassembly) -> None:
        if self._current_path != loaded.path or self._selected_function_address != loaded.function_address:
            return
        if loaded.result is None:
            self._current_function_disassembly = None
            self._pending_function_scroll_address = None
            self.function_disassembly_summary.setText(loaded.message)
            self.function_disassembly_preview.setPlainText("")
            self._set_status(loaded.message, 4000)
            return
        function = loaded.result.function
        self._current_function_disassembly = loaded.result
        self.function_disassembly_summary.setText(
            f"{loaded.result.architecture} {loaded.result.bits}-bit function at {_format_hex(function.address)}. Click jump targets to navigate."
        )
        self.function_disassembly_preview.setHtml(format_function_disassembly_html(loaded.result))
        if self._pending_function_scroll_address is not None:
            self._highlight_cfg_block(self._pending_function_scroll_address)
            self._scroll_function_disassembly_to_address(self._pending_function_scroll_address)
            self._pending_function_scroll_address = None
        self._set_status(f"Loaded function disassembly for {function.name}", 4000)

    def _on_function_decompilation_loaded(self, loaded: LoadedFunctionDecompilation) -> None:
        if self._current_path != loaded.path or self._selected_function_address != loaded.function_address:
            return
        if loaded.result is None:
            self._current_function_decompilation = None
            self.function_decompilation_summary.setText(loaded.message)
            self.function_decompilation_preview.setPlainText("")
            self._set_status(loaded.message, 4000)
            return
        function = loaded.result.function
        self._current_function_decompilation = loaded.result
        self.function_decompilation_summary.setText(
            f"{loaded.result.backend} HLL-style decompilation for {function.name} at {_format_hex(function.address)}."
        )
        self.function_decompilation_preview.setPlainText(loaded.result.text)
        self._set_status(f"Loaded HLL view for {function.name}", 4000)

    def _on_function_graph_loaded(self, loaded: LoadedFunctionGraph) -> None:
        if self._current_path != loaded.path or self._selected_function_address != loaded.function_address:
            return
        if loaded.result is None:
            self._current_function_graph = None
            self.function_cfg_summary.setText(loaded.message)
            self.function_cfg_scene.clear()
            self._cfg_block_items.clear()
            self._selected_cfg_block_address = None
            self._set_status(loaded.message, 4000)
            return
        self._current_function_graph = loaded.result
        self._render_function_graph(loaded.result)
        self.function_cfg_summary.setText(
            f"{len(loaded.result.blocks):,} blocks, {len(loaded.result.edges):,} edges. Click a block to jump into disassembly."
        )
        if self._pending_function_scroll_address is not None:
            self._highlight_cfg_block(self._pending_function_scroll_address)
        else:
            self._highlight_cfg_block(loaded.result.function.address)
        self._set_status(f"Loaded CFG for {loaded.result.function.name}", 4000)

    def _on_strings_loaded(self, loaded: LoadedStrings) -> None:
        if self._current_path != loaded.path:
            return
        self._strings = loaded.strings
        self._populate_strings_table(loaded.strings)
        self._apply_string_filter(self.string_filter_input.text())
        self._set_status(f"Loaded {len(loaded.strings):,} radare2 strings", 4000)

    def _on_xrefs_loaded(self, loaded: LoadedXrefs) -> None:
        if self._current_path != loaded.path or self._selected_string_address != loaded.string_address:
            return
        self._populate_xrefs_table(loaded.xrefs)
        self.xref_summary_label.setText(f"{len(loaded.xrefs):,} xrefs loaded")
        self._set_status(f"Loaded {len(loaded.xrefs):,} xrefs for string {_format_hex(loaded.string_address)}", 4000)

    def _on_imports_loaded(self, loaded: LoadedImports) -> None:
        if self._current_path != loaded.path:
            return
        self._imports = loaded.imports
        self._populate_imports_table(loaded.imports)
        self._apply_import_filter(self.import_filter_input.text())
        self._set_status(f"Loaded {len(loaded.imports):,} radare2 imports", 4000)

    def _on_import_xrefs_loaded(self, loaded: LoadedImportXrefs) -> None:
        if self._current_path != loaded.path or self._selected_import_name != loaded.import_name:
            return
        self._populate_import_xrefs_table(loaded.xrefs)
        self.import_xref_summary_label.setText(f"{len(loaded.xrefs):,} callers loaded")
        self._set_status(f"Loaded {len(loaded.xrefs):,} callers for import {loaded.import_name}", 4000)

    def _on_symbols_loaded(self, loaded: LoadedSymbols) -> None:
        if self._current_path != loaded.path:
            return
        self._symbols = loaded.symbols
        self._populate_symbols_table(loaded.symbols)
        self._apply_symbol_filter(self.symbol_filter_input.text())
        self._set_status(f"Loaded {len(loaded.symbols):,} GNU symbols", 4000)

    def _on_elf_report_loaded(self, loaded: LoadedElfReport) -> None:
        if self._current_path != loaded.path:
            return
        if loaded.report is None:
            self._readelf_report = ""
            self.elf_summary_label.setText(loaded.message)
            self.elf_report_view.setPlainText("")
            self._set_status(loaded.message, 4000)
            return
        self._readelf_report = loaded.report.text
        self.elf_summary_label.setText("readelf header, program header, and section report")
        self.elf_report_view.setPlainText(loaded.report.text)
        self._set_status("Loaded GNU readelf report", 4000)

    def _on_address_metadata_loaded(self, loaded: LoadedAddressMetadata) -> None:
        if self._current_path != loaded.path:
            return
        if loaded.subject == "function" and self._selected_function_address == loaded.address:
            self.function_demangled_value.setText(loaded.demangled_name or loaded.raw_name)
            self.function_source_value.setText(_source_text(loaded.source_location))
            return
        if (
            loaded.subject == "symbol"
            and self._selected_symbol_address == loaded.address
            and self._selected_symbol_name == loaded.raw_name
        ):
            self.symbol_demangled_label.setText(loaded.demangled_name or loaded.raw_name)
            self.symbol_source_label.setText(_source_text(loaded.source_location))

    def _show_error(self, error: ErrorInfo | str) -> None:
        if isinstance(error, ErrorInfo):
            title = error.title
            message = error.message
        else:
            title = "IronView Error"
            message = error
        self._loading_image = False
        self._set_status(message, 6000)
        QMessageBox.critical(self, title, message)
        if self._current_image is None:
            self._set_loaded_state(False)
            self._clear_details()

    def _set_loaded_state(self, loaded: bool) -> None:
        self.reload_action.setEnabled(self._current_path is not None)
        self.sections_table.setEnabled(loaded)
        self.functions_table.setEnabled(loaded)
        self.strings_table.setEnabled(loaded)
        self.imports_table.setEnabled(loaded)
        self.symbols_table.setEnabled(loaded)
        has_selection = loaded and bool(self._selected_section_bytes)
        self.export_action.setEnabled(has_selection)
        self.export_button.setEnabled(has_selection)
        self.filter_input.setEnabled(loaded)
        self.function_filter_input.setEnabled(loaded)
        self.string_filter_input.setEnabled(loaded)
        self.import_filter_input.setEnabled(loaded)
        self.symbol_filter_input.setEnabled(loaded)
        self.run_codex_action.setEnabled(_terminal_command() is not None and shutil.which("codex") is not None)
        self.run_gdb_action.setEnabled(
            loaded and self._current_path is not None and _terminal_command() is not None and GnuToolchain.has_gdb()
        )

    def _populate_sections_table(self, sections: tuple[SectionInfo, ...]) -> None:
        self.sections_table.setSortingEnabled(False)
        self.sections_table.setRowCount(len(sections))
        for row, section in enumerate(sections):
            values = (
                section.name,
                _format_int(section.index),
                _format_int(section.size),
                _format_hex(section.vma),
                _format_hex(section.lma),
                _format_hex(section.flags),
                _format_int(section.alignment_power),
                _format_hex(section.file_offset),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, section)
                self.sections_table.setItem(row, column, item)
        self.sections_table.setSortingEnabled(True)
        self.sections_table.sortItems(1, Qt.SortOrder.AscendingOrder)

    def _populate_functions_table(self, functions: tuple[FunctionInfo, ...]) -> None:
        self.functions_table.setSortingEnabled(False)
        self.functions_table.setRowCount(len(functions))
        for row, function in enumerate(functions):
            values = (
                function.name,
                _format_hex(function.address),
                _format_int(function.size),
                _format_int(function.instruction_count),
                function.kind,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, function)
                self.functions_table.setItem(row, column, item)
        self.functions_table.setSortingEnabled(True)
        self.functions_table.sortItems(1, Qt.SortOrder.AscendingOrder)

    def _populate_strings_table(self, strings: tuple[StringInfo, ...]) -> None:
        self.strings_table.setSortingEnabled(False)
        self.strings_table.setRowCount(len(strings))
        for row, string in enumerate(strings):
            values = (
                string.value,
                _format_hex(string.address),
                _format_int(string.length),
                string.section,
                string.kind,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, string)
                self.strings_table.setItem(row, column, item)
        self.strings_table.setSortingEnabled(True)
        self.strings_table.sortItems(1, Qt.SortOrder.AscendingOrder)

    def _populate_xrefs_table(self, xrefs: tuple[XrefInfo, ...]) -> None:
        self.xrefs_table.setSortingEnabled(False)
        self.xrefs_table.setRowCount(len(xrefs))
        for row, xref in enumerate(xrefs):
            values = (
                _format_hex(xref.from_address),
                xref.function_name or "-",
                xref.xref_type,
                xref.opcode,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, xref)
                self.xrefs_table.setItem(row, column, item)
        self.xrefs_table.setSortingEnabled(True)
        self.xrefs_table.sortItems(0, Qt.SortOrder.AscendingOrder)

    def _populate_imports_table(self, imports: tuple[ImportInfo, ...]) -> None:
        self.imports_table.setSortingEnabled(False)
        self.imports_table.setRowCount(len(imports))
        for row, imp in enumerate(imports):
            values = (
                imp.name,
                _format_hex(imp.plt_address),
                imp.bind,
                imp.kind,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, imp)
                self.imports_table.setItem(row, column, item)
        self.imports_table.setSortingEnabled(True)
        self.imports_table.sortItems(0, Qt.SortOrder.AscendingOrder)

    def _populate_import_xrefs_table(self, xrefs: tuple[XrefInfo, ...]) -> None:
        self.import_xrefs_table.setSortingEnabled(False)
        self.import_xrefs_table.setRowCount(len(xrefs))
        for row, xref in enumerate(xrefs):
            values = (
                _format_hex(xref.from_address),
                xref.function_name or "-",
                xref.xref_type,
                xref.opcode,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, xref)
                self.import_xrefs_table.setItem(row, column, item)
        self.import_xrefs_table.setSortingEnabled(True)
        self.import_xrefs_table.sortItems(0, Qt.SortOrder.AscendingOrder)

    def _populate_symbols_table(self, symbols: tuple[SymbolInfo, ...]) -> None:
        self.symbols_table.setSortingEnabled(False)
        self.symbols_table.setRowCount(len(symbols))
        for row, symbol in enumerate(symbols):
            values = (
                symbol.name,
                symbol.demangled_name,
                _format_hex(symbol.address),
                symbol.kind,
                "dynamic" if symbol.is_dynamic else "regular",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, symbol)
                self.symbols_table.setItem(row, column, item)
        self.symbols_table.setSortingEnabled(True)
        self.symbols_table.sortItems(2, Qt.SortOrder.AscendingOrder)

    def _apply_section_filter(self, query: str) -> None:
        visible_rows = 0
        for row in range(self.sections_table.rowCount()):
            item = self.sections_table.item(row, 0)
            section = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            hidden = not isinstance(section, SectionInfo) or not _matches_section_filter(section, query)
            self.sections_table.setRowHidden(row, hidden)
            if not hidden:
                visible_rows += 1
        total_rows = self.sections_table.rowCount()
        self.visible_count_label.setText(f"{visible_rows} shown")
        if total_rows:
            self.section_count_value.setText(f"{visible_rows}/{total_rows}")
        else:
            self.section_count_value.setText("0")
        if visible_rows == 0:
            self.sections_table.clearSelection()
            self._selected_section = None
            self._selected_section_bytes = b""
            self._clear_section_details()
            self._set_status("No sections match the current filter.", 4000)
            return
        if not self.sections_table.selectedItems():
            self._select_first_visible_row(self.sections_table)

    def _apply_function_filter(self, query: str) -> None:
        visible_rows = 0
        for row in range(self.functions_table.rowCount()):
            item = self.functions_table.item(row, 0)
            function = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            hidden = not isinstance(function, FunctionInfo) or not _matches_function_filter(function, query)
            self.functions_table.setRowHidden(row, hidden)
            if not hidden:
                visible_rows += 1
        self.function_count_label.setText(f"{visible_rows} shown")
        if visible_rows == 0:
            self.functions_table.clearSelection()
            self._selected_function_address = None
            self._clear_function_details()
            return

    def _apply_string_filter(self, query: str) -> None:
        visible_rows = 0
        for row in range(self.strings_table.rowCount()):
            item = self.strings_table.item(row, 0)
            string = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            hidden = not isinstance(string, StringInfo) or not _matches_string_filter(string, query)
            self.strings_table.setRowHidden(row, hidden)
            if not hidden:
                visible_rows += 1
        self.string_count_label.setText(f"{visible_rows} shown")
        if visible_rows == 0:
            self.strings_table.clearSelection()
            self._selected_string_address = None
            self._clear_string_details()
            return

    def _apply_import_filter(self, query: str) -> None:
        visible_rows = 0
        for row in range(self.imports_table.rowCount()):
            item = self.imports_table.item(row, 0)
            imp = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            hidden = not isinstance(imp, ImportInfo) or not _matches_import_filter(imp, query)
            self.imports_table.setRowHidden(row, hidden)
            if not hidden:
                visible_rows += 1
        self.import_count_label.setText(f"{visible_rows} shown")
        if visible_rows == 0:
            self.imports_table.clearSelection()
            self._selected_import_name = None
            self._clear_import_details()
            return

    def _apply_symbol_filter(self, query: str) -> None:
        visible_rows = 0
        for row in range(self.symbols_table.rowCount()):
            item = self.symbols_table.item(row, 0)
            symbol = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            hidden = not isinstance(symbol, SymbolInfo) or not _matches_symbol_filter(symbol, query)
            self.symbols_table.setRowHidden(row, hidden)
            if not hidden:
                visible_rows += 1
        self.symbol_count_label.setText(f"{visible_rows} shown")
        if visible_rows == 0:
            self.symbols_table.clearSelection()
            self._selected_symbol_address = None
            self._selected_symbol_name = None
            self._clear_symbol_details()
            return

    def _select_first_visible_row(self, table: QTableWidget) -> None:
        for row in range(table.rowCount()):
            if not table.isRowHidden(row):
                table.selectRow(row)
                return

    def _on_section_selection_changed(self) -> None:
        selected_items = self.sections_table.selectedItems()
        if not selected_items or self._current_path is None or self._loading_image:
            return
        section = selected_items[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(section, SectionInfo):
            return
        self._selected_section = section.name
        self._selected_section_bytes = b""
        self.details_tabs.setCurrentIndex(0)
        self._update_details(section)
        self.preview.setPlainText("Loading section bytes...")
        self.disassembly_summary.setText("Loading radare2 disassembly...")
        self.disassembly_preview.setPlainText("Loading disassembly...")
        self.export_action.setEnabled(False)
        self.export_button.setEnabled(False)
        self._set_status(f"Reading {section.name}...")
        self._thread_pool.start(SectionLoadWorker(self._current_path, section.name, self._signals))
        self._thread_pool.start(DisassemblyLoadWorker(self._current_path, section, self._signals))

    def _on_function_selection_changed(self) -> None:
        selected_items = self.functions_table.selectedItems()
        if not selected_items or self._current_path is None or self._loading_image:
            return
        function = selected_items[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(function, FunctionInfo):
            return
        self._selected_function_address = function.address
        self._current_function_decompilation = None
        self._current_function_graph = None
        self.details_tabs.setCurrentIndex(1)
        self._update_function_details(function)
        self.function_preview_tabs.setCurrentIndex(0)
        self.function_disassembly_summary.setText("Loading function disassembly from radare2...")
        self.function_disassembly_preview.setPlainText("Loading function disassembly...")
        self.function_decompilation_summary.setText("Loading HLL-style decompilation from radare2...")
        self.function_decompilation_preview.setPlainText("Loading decompilation...")
        self.function_cfg_summary.setText("Loading control-flow graph from radare2...")
        self.function_cfg_scene.clear()
        self._cfg_block_items.clear()
        self._selected_cfg_block_address = None
        self.function_demangled_value.setText("Loading demangled name...")
        self.function_source_value.setText("Loading source lookup...")
        self._set_status(f"Reading {function.name}...")
        self._thread_pool.start(FunctionDisassemblyWorker(self._current_path, function, self._signals))
        self._thread_pool.start(FunctionDecompilationWorker(self._current_path, function, self._signals))
        self._thread_pool.start(FunctionGraphWorker(self._current_path, function, self._signals))
        self._thread_pool.start(
            AddressMetadataWorker(
                self._current_path,
                function.name,
                function.address,
                "function",
                self._signals,
            )
        )

    def _on_string_selection_changed(self) -> None:
        selected_items = self.strings_table.selectedItems()
        if not selected_items or self._current_path is None or self._loading_image:
            return
        string = selected_items[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(string, StringInfo):
            return
        self._selected_string_address = string.address
        self.details_tabs.setCurrentIndex(2)
        self._update_string_details(string)
        self.xref_summary_label.setText("Loading xrefs from radare2...")
        self.xrefs_table.setRowCount(0)
        self._set_status(f"Reading xrefs for string at {_format_hex(string.address)}...")
        self._thread_pool.start(XrefLoadWorker(self._current_path, string, self._signals))

    def _on_import_selection_changed(self) -> None:
        selected_items = self.imports_table.selectedItems()
        if not selected_items or self._current_path is None or self._loading_image:
            return
        imp = selected_items[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(imp, ImportInfo):
            return
        self._selected_import_name = imp.name
        self.details_tabs.setCurrentIndex(3)
        self._update_import_details(imp)
        self.import_xref_summary_label.setText("Loading import callers from radare2...")
        self.import_xrefs_table.setRowCount(0)
        self._set_status(f"Reading callers for import {imp.name}...")
        self._thread_pool.start(ImportXrefLoadWorker(self._current_path, imp, self._signals))

    def _on_symbol_selection_changed(self) -> None:
        selected_items = self.symbols_table.selectedItems()
        if not selected_items or self._current_path is None or self._loading_image:
            return
        symbol = selected_items[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(symbol, SymbolInfo):
            return
        self._selected_symbol_address = symbol.address
        self._selected_symbol_name = symbol.name
        self.details_tabs.setCurrentIndex(4)
        self._update_symbol_details(symbol)
        self._set_status(f"Reading GNU metadata for symbol {symbol.name}...")
        self._thread_pool.start(
            AddressMetadataWorker(
                self._current_path,
                symbol.name,
                symbol.address,
                "symbol",
                self._signals,
            )
        )

    def _navigate_selected_xref(self, *_args: object) -> None:
        selected_items = self.xrefs_table.selectedItems()
        if not selected_items:
            return
        xref = selected_items[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(xref, XrefInfo) or xref.function_address <= 0:
            return
        self._select_function_by_address(xref.function_address)

    def _navigate_selected_import_xref(self, *_args: object) -> None:
        selected_items = self.import_xrefs_table.selectedItems()
        if not selected_items:
            return
        xref = selected_items[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(xref, XrefInfo) or xref.function_address <= 0:
            return
        self._select_function_by_address(xref.function_address)

    def _navigate_selected_symbol(self, *_args: object) -> None:
        selected_items = self.symbols_table.selectedItems()
        if not selected_items:
            return
        symbol = selected_items[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(symbol, SymbolInfo) or symbol.address <= 0:
            return
        if self._select_function_by_address(symbol.address, scroll_address=symbol.address):
            return
        self._set_status(f"No loaded function matched symbol {symbol.name}", 4000)

    def _on_function_cfg_block_activated(self, address: int) -> None:
        self._highlight_cfg_block(address)
        self.function_preview_tabs.setCurrentIndex(0)
        self._navigate_to_address(address, prefer_section_scroll=False)

    def _navigate_section_disassembly_target(self, url: QUrl) -> None:
        address = self._parse_navigation_target(url)
        if address is None:
            return
        self._navigate_to_address(address, prefer_section_scroll=True)

    def _navigate_function_disassembly_target(self, url: QUrl) -> None:
        address = self._parse_navigation_target(url)
        if address is None:
            return
        self._navigate_to_address(address, prefer_section_scroll=False)

    def _parse_navigation_target(self, url: QUrl) -> int | None:
        target = url.toString()
        if not target.startswith("nav://"):
            return None
        try:
            return int(target.removeprefix("nav://"), 16)
        except ValueError:
            return None

    def _navigate_to_address(self, address: int, *, prefer_section_scroll: bool) -> None:
        if (
            self._current_function_disassembly is not None
            and _function_contains_address(self._current_function_disassembly.function, address)
        ):
            self.details_tabs.setCurrentIndex(1)
            self.function_preview_tabs.setCurrentIndex(0)
            self._highlight_cfg_block(address)
            self._scroll_function_disassembly_to_address(address)
            self._set_status(
                f"Navigated to {_format_hex(address)} in {self._current_function_disassembly.function.name}",
                4000,
            )
            return
        if self._select_function_by_address(address, scroll_address=address):
            return
        if prefer_section_scroll and self._current_section_disassembly is not None:
            self.details_tabs.setCurrentIndex(0)
            self.preview_tabs.setCurrentIndex(1)
            self.disassembly_preview.scrollToAnchor(_address_anchor(address))
            self._set_status(f"Navigated to {_format_hex(address)} in section disassembly", 4000)
            return
        self._set_status(f"No loaded function matched {_format_hex(address)}", 4000)

    def _select_function_by_address(self, address: int, scroll_address: int | None = None) -> bool:
        for row in range(self.functions_table.rowCount()):
            item = self.functions_table.item(row, 0)
            function = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            if not isinstance(function, FunctionInfo) or not _function_contains_address(function, address):
                continue
            self.details_tabs.setCurrentIndex(1)
            self._pending_function_scroll_address = scroll_address
            self.functions_table.selectRow(row)
            if (
                self._current_function_disassembly is not None
                and self._current_function_disassembly.function.address == function.address
            ):
                if scroll_address is not None:
                    self._highlight_cfg_block(scroll_address)
                    self.function_preview_tabs.setCurrentIndex(0)
                    self._scroll_function_disassembly_to_address(scroll_address)
                    self._pending_function_scroll_address = None
                self._set_status(f"Navigated to function {function.name}", 4000)
            return True
        if scroll_address is None:
            self._set_status(f"No loaded function matched {_format_hex(address)}", 4000)
        return False

    def _scroll_function_disassembly_to_address(self, address: int) -> None:
        self.function_disassembly_preview.scrollToAnchor(_address_anchor(address))

    def _highlight_cfg_block(self, address: int) -> None:
        if self._current_function_graph is None:
            return
        block_address = _find_cfg_block_address(self._current_function_graph.blocks, address)
        if block_address is None:
            return
        default_brush = QBrush(QColor("#1b2430"))
        selected_brush = QBrush(QColor("#1f6feb"))
        for candidate_address, item in self._cfg_block_items.items():
            item.setBrush(selected_brush if candidate_address == block_address else default_brush)
        self._selected_cfg_block_address = block_address
        self.function_cfg_view.centerOn(self._cfg_block_items[block_address])

    def _render_function_graph(self, result: FunctionGraphResult) -> None:
        self._current_function_graph = result
        self.function_cfg_scene.clear()
        self._cfg_block_items.clear()
        self._selected_cfg_block_address = None
        if not result.blocks:
            return

        entry_address = result.function.address
        depths: dict[int, int] = {entry_address: 0}
        changed = True
        while changed:
            changed = False
            for edge in result.edges:
                source_depth = depths.get(edge.source_address)
                if source_depth is None:
                    continue
                target_depth = source_depth + 1
                current_depth = depths.get(edge.target_address)
                if current_depth is None or target_depth < current_depth:
                    depths[edge.target_address] = target_depth
                    changed = True

        block_positions: dict[int, QPointF] = {}
        fixed_font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        fixed_font.setPointSize(max(fixed_font.pointSize() - 1, 8))
        block_width = 360.0
        block_height = 118.0
        horizontal_gap = 110.0
        vertical_gap = 34.0

        for row, block in enumerate(result.blocks):
            depth = depths.get(block.address, 0)
            x = depth * (block_width + horizontal_gap)
            y = row * (block_height + vertical_gap)
            position = QPointF(x, y)
            block_positions[block.address] = position

            rect_item = self.function_cfg_scene.addRect(
                x,
                y,
                block_width,
                block_height,
                QPen(QColor("#4b5b70"), 1.5),
                QBrush(QColor("#1b2430")),
            )
            rect_item.setData(0, block.address)
            self._cfg_block_items[block.address] = rect_item

            text_item = QGraphicsTextItem(_cfg_preview_text(block), rect_item)
            text_item.setDefaultTextColor(QColor("#eef2f7"))
            text_item.setFont(fixed_font)
            text_item.setPos(10, 8)

        for edge in result.edges:
            source_position = block_positions.get(edge.source_address)
            target_position = block_positions.get(edge.target_address)
            if source_position is None or target_position is None:
                continue
            source_point = QPointF(source_position.x() + block_width, source_position.y() + (block_height / 2))
            target_point = QPointF(target_position.x(), target_position.y() + (block_height / 2))
            mid_x = (source_point.x() + target_point.x()) / 2
            path = QPainterPath(source_point)
            path.cubicTo(
                QPointF(mid_x, source_point.y()),
                QPointF(mid_x, target_point.y()),
                target_point,
            )
            edge_color = QColor("#3fb950") if edge.kind == "jump" else QColor("#d29922")
            self.function_cfg_scene.addPath(path, QPen(edge_color, 2.0))
            label_item = self.function_cfg_scene.addText(edge.kind.upper(), fixed_font)
            label_item.setDefaultTextColor(edge_color)
            label_item.setPos(mid_x - 18, (source_point.y() + target_point.y()) / 2 - 10)

        bounds = self.function_cfg_scene.itemsBoundingRect()
        self.function_cfg_scene.setSceneRect(bounds.adjusted(-40, -30, 40, 30))

    def _update_details(self, section: SectionInfo) -> None:
        self.detail_name.setText(section.name)
        self.detail_index.setText(_format_int(section.index))
        self.detail_size.setText(f"{_format_int(section.size)} bytes")
        self.detail_vma.setText(_format_hex(section.vma))
        self.detail_lma.setText(_format_hex(section.lma))
        self.detail_flags.setText(_format_hex(section.flags))
        self.detail_alignment.setText(_format_int(section.alignment_power))
        self.detail_offset.setText(_format_hex(section.file_offset))

    def _update_function_details(self, function: FunctionInfo) -> None:
        self.function_name_value.setText(function.name)
        self.function_address_value.setText(_format_hex(function.address))
        self.function_size_value.setText(f"{_format_int(function.size)} bytes")
        self.function_instr_count_value.setText(_format_int(function.instruction_count))
        self.function_type_value.setText(function.kind)
        self.function_signature_value.setText(function.signature or "-")
        self.function_demangled_value.setText(function.name)
        self.function_source_value.setText("Loading source lookup...")

    def _update_string_details(self, string: StringInfo) -> None:
        self.string_value_label.setText(string.value)
        self.string_address_label.setText(_format_hex(string.address))
        self.string_length_label.setText(_format_int(string.length))
        self.string_section_label.setText(string.section or "-")
        self.string_type_label.setText(string.kind)

    def _update_import_details(self, imp: ImportInfo) -> None:
        self.import_name_label.setText(imp.name)
        self.import_plt_label.setText(_format_hex(imp.plt_address))
        self.import_bind_label.setText(imp.bind or "-")
        self.import_type_label.setText(imp.kind)

    def _update_symbol_details(self, symbol: SymbolInfo) -> None:
        self.symbol_name_label.setText(symbol.name)
        self.symbol_demangled_label.setText(symbol.demangled_name or symbol.name)
        self.symbol_address_label.setText(_format_hex(symbol.address))
        self.symbol_type_label.setText(symbol.kind)
        self.symbol_origin_label.setText("dynamic" if symbol.is_dynamic else "regular")
        self.symbol_source_label.setText("Loading source lookup...")

    def _clear_section_details(self) -> None:
        self._current_section_disassembly = None
        self.detail_name.setText("No section selected")
        self.detail_index.setText("-")
        self.detail_size.setText("-")
        self.detail_vma.setText("-")
        self.detail_lma.setText("-")
        self.detail_flags.setText("-")
        self.detail_alignment.setText("-")
        self.detail_offset.setText("-")
        self.preview_hint.setText("Save the current section bytes to disk.")
        self.preview.setPlainText("")
        self.disassembly_summary.setText(
            f"Previewing up to {DEFAULT_INSTRUCTION_LIMIT} instructions with radare2."
        )
        self.disassembly_preview.setPlainText("")
        self.export_action.setEnabled(False)
        self.export_button.setEnabled(False)

    def _clear_function_details(self) -> None:
        self._current_function_disassembly = None
        self._current_function_decompilation = None
        self._current_function_graph = None
        self._pending_function_scroll_address = None
        self._selected_cfg_block_address = None
        self._cfg_block_items.clear()
        self.function_name_value.setText("No function selected")
        self.function_address_value.setText("-")
        self.function_size_value.setText("-")
        self.function_instr_count_value.setText("-")
        self.function_type_value.setText("-")
        self.function_signature_value.setText("-")
        self.function_demangled_value.setText("-")
        self.function_source_value.setText("-")
        self.function_disassembly_summary.setText(
            "Select a radare2 function to preview its full disassembly."
        )
        self.function_disassembly_preview.setPlainText("")
        self.function_decompilation_summary.setText(
            "Select a radare2 function to preview its HLL-style decompilation."
        )
        self.function_decompilation_preview.setPlainText("")
        self.function_cfg_summary.setText("Select a radare2 function to preview its control-flow graph.")
        self.function_cfg_scene.clear()

    def _clear_string_details(self) -> None:
        self.string_value_label.setText("No string selected")
        self.string_address_label.setText("-")
        self.string_length_label.setText("-")
        self.string_section_label.setText("-")
        self.string_type_label.setText("-")
        self.xref_summary_label.setText("Select a string to load xrefs.")
        self.xrefs_table.setRowCount(0)

    def _clear_import_details(self) -> None:
        self.import_name_label.setText("No import selected")
        self.import_plt_label.setText("-")
        self.import_bind_label.setText("-")
        self.import_type_label.setText("-")
        self.import_xref_summary_label.setText("Select an import to load callers.")
        self.import_xrefs_table.setRowCount(0)

    def _clear_symbol_details(self) -> None:
        self._selected_symbol_name = None
        self.symbol_name_label.setText("No symbol selected")
        self.symbol_demangled_label.setText("-")
        self.symbol_address_label.setText("-")
        self.symbol_type_label.setText("-")
        self.symbol_origin_label.setText("-")
        self.symbol_source_label.setText("-")

    def _clear_details(self) -> None:
        self._clear_section_details()
        self._clear_function_details()
        self._clear_string_details()
        self._clear_import_details()
        self._clear_symbol_details()

    def export_selected_section(self) -> None:
        if self._current_path is None or self._selected_section is None or not self._selected_section_bytes:
            return
        target, _ = QFileDialog.getSaveFileName(
            self,
            "Export Section",
            str(_build_export_path(self._current_path, self._selected_section)),
            "Binary Files (*.bin);;All Files (*)",
        )
        if not target:
            return
        output_path = Path(target)
        try:
            output_path.write_bytes(self._selected_section_bytes)
        except OSError as exc:
            self._show_error(
                ErrorInfo(
                    title="Export Error",
                    message=f"failed to export {self._selected_section} to {output_path}: {exc}",
                )
            )
            return
        self.preview_hint.setText(f"Exported {len(self._selected_section_bytes):,} bytes.")
        self._set_status(f"Exported {self._selected_section} to {output_path}", 5000)

    def _log_message(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.appendPlainText(f"[{timestamp}] {message}")

    def _set_status(self, message: str, timeout_ms: int = 0) -> None:
        self.statusBar().showMessage(message, timeout_ms)
        self._log_message(message)

    def _clear_console(self) -> None:
        self.console.clear()
        self._log_message("Console cleared.")

    def _console_workdir(self) -> Path:
        return self._current_path.parent if self._current_path is not None else DEFAULT_WORKDIR

    def _update_command_controls(self) -> None:
        running = self._command_process.state() != QProcess.ProcessState.NotRunning
        self.command_input.setEnabled(not running)
        self.run_command_button.setEnabled(not running)
        self.stop_command_button.setEnabled(running)
        self.run_codex_button.setEnabled(shutil.which("codex") is not None and _terminal_command() is not None)
        self.run_gdb_button.setEnabled(
            self._current_path is not None and _terminal_command() is not None and GnuToolchain.has_gdb()
        )

    def execute_console_command(self) -> None:
        command = self.command_input.text().strip()
        if not command:
            return
        if self._command_process.state() != QProcess.ProcessState.NotRunning:
            self._set_status("A command is already running. Stop it before starting another.", 4000)
            return
        workdir = self._console_workdir()
        self.console.appendPlainText(f"$ cd {workdir}")
        self.console.appendPlainText(f"$ {command}")
        self._command_process.setWorkingDirectory(str(workdir))
        self._command_process.start(_shell_path(), ["-lc", command])
        if not self._command_process.waitForStarted(1000):
            self._set_status(f"Failed to start command: {command}", 6000)
            self._update_command_controls()
            return
        self._set_status(f"Running command: {command}")
        self._update_command_controls()

    def _append_command_output(self) -> None:
        data = self._command_process.readAllStandardOutput().data().decode(errors="replace")
        if not data:
            return
        self.console.moveCursor(self.console.textCursor().MoveOperation.End)
        self.console.insertPlainText(data)
        if not data.endswith("\n"):
            self.console.insertPlainText("\n")
        self.console.ensureCursorVisible()

    def _on_command_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        status_name = "normal" if exit_status == QProcess.ExitStatus.NormalExit else "crashed"
        self._set_status(f"Command finished with exit code {exit_code} ({status_name}).", 5000)
        self._update_command_controls()

    def _on_command_error(self, _error: QProcess.ProcessError) -> None:
        error_text = self._command_process.errorString() or "Unknown process error"
        self._set_status(f"Command error: {error_text}", 6000)
        self._update_command_controls()

    def stop_console_command(self) -> None:
        if self._command_process.state() == QProcess.ProcessState.NotRunning:
            return
        self._command_process.kill()
        self._command_process.waitForFinished(1000)
        self._set_status("Command stopped by user.", 4000)
        self._update_command_controls()

    def launch_codex_terminal(self) -> None:
        codex = shutil.which("codex")
        if codex is None:
            self._set_status("The codex command is not available in PATH.", 6000)
            return
        workdir = self._console_workdir()
        self._launch_external_terminal([codex], workdir=workdir, success_message=f"Launched codex in external terminal from {workdir}")

    def launch_gdb_terminal(self) -> None:
        if self._current_path is None:
            self._set_status("Load a binary before launching gdb.", 6000)
            return
        gdb = shutil.which("gdb")
        if gdb is None:
            self._set_status("The gdb command is not available in PATH.", 6000)
            return
        workdir = self._console_workdir()
        self._launch_external_terminal(
            [gdb, "-q", str(self._current_path)],
            workdir=workdir,
            success_message=f"Launched gdb for {self._current_path.name} in external terminal",
        )

    def _launch_external_terminal(self, command: list[str], *, workdir: Path, success_message: str) -> None:
        terminal = _terminal_command()
        if terminal is None:
            self._set_status("No terminal emulator was found for launching external tools.", 6000)
            return
        shell = _shell_path()
        shell_command = f"cd {shlex.quote(str(workdir))} && {' '.join(shlex.quote(part) for part in command)}"
        ok, _pid = QProcess.startDetached(terminal, ["-e", shell, "-lc", shell_command], str(workdir))
        if not ok:
            self._set_status("Failed to launch the external terminal command.", 6000)
            return
        self._set_status(success_message, 5000)

    def set_theme(self, theme: str) -> None:
        self._theme = theme
        app = QApplication.instance()
        if app is None:
            return
        app.setStyleSheet(_theme_stylesheet(theme))
        self.light_theme_action.setChecked(theme == LIGHT_THEME)
        self.dark_theme_action.setChecked(theme == DARK_THEME)

    def show_about_dialog(self) -> None:
        QMessageBox.about(
            self,
            f"About {APP_NAME}",
            f"{APP_NAME}\n\nA Qt desktop interface for browsing binaries through libbfd, radare2, and GNU binutils.",
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._command_process.state() != QProcess.ProcessState.NotRunning:
            self._command_process.kill()
            self._command_process.waitForFinished(1000)
        self._thread_pool.clear()
        self._thread_pool.waitForDone(3000)
        self._log_message("Application shutting down.")
        self.statusBar().clearMessage()
        super().closeEvent(event)


def create_application(argv: Sequence[str] | None = None) -> QApplication:
    app = QApplication(list(argv or []))
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("ironview")
    app.setStyle("Fusion")
    app.setStyleSheet(_theme_stylesheet(LIGHT_THEME))
    return app


def run_gui(initial_path: str | Path | None = None) -> int:
    app = create_application()
    window = MainWindow(initial_path)
    window.show()
    return app.exec()
