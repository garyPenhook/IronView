import json
import shutil
import subprocess
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

import src.binary_loader
import src.gnu_toolchain
from src.binary_loader import BinaryImage, BinaryLoader, BinaryLoaderError
from src.disassembler import (
    BinaryMetadataReport,
    ControlFlowBlock,
    ControlFlowEdge,
    DecompilationAnnotation,
    DecompilationLineMapping,
    DisassembledInstruction,
    DisassemblyResult,
    ExportInfo,
    FunctionDecompilationResult,
    FunctionDisassemblyResult,
    FunctionGraphResult,
    FunctionInfo,
    ImportInfo,
    InstructionTarget,
    Radare2Disassembler,
    Radare2DisassemblerError,
    RelocationInfo,
    StringInfo,
    XrefInfo,
    format_disassembly,
    format_disassembly_html,
    format_function_disassembly,
    format_function_disassembly_html,
)
from src.gnu_toolchain import GnuToolchain, GnuToolchainError, SymbolInfo
from src.gui import (
    AddressMetadataWorker,
    DARK_THEME,
    ErrorInfo,
    LIGHT_THEME,
    LoadedBinaryReport,
    LoadedExportXrefs,
    LoadedImage,
    LoadedFunctionDecompilation,
    LoadedRelocationXrefs,
    MainWindow,
    _build_export_path,
    _find_cfg_block_address,
    _matches_section_filter,
)
from src.main import main


@pytest.fixture()
def sample_binary() -> Path:
    return Path("/bin/ls")


@pytest.fixture(scope="session")
def qt_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture(scope="session")
def has_radare2() -> bool:
    return shutil.which("r2") is not None or shutil.which("radare2") is not None


@pytest.fixture(scope="session")
def has_gnu_toolchain() -> bool:
    return GnuToolchain.has_nm() and GnuToolchain.has_readelf() and GnuToolchain.has_addr2line()


def test_loader_lists_sections(sample_binary: Path) -> None:
    with BinaryLoader(sample_binary) as loader:
        image = loader.image()

    assert image.arch_size in (32, 64)
    assert image.file_format == "ELF"
    assert "elf" in image.target.lower()
    assert image.sections
    assert any(section.name == ".text" for section in image.sections)


def test_loader_reads_named_section(sample_binary: Path) -> None:
    with BinaryLoader(sample_binary) as loader:
        text = loader.read_section(".text")

    assert text
    assert len(text) > 16


def test_loader_raises_for_missing_section(sample_binary: Path) -> None:
    with BinaryLoader(sample_binary) as loader:
        with pytest.raises(BinaryLoaderError, match="section not found"):
            loader.read_section(".definitely_missing")


def test_loader_wraps_libbfd_initialization_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenLibBfd:
        def __init__(self) -> None:
            raise OSError("missing libbfd dependency")

    monkeypatch.setattr(src.binary_loader, "_LIBBFD", None)
    monkeypatch.setattr(src.binary_loader, "_LibBfd", BrokenLibBfd)

    with pytest.raises(BinaryLoaderError, match="failed to initialize libbfd: missing libbfd dependency"):
        src.binary_loader._libbfd()


def test_resolve_library_skips_missing_hardcoded_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    original_exists = src.binary_loader.Path.exists
    original_is_file = src.binary_loader.Path.is_file

    monkeypatch.setattr(src.binary_loader.ctypes.util, "find_library", lambda name: None)
    monkeypatch.setattr(
        src.binary_loader.Path,
        "exists",
        lambda self: False
        if str(self) == "/usr/lib/x86_64-linux-gnu/libbfd.so"
        else original_exists(self),
    )
    monkeypatch.setattr(
        src.binary_loader.Path,
        "is_file",
        lambda self: True
        if str(self) == "/usr/lib/x86_64-linux-gnu/libbfd-2.46-system.so"
        else original_is_file(self),
    )
    monkeypatch.setattr(
        src.binary_loader.Path,
        "glob",
        lambda self, pattern: [Path("/usr/lib/x86_64-linux-gnu/libbfd-2.46-system.so")]
        if str(self) == "/usr/lib" and pattern == "*/libbfd-*.so"
        else [],
    )

    resolved = src.binary_loader._LibBfd._resolve_library()

    assert resolved == "/usr/lib/x86_64-linux-gnu/libbfd-2.46-system.so"


def test_main_launches_gui_when_no_path(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str | None] = []

    def fake_run_gui(initial_path: str | None = None) -> int:
        calls.append(initial_path)
        return 17

    monkeypatch.setattr("src.main.run_gui", fake_run_gui)

    assert main([]) == 17
    assert calls == [None]


def test_main_rejects_section_without_path() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--section", ".text"])

    assert exc_info.value.code == 2


def test_main_cli_json_includes_format_metadata(sample_binary: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(sample_binary)]) == 0

    payload = json.loads(capsys.readouterr().out)

    assert payload["file_format"] == "ELF"
    assert "elf" in payload["target"].lower()


def test_matches_section_filter_checks_name_and_addresses(sample_binary: Path) -> None:
    with BinaryLoader(sample_binary) as loader:
        section = next(item for item in loader.image().sections if item.name == ".text")

    assert _matches_section_filter(section, ".text")
    assert _matches_section_filter(section, hex(section.vma))
    assert not _matches_section_filter(section, "definitely-not-present")


def test_build_export_path_uses_binary_name_and_section_name() -> None:
    export_path = _build_export_path(Path("/tmp/sample.bin"), ".text")

    assert export_path == Path("/tmp/sample.bin.text.bin")


def test_radare2_disassembler_returns_text_for_code_section(
    has_radare2: bool,
    sample_binary: Path,
) -> None:
    if not has_radare2:
        pytest.skip("radare2 is not installed")

    with BinaryLoader(sample_binary) as loader:
        text_section = next(section for section in loader.image().sections if section.name == ".text")

    with Radare2Disassembler(sample_binary) as disassembler:
        result = disassembler.disassemble_section(
            text_section.name,
            start_address=text_section.vma,
            fallback_address=text_section.file_offset,
            instruction_limit=8,
        )

    assert result.instructions
    rendered = format_disassembly(result)
    assert ".text" in rendered
    assert "instructions" in rendered


def test_radare2_lists_functions_and_renders_function_disassembly(
    has_radare2: bool,
    sample_binary: Path,
) -> None:
    if not has_radare2:
        pytest.skip("radare2 is not installed")

    with Radare2Disassembler(sample_binary) as disassembler:
        functions = disassembler.list_functions()
        entry_function = next(function for function in functions if function.name == "entry0")
        result = disassembler.disassemble_function(entry_function)

    assert functions
    assert result.instructions
    rendered = format_function_disassembly(result)
    assert "entry0" in rendered
    assert "instructions" in rendered


def test_radare2_decompile_function_returns_hll_text() -> None:
    class FakeR2:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def cmd(self, command: str) -> str:
            self.commands.append(command)
            if command == "pdg?":
                return "You need to install the plugin with r2pm -ci r2ghidra"
            if command == "pdd?":
                return "You need to install the plugin with r2pm -ci r2dec"
            if command == "pdc?":
                return "Usage: pdc pseudo decompile function"
            if command == "pdc @ 4198400":
                return "int main(void) {\n    return 0;\n}\n"
            raise AssertionError(command)

    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    disassembler = Radare2Disassembler("/bin/ls")
    fake_r2 = FakeR2()
    disassembler._r2 = fake_r2
    disassembler._architecture = "x86"
    disassembler._bits = 64

    result = disassembler.decompile_function(function)

    assert result.backend == "pdc"
    assert "return 0;" in result.text
    assert fake_r2.commands == ["pdg?", "pdd?", "pdc?", "pdc @ 4198400"]


def test_radare2_decompile_function_includes_metadata_and_line_mappings() -> None:
    class FakeR2:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def cmd(self, command: str) -> str:
            self.commands.append(command)
            responses = {
                "pdg?": "You need to install the plugin with r2pm -ci r2ghidra",
                "pdd?": "You need to install the plugin with r2pm -ci r2dec",
                "pdc?": "Usage: pdc pseudo decompile function",
                "pdc @ 4198400": "int main(void) {\n    return 0;\n}",
            }
            return responses[command]

        def cmdj(self, command: str) -> dict[str, object]:
            assert command == "pdcj @ 4198400"
            return {
                "code": "int main(void) {\n    return 0;\n}",
                "annotations": [
                    {"start": 0, "end": 2, "offset": 0x401000, "type": "offset"},
                    {"start": 21, "end": 26, "offset": 0x401004, "type": "offset"},
                ],
            }

    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    disassembler = Radare2Disassembler("/bin/ls")
    fake_r2 = FakeR2()
    disassembler._r2 = fake_r2
    disassembler._architecture = "x86"
    disassembler._bits = 64

    result = disassembler.decompile_function(function)

    assert result.backend == "pdc"
    assert result.backend_display_name == "radare2 pseudo (pdc)"
    assert result.available_backends == ("pdc",)
    assert result.used_fallback is True
    assert result.annotations == (
        DecompilationAnnotation(start=0, end=2, address=0x401000, kind="offset"),
        DecompilationAnnotation(start=21, end=26, address=0x401004, kind="offset"),
    )
    assert result.line_mappings == (
        DecompilationLineMapping(line_number=1, start=0, end=17, addresses=(0x401000,)),
        DecompilationLineMapping(line_number=2, start=17, end=31, addresses=(0x401004,)),
    )
    assert any("Preferred HLL backend pdg was unavailable" in warning for warning in result.warnings)
    assert any("pdc output is heuristic" in warning for warning in result.warnings)
    assert fake_r2.commands == ["pdg?", "pdd?", "pdc?", "pdc @ 4198400"]


def test_radare2_lists_available_decompilation_backends_in_priority_order() -> None:
    class FakeR2:
        def cmd(self, command: str) -> str:
            responses = {
                "pdg?": "Usage: pdg decompile current function",
                "pdd?": "You need to install the plugin with r2pm -ci r2dec",
                "pdc?": "Usage: pdc pseudo decompile function",
            }
            return responses[command]

    disassembler = Radare2Disassembler("/bin/ls")
    disassembler._r2 = FakeR2()

    assert disassembler.available_decompilation_backends() == ("pdg", "pdc")


def test_radare2_decompile_function_prefers_richer_available_backend() -> None:
    class FakeR2:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def cmd(self, command: str) -> str:
            self.commands.append(command)
            responses = {
                "pdg?": "Usage: pdg decompile current function",
                "pdd?": "Usage: pdd decompile current function",
                "pdc?": "Usage: pdc pseudo decompile function",
                "pdg @ 4198400": "int main(int argc, char **argv) {\n    return argc;\n}",
            }
            return responses[command]

    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    disassembler = Radare2Disassembler("/bin/ls")
    fake_r2 = FakeR2()
    disassembler._r2 = fake_r2
    disassembler._architecture = "x86"
    disassembler._bits = 64

    result = disassembler.decompile_function(function)

    assert result.backend == "pdg"
    assert "return argc;" in result.text
    assert fake_r2.commands == ["pdg?", "pdd?", "pdc?", "pdg @ 4198400"]


def test_radare2_decompile_function_allows_explicit_backend_selection() -> None:
    class FakeR2:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def cmd(self, command: str) -> str:
            self.commands.append(command)
            responses = {
                "pdg?": "Usage: pdg decompile current function",
                "pdd?": "Usage: pdd decompile current function",
                "pdc?": "Usage: pdc pseudo decompile function",
                "pdd @ 4198400": "int main(void) {\n    return 1;\n}",
            }
            return responses[command]

    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    disassembler = Radare2Disassembler("/bin/ls")
    fake_r2 = FakeR2()
    disassembler._r2 = fake_r2
    disassembler._architecture = "x86"
    disassembler._bits = 64

    result = disassembler.decompile_function(function, backend="pdd")

    assert result.backend == "pdd"
    assert "return 1;" in result.text
    assert fake_r2.commands == ["pdg?", "pdd?", "pdc?", "pdd @ 4198400"]


def test_radare2_decompile_function_rejects_unavailable_explicit_backend() -> None:
    class FakeR2:
        def cmd(self, command: str) -> str:
            responses = {
                "pdg?": "You need to install the plugin with r2pm -ci r2ghidra",
                "pdd?": "You need to install the plugin with r2pm -ci r2dec",
                "pdc?": "Usage: pdc pseudo decompile function",
            }
            return responses[command]

    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    disassembler = Radare2Disassembler("/bin/ls")
    disassembler._r2 = FakeR2()

    with pytest.raises(Radare2DisassemblerError, match="decompilation backend pdd is not available"):
        disassembler.decompile_function(function, backend="pdd")


def test_disassembly_html_renders_navigation_links() -> None:
    result = DisassemblyResult(
        path=Path("/tmp/sample.bin"),
        section_name=".text",
        architecture="x86",
        bits=64,
        start_address=0x401000,
        instructions=(
            DisassembledInstruction(
                address=0x401000,
                size=5,
                bytes_hex="E8 0B 00 00 00",
                text="call 0x401010",
                targets=(InstructionTarget("jump", 0x401010),),
            ),
        ),
    )

    rendered = format_disassembly_html(result)

    assert "nav://0x401010" in rendered
    assert "addr-401000" in rendered
    assert "call 0x401010" in rendered


def test_function_disassembly_html_renders_navigation_links() -> None:
    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    result = FunctionDisassemblyResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        instructions=(
            DisassembledInstruction(
                address=0x401000,
                size=2,
                bytes_hex="75 0A",
                text="jne 0x40100c",
                targets=(InstructionTarget("jump", 0x40100C), InstructionTarget("fail", 0x401002)),
            ),
        ),
    )

    rendered = format_function_disassembly_html(result)

    assert "nav://0x40100C" in rendered
    assert "nav://0x401002" in rendered
    assert "int main(void);" in rendered


def test_gnu_toolchain_lists_symbols_and_reads_elf_report(
    has_gnu_toolchain: bool,
    sample_binary: Path,
) -> None:
    if not has_gnu_toolchain:
        pytest.skip("GNU binutils are not fully installed")

    toolchain = GnuToolchain(sample_binary)
    symbols = toolchain.list_symbols()
    report = toolchain.read_elf_report()
    source = toolchain.lookup_source(next(symbol.address for symbol in symbols if symbol.address > 0))

    assert symbols
    assert report.text.startswith("ELF Header:")
    assert source is not None
    assert source.function_name


def test_gnu_toolchain_demangles_cxx_symbol() -> None:
    if not GnuToolchain.has_cxxfilt():
        pytest.skip("c++filt is not installed")
    toolchain = GnuToolchain("/bin/ls")
    assert toolchain.demangle("_ZNSt8ios_base4InitC1Ev") == "std::ios_base::Init::Init()"


def test_gnu_toolchain_reports_partial_nm_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    toolchain = GnuToolchain("/bin/ls")
    monkeypatch.setattr(
        src.gnu_toolchain.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["nm"],
            returncode=1,
            stdout="main T 0000000000401000 10\n",
            stderr="file format not recognized",
        ),
    )

    with pytest.raises(GnuToolchainError, match="nm produced partial output: file format not recognized"):
        toolchain._run_nm(is_dynamic=False)


def test_find_cfg_block_address_matches_inner_address() -> None:
    blocks = (
        ControlFlowBlock(0x401000, 0x10, ()),
        ControlFlowBlock(0x401010, 0x20, ()),
    )

    assert _find_cfg_block_address(blocks, 0x401000) == 0x401000
    assert _find_cfg_block_address(blocks, 0x40101A) == 0x401010
    assert _find_cfg_block_address(blocks, 0x402000) is None


def test_radare2_lists_strings_and_xrefs(
    has_radare2: bool,
    sample_binary: Path,
) -> None:
    if not has_radare2:
        pytest.skip("radare2 is not installed")

    with Radare2Disassembler(sample_binary) as disassembler:
        strings = disassembler.list_strings()
        target = next(string for string in strings if string.value == "dev_ino_pop")
        xrefs = disassembler.list_xrefs_to(target.address)

    assert strings
    assert xrefs
    assert any(xref.function_name == "main" for xref in xrefs)


def test_radare2_lists_imports_and_callers(
    has_radare2: bool,
    sample_binary: Path,
) -> None:
    if not has_radare2:
        pytest.skip("radare2 is not installed")

    with Radare2Disassembler(sample_binary) as disassembler:
        imports = disassembler.list_imports()
        target = next(imp for imp in imports if imp.name == "getenv")
        xrefs = disassembler.list_xrefs_to_import(target.name)

    assert imports
    assert xrefs
    assert any(xref.function_name == "main" for xref in xrefs)


def test_radare2_lists_symbols(
    has_radare2: bool,
    sample_binary: Path,
) -> None:
    if not has_radare2:
        pytest.skip("radare2 is not installed")

    with Radare2Disassembler(sample_binary) as disassembler:
        symbols = disassembler.list_symbols()

    assert symbols
    assert any(symbol.kind == "FUNC" for symbol in symbols)
    assert any(symbol.is_dynamic for symbol in symbols)


def test_radare2_lists_exports(
    has_radare2: bool,
    sample_binary: Path,
) -> None:
    if not has_radare2:
        pytest.skip("radare2 is not installed")

    with Radare2Disassembler(sample_binary) as disassembler:
        exports = disassembler.list_exports()

    assert exports
    assert any(export.kind == "OBJ" for export in exports)


def test_radare2_lists_relocations(
    has_radare2: bool,
    sample_binary: Path,
) -> None:
    if not has_radare2:
        pytest.skip("radare2 is not installed")

    with Radare2Disassembler(sample_binary) as disassembler:
        relocations = disassembler.list_relocations()

    assert relocations
    assert any(relocation.kind for relocation in relocations)


def test_radare2_inspects_binary_metadata(
    has_radare2: bool,
    sample_binary: Path,
) -> None:
    if not has_radare2:
        pytest.skip("radare2 is not installed")

    with Radare2Disassembler(sample_binary) as disassembler:
        report = disassembler.inspect_binary()

    assert "Format:" in report.text
    assert "Sections (" in report.text
    assert "Entrypoints (" in report.text
    assert "Imports (" in report.text
    assert "sections" in report.summary
    assert report.libraries


def test_radare2_builds_function_cfg(
    has_radare2: bool,
    sample_binary: Path,
) -> None:
    if not has_radare2:
        pytest.skip("radare2 is not installed")

    with Radare2Disassembler(sample_binary) as disassembler:
        functions = disassembler.list_functions()
        main_function = next(function for function in functions if function.name == "main")
        graph = disassembler.analyze_function_graph(main_function)

    assert graph.blocks
    assert any(block.address == main_function.address for block in graph.blocks)
    assert graph.edges


def test_main_window_theme_toggle_and_filtering(qt_app: QApplication, sample_binary: Path) -> None:
    window = MainWindow()
    with BinaryLoader(sample_binary) as loader:
        image = loader.image()

    window._current_path = sample_binary.resolve()
    window._current_image = image
    window._populate_sections_table(image.sections)
    window._set_loaded_state(True)
    qt_app.processEvents()
    window.filter_input.setText(".text")
    qt_app.processEvents()

    visible_rows = [
        row for row in range(window.sections_table.rowCount()) if not window.sections_table.isRowHidden(row)
    ]
    assert visible_rows

    window.set_theme(DARK_THEME)
    assert window.dark_theme_action.isChecked()
    window.set_theme(LIGHT_THEME)
    assert window.light_theme_action.isChecked()
    window.close()


def test_main_window_function_filtering(qt_app: QApplication) -> None:
    window = MainWindow()
    window._populate_functions_table(
        (
            FunctionInfo("entry0", 0x4010, 32, 12, "sym", "entry0 ();"),
            FunctionInfo("sym.imp.printf", 0x4020, 6, 1, "sym", "printf ();"),
        )
    )
    window._set_loaded_state(True)
    qt_app.processEvents()
    window.function_filter_input.setText("entry0")
    qt_app.processEvents()

    visible_rows = [
        row for row in range(window.functions_table.rowCount()) if not window.functions_table.isRowHidden(row)
    ]
    assert visible_rows == [0]
    assert window.function_count_label.text() == "1 shown"
    window.close()


def test_main_window_select_function_by_inner_address(qt_app: QApplication) -> None:
    window = MainWindow()
    window._populate_functions_table(
        (
            FunctionInfo("entry0", 0x4010, 0x20, 12, "sym", "entry0 ();"),
            FunctionInfo("main", 0x4100, 0x40, 18, "sym", "int main(void);"),
        )
    )
    window._set_loaded_state(True)
    qt_app.processEvents()

    matched = window._select_function_by_address(0x4110)
    qt_app.processEvents()

    assert matched is True
    assert window.functions_table.currentRow() == 1
    window.close()


def test_main_window_renders_function_cfg(qt_app: QApplication) -> None:
    window = MainWindow()
    function = FunctionInfo("main", 0x401000, 0x30, 3, "sym", "int main(void);")
    graph = FunctionGraphResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        blocks=(
            ControlFlowBlock(
                0x401000,
                0x10,
                (
                    DisassembledInstruction(0x401000, 2, "75 0A", "jne 0x40100c"),
                    DisassembledInstruction(0x401002, 2, "90", "nop"),
                ),
            ),
            ControlFlowBlock(
                0x401010,
                0x10,
                (
                    DisassembledInstruction(0x401010, 1, "C3", "ret"),
                ),
            ),
        ),
        edges=(
            ControlFlowEdge(0x401000, 0x401010, "jump"),
        ),
    )

    window._render_function_graph(graph)
    window._highlight_cfg_block(0x401010)
    qt_app.processEvents()

    assert len(window._cfg_block_items) == 2
    assert window._selected_cfg_block_address == 0x401010
    assert not window.function_cfg_scene.itemsBoundingRect().isNull()
    window.close()


def test_main_window_loads_function_decompilation(qt_app: QApplication) -> None:
    window = MainWindow()
    function = FunctionInfo("main", 0x401000, 0x30, 3, "sym", "int main(void);")
    result = FunctionDecompilationResult(
        path=Path("/bin/ls"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdc",
        backend_display_name="radare2 pseudo (pdc)",
        text="int main(void) {\n    return 0;\n}",
        used_fallback=True,
        warnings=("Preferred HLL backend pdg was unavailable; using pdc instead.",),
        line_mappings=(
            DecompilationLineMapping(line_number=1, start=0, end=17, addresses=(0x401000,)),
        ),
    )
    window._current_path = Path("/bin/ls")
    window._selected_function_address = function.address

    window._on_function_decompilation_loaded(
        LoadedFunctionDecompilation(
            path=Path("/bin/ls"),
            function_address=function.address,
            result=result,
        )
    )
    qt_app.processEvents()

    assert "radare2 pseudo (pdc) HLL-style decompilation" in window.function_decompilation_summary.text()
    assert "Fallback backend in use." in window.function_decompilation_summary.text()
    assert "1 correlated lines." in window.function_decompilation_summary.text()
    assert "return 0;" in window.function_decompilation_preview.toPlainText()
    window.close()


def test_main_window_string_filtering(qt_app: QApplication) -> None:
    window = MainWindow()
    window._populate_strings_table(
        (
            StringInfo("entry-string", 0x5000, 12, 12, ".rodata", "ascii"),
            StringInfo("printf", 0x5010, 6, 6, ".rodata", "ascii"),
        )
    )
    window._set_loaded_state(True)
    qt_app.processEvents()
    window.string_filter_input.setText("entry-string")
    qt_app.processEvents()

    visible_rows = [
        row for row in range(window.strings_table.rowCount()) if not window.strings_table.isRowHidden(row)
    ]
    assert visible_rows == [0]
    assert window.string_count_label.text() == "1 shown"
    window.close()


def test_main_window_import_filtering(qt_app: QApplication) -> None:
    window = MainWindow()
    window._populate_imports_table(
        (
            ImportInfo("getenv", "GLOBAL", "FUNC", 0x4030),
            ImportInfo("printf", "GLOBAL", "FUNC", 0x4040),
        )
    )
    window._set_loaded_state(True)
    qt_app.processEvents()
    window.import_filter_input.setText("getenv")
    qt_app.processEvents()

    visible_rows = [
        row for row in range(window.imports_table.rowCount()) if not window.imports_table.isRowHidden(row)
    ]
    assert visible_rows == [0]
    assert window.import_count_label.text() == "1 shown"
    window.close()


def test_main_window_export_filtering(qt_app: QApplication) -> None:
    window = MainWindow()
    window._populate_exports_table(
        (
            ExportInfo("export_alpha", 0x4100, 16, "FUNC", "GLOBAL"),
            ExportInfo("export_beta", 0x4200, 32, "OBJ", "GLOBAL"),
        )
    )
    window._set_loaded_state(True)
    qt_app.processEvents()
    window.export_filter_input.setText("export_alpha")
    qt_app.processEvents()

    visible_rows = [
        row for row in range(window.exports_table.rowCount()) if not window.exports_table.isRowHidden(row)
    ]
    assert visible_rows == [0]
    assert window.export_count_label.text() == "1 shown"
    window.close()


def test_main_window_export_details_show_correlated_context(qt_app: QApplication) -> None:
    window = MainWindow()
    window._functions = (FunctionInfo("export_alpha", 0x4100, 16, 4, "sym", "export_alpha();"),)
    window._symbols = (SymbolInfo("export_alpha", "export_alpha", 0x4100, "FUNC", 16, False),)

    window._update_export_details(ExportInfo("export_alpha", 0x4100, 16, "FUNC", "GLOBAL"))
    qt_app.processEvents()

    assert "export_alpha @" in window.export_function_label.text()
    assert "export_alpha @" in window.export_symbol_label.text()
    window.close()


def test_main_window_loads_export_xrefs(qt_app: QApplication) -> None:
    window = MainWindow()
    window._current_path = Path("/tmp/sample.bin")
    window._selected_export_address = 0x4100

    window._on_export_xrefs_loaded(
        LoadedExportXrefs(
            path=window._current_path,
            export_address=0x4100,
            xrefs=(XrefInfo(0x5000, "CODE", "r-x", "call 0x4100", 0x5000, "main", "export_alpha"),),
        )
    )
    qt_app.processEvents()

    assert window.export_xref_summary_label.text() == "1 xrefs loaded"
    assert window.export_xrefs_table.rowCount() == 1
    window.close()


def test_main_window_relocation_filtering(qt_app: QApplication) -> None:
    window = MainWindow()
    window._populate_relocations_table(
        (
            RelocationInfo("puts", 0x5000, 0x4100, "JMP_SLOT", False),
            RelocationInfo("exit", 0x5010, 0x4200, "GLOB_DAT", False),
        )
    )
    window._set_loaded_state(True)
    qt_app.processEvents()
    window.relocation_filter_input.setText("puts")
    qt_app.processEvents()

    visible_rows = [
        row for row in range(window.relocations_table.rowCount()) if not window.relocations_table.isRowHidden(row)
    ]
    assert visible_rows == [0]
    assert window.relocation_count_label.text() == "1 shown"
    window.close()


def test_main_window_loads_relocation_xrefs(qt_app: QApplication) -> None:
    window = MainWindow()
    window._current_path = Path("/tmp/sample.bin")
    window._selected_relocation_address = 0x5000

    window._on_relocation_xrefs_loaded(
        LoadedRelocationXrefs(
            path=window._current_path,
            relocation_address=0x5000,
            xrefs=(XrefInfo(0x401000, "DATA", "r--", "lea rax, [0x5000]", 0x401000, "entry0", "puts"),),
        )
    )
    qt_app.processEvents()

    assert window.relocation_xref_summary_label.text() == "1 xrefs loaded"
    assert window.relocation_xrefs_table.rowCount() == 1
    window.close()


def test_main_window_relocation_details_show_correlated_context(qt_app: QApplication) -> None:
    window = MainWindow()
    window._functions = (FunctionInfo("puts", 0x401000, 32, 8, "sym", "puts();"),)
    window._imports = (ImportInfo("puts", "GLOBAL", "FUNC", 0x4030),)

    window._update_relocation_details(RelocationInfo("puts", 0x5000, 0x4030, "JMP_SLOT", False))
    qt_app.processEvents()

    assert "puts @" in window.relocation_function_label.text()
    assert window.relocation_import_label.text() == "puts"
    window.close()


def test_main_window_symbol_filtering(qt_app: QApplication) -> None:
    window = MainWindow()
    window._current_image = BinaryImage(
        path=Path("/tmp/sample.bin"),
        arch_size=64,
        target="elf64-x86-64",
        file_format="ELF",
        sections=(),
    )
    window._populate_symbols_table(
        (
            SymbolInfo("_Z3foov", "foo()", 0x4100, "T", 16, False),
            SymbolInfo("puts@GLIBC_2.2.5", "puts@GLIBC_2.2.5", 0x0, "U", 0, True),
        )
    )
    window._set_loaded_state(True)
    qt_app.processEvents()
    window.symbol_filter_input.setText("foo()")
    qt_app.processEvents()

    visible_rows = [
        row for row in range(window.symbols_table.rowCount()) if not window.symbols_table.isRowHidden(row)
    ]
    assert len(visible_rows) == 1
    assert window.symbols_table.item(visible_rows[0], 1).text() == "foo()"
    assert window.symbol_count_label.text() == "1 shown"
    window.close()


def test_main_window_navigate_export_falls_back_to_name_match(qt_app: QApplication) -> None:
    window = MainWindow()
    function = FunctionInfo("export_alpha", 0x4100, 32, 6, "sym", "export_alpha();")
    window._functions = (function,)
    window._populate_functions_table((function,))
    window._populate_exports_table((ExportInfo("export_alpha", 0x9000, 16, "FUNC", "GLOBAL"),))
    window._set_loaded_state(True)
    window.exports_table.selectRow(0)
    qt_app.processEvents()

    window._navigate_selected_export()
    qt_app.processEvents()

    assert window.functions_table.currentRow() == 0
    window.close()


def test_main_window_navigate_relocation_falls_back_to_import_name(qt_app: QApplication) -> None:
    window = MainWindow()
    imp = ImportInfo("puts", "GLOBAL", "FUNC", 0x4030)
    window._imports = (imp,)
    window._populate_imports_table((imp,))
    window._populate_relocations_table((RelocationInfo("puts", 0x5000, 0x0, "JMP_SLOT", False),))
    window._set_loaded_state(True)
    window.relocations_table.selectRow(0)
    qt_app.processEvents()

    window._navigate_selected_relocation()
    qt_app.processEvents()

    assert window.imports_table.currentRow() == 0
    window.close()


def test_main_window_navigate_export_xref_selects_function(qt_app: QApplication) -> None:
    window = MainWindow()
    function = FunctionInfo("main", 0x5000, 32, 6, "sym", "main();")
    window._functions = (function,)
    window._populate_functions_table((function,))
    window.export_xrefs_table.setRowCount(1)
    item = window.export_xrefs_table.item(0, 0)
    if item is None:
        from PySide6.QtWidgets import QTableWidgetItem

        values = ("0x5000", "main", "CODE", "call 0x4100")
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setData(
                256,
                XrefInfo(0x5000, "CODE", "r-x", "call 0x4100", 0x5000, "main", "export_alpha"),
            )
            window.export_xrefs_table.setItem(0, column, item)
    window.export_xrefs_table.selectRow(0)
    window._set_loaded_state(True)
    qt_app.processEvents()

    window._navigate_selected_export_xref()
    qt_app.processEvents()

    assert window.functions_table.currentRow() == 0
    window.close()


def test_main_window_starts_binary_report_worker_for_pe_images(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    image = BinaryImage(
        path=Path("/tmp/sample.exe"),
        arch_size=64,
        target="pei-x86-64",
        file_format="PE/COFF",
        sections=(),
    )
    started_workers: list[object] = []
    monkeypatch.setattr(window._thread_pool, "start", lambda worker: started_workers.append(worker))
    window._current_path = image.path

    window._on_image_loaded(LoadedImage(path=image.path, image=image))
    qt_app.processEvents()

    assert any(worker.__class__.__name__ == "SymbolListWorker" for worker in started_workers)
    assert any(worker.__class__.__name__ == "BinaryReportWorker" for worker in started_workers)
    assert any(worker.__class__.__name__ == "ExportListWorker" for worker in started_workers)
    assert any(worker.__class__.__name__ == "RelocationListWorker" for worker in started_workers)
    assert window.symbols_table.isEnabled()
    assert window.format_value.text() == "PE/COFF"
    assert "Loading PE/COFF metadata" in window.elf_summary_label.text()
    window.close()


def test_main_window_loads_binary_report(qt_app: QApplication) -> None:
    window = MainWindow()
    report = BinaryMetadataReport(
        path=Path("/tmp/sample.exe"),
        summary="pe | x86 64-bit | 5 sections | 1 entrypoints | 7 imports",
        text="Format: pe\nSections (5)\nEntrypoints (1)\nImports (7)\n",
        libraries=("KERNEL32.dll", "USER32.dll"),
    )
    window._current_path = report.path

    window._on_binary_report_loaded(LoadedBinaryReport(path=report.path, report=report))
    qt_app.processEvents()

    assert window.elf_summary_label.text() == report.summary
    assert "Entrypoints (1)" in window.elf_report_view.toPlainText()
    assert window.library_summary_label.text() == "2 linked libraries"
    assert window.libraries_table.rowCount() == 2
    window.close()


def test_main_window_function_metadata_skips_source_lookup_for_non_elf(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    window._current_path = Path("/tmp/sample.exe")
    window._current_image = BinaryImage(
        path=window._current_path,
        arch_size=64,
        target="pei-x86-64",
        file_format="PE/COFF",
        sections=(),
    )
    started_workers: list[object] = []
    monkeypatch.setattr(window._thread_pool, "start", lambda worker: started_workers.append(worker))
    window._populate_functions_table((FunctionInfo("entry0", 0x401000, 32, 12, "sym", "entry0();"),))
    window._set_loaded_state(True)

    window.functions_table.selectRow(0)
    qt_app.processEvents()

    metadata_worker = next(worker for worker in started_workers if isinstance(worker, AddressMetadataWorker))
    assert metadata_worker.include_source_lookup is False
    assert window.function_source_value.text() == "Unavailable for PE/COFF binaries"
    window.close()


def test_main_window_export_handles_filesystem_errors(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    window._current_path = Path("/bin/ls")
    window._selected_section = ".text"
    window._selected_section_bytes = b"\x90\xC3"
    errors: list[tuple[str, str]] = []

    monkeypatch.setattr("src.gui.QFileDialog.getSaveFileName", lambda *args: ("/root/forbidden.bin", ""))
    monkeypatch.setattr(
        "src.gui.QMessageBox.critical",
        lambda _parent, title, message: errors.append((title, message)),
    )
    monkeypatch.setattr(
        Path,
        "write_bytes",
        lambda self, data: (_ for _ in ()).throw(PermissionError("permission denied")),
    )

    window.export_selected_section()
    qt_app.processEvents()

    assert errors == [("Export Error", "failed to export .text to /root/forbidden.bin: permission denied")]
    assert "failed to export .text to /root/forbidden.bin: permission denied" in window.console.toPlainText()
    window.close()


def test_main_window_console_logs_messages(qt_app: QApplication) -> None:
    window = MainWindow()
    window._log_message("test message")
    qt_app.processEvents()

    assert "test message" in window.console.toPlainText()
    window.close()


def test_main_window_launch_codex_terminal_logs_launch(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    monkeypatch.setattr("src.gui._terminal_command", lambda: "/usr/bin/x-terminal-emulator")
    monkeypatch.setattr(
        "src.gui.shutil.which",
        lambda name: "/home/gary/.local/npm/bin/codex" if name == "codex" else f"/usr/bin/{name}",
    )
    monkeypatch.setattr("src.gui.QProcess.startDetached", lambda *args: (True, 1234))

    window.launch_codex_terminal()
    qt_app.processEvents()

    assert "Launched codex in external terminal" in window.console.toPlainText()
    window.close()


def test_main_window_launch_gdb_terminal_logs_launch(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    window._current_path = Path("/bin/ls")
    monkeypatch.setattr("src.gui._terminal_command", lambda: "/usr/bin/x-terminal-emulator")
    monkeypatch.setattr(
        "src.gui.shutil.which",
        lambda name: "/usr/bin/gdb" if name == "gdb" else f"/usr/bin/{name}",
    )
    monkeypatch.setattr("src.gui.QProcess.startDetached", lambda *args: (True, 1234))

    window.launch_gdb_terminal()
    qt_app.processEvents()

    assert "Launched gdb for ls in external terminal" in window.console.toPlainText()
    window.close()


def test_main_window_show_error_uses_error_title(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    errors: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "src.gui.QMessageBox.critical",
        lambda _parent, title, message: errors.append((title, message)),
    )

    window._show_error(ErrorInfo(title="GNU Toolchain Error", message="nm failed"))
    qt_app.processEvents()

    assert errors == [("GNU Toolchain Error", "nm failed")]
    window.close()


def test_radare2_close_suppresses_quit_failures() -> None:
    class BrokenR2:
        def quit(self) -> None:
            raise RuntimeError("broken pipe")

    disassembler = Radare2Disassembler("/bin/ls")
    disassembler._r2 = BrokenR2()

    disassembler.close()

    assert disassembler._r2 is None
