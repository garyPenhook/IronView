import shutil
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from src.binary_loader import BinaryLoader, BinaryLoaderError
from src.disassembler import (
    DisassembledInstruction,
    DisassemblyResult,
    FunctionDisassemblyResult,
    FunctionInfo,
    ImportInfo,
    InstructionTarget,
    Radare2Disassembler,
    StringInfo,
    format_disassembly,
    format_disassembly_html,
    format_function_disassembly,
    format_function_disassembly_html,
)
from src.gnu_toolchain import GnuToolchain, SymbolInfo
from src.gui import DARK_THEME, LIGHT_THEME, MainWindow, _build_export_path, _matches_section_filter
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


def test_main_window_symbol_filtering(qt_app: QApplication) -> None:
    window = MainWindow()
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
