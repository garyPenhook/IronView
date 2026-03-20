import json
import shutil
import subprocess
from pathlib import Path

import pytest
from PySide6.QtCore import Qt, QUrl
from PySide6.QtWidgets import QApplication, QTableWidgetItem

import src.binary_loader
import src.gnu_toolchain
from src.binary_loader import BinaryImage, BinaryLoader, BinaryLoaderError
from src.disassembler import (
    BinaryMetadataReport,
    ControlFlowBlock,
    ControlFlowEdge,
    DecompilationAnnotation,
    DecompilationInlineLink,
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
    format_function_decompilation_html,
    format_function_disassembly,
    format_function_disassembly_html,
)
from src.gnu_toolchain import GnuToolchain, GnuToolchainError, SymbolInfo
from src.gui import (
    AddressMetadataWorker,
    DARK_THEME,
    ErrorInfo,
    FunctionDecompilationWorker,
    HllCallItem,
    HllContextItem,
    HllDeclarationSummary,
    LIGHT_THEME,
    LoadedBinaryReport,
    LoadedExportXrefs,
    LoadedImage,
    LoadedFunctionDecompilation,
    LoadedRelocationXrefs,
    MainWindow,
    _build_hll_inline_links,
    _build_export_path,
    _correlate_function_decompilation_context,
    _extract_hll_calls,
    _find_cfg_block_address,
    _matches_section_filter,
    _parse_decompilation_arguments,
    _parse_decompilation_locals,
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
    assert any("Only the built-in pdc backend is installed" in warning for warning in result.warnings)
    assert fake_r2.commands == ["pdg?", "pdd?", "pdc?", "pdc @ 4198400"]


def test_radare2_decompile_function_simplifies_import_thunk_pdc_output() -> None:
    class FakeR2:
        def __init__(self) -> None:
            self.commands: list[str] = []

        def cmd(self, command: str) -> str:
            self.commands.append(command)
            responses = {
                "pdg?": "You need to install the plugin with r2pm -ci r2ghidra",
                "pdd?": "You need to install the plugin with r2pm -ci r2dec",
                "pdc?": "Usage: pdc pseudo decompile function",
                "pdc @ 8336": (
                    "// callconv: rax amd64 (rdi, rsi, rdx, rcx, r8, r9);\n"
                    "ssize_t read (int fildes, void *buf, size_t nbyte) {\n"
                    "    loc_0x00002090:\n"
                    "        goto loc_qword [reloc.read]\n"
                    "        return rax;\n"
                    "}"
                ),
            }
            return responses[command]

        def cmdj(self, command: str) -> dict[str, object]:
            assert command == "pdcj @ 8336"
            return {}

    function = FunctionInfo("read", 0x2090, 0x10, 2, "sym", "ssize_t read(int fildes, void *buf, size_t nbyte);")
    disassembler = Radare2Disassembler("/bin/ls")
    fake_r2 = FakeR2()
    disassembler._r2 = fake_r2
    disassembler._architecture = "x86"
    disassembler._bits = 64

    result = disassembler.decompile_function(function)

    assert result.backend == "pdc"
    assert "return import.read(fildes, buf, nbyte);" in result.text
    assert "goto loc_qword" not in result.text
    assert any("thunk/import wrapper" in warning for warning in result.warnings)


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


def test_function_decompilation_html_renders_navigation_links() -> None:
    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdc",
        backend_display_name="radare2 pseudo (pdc)",
        text="int main(void) {\n    return 0;\n}",
        line_mappings=(
            DecompilationLineMapping(line_number=2, start=17, end=31, addresses=(0x401004,)),
        ),
    )

    rendered = format_function_decompilation_html(result)

    assert "nav://0x401004" in rendered
    assert "0002" in rendered


def test_function_decompilation_html_hides_inline_multi_address_noise() -> None:
    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text="value = 1;",
        line_mappings=(
            DecompilationLineMapping(line_number=1, start=0, end=10, addresses=(0x401000, 0x401004, 0x401008)),
        ),
    )

    rendered = format_function_decompilation_html(result)

    assert 'title="0x401000, 0x401004, 0x401008"' in rendered
    assert "[1:" not in rendered


def test_function_decompilation_html_cleans_plugin_noise_for_display() -> None:
    function = FunctionInfo("entry.init2", 0x13EAB0, 0x40, 6, "sym", "void entry.init2(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text=(
            "// callconv: rax amd64 (rdi, rsi);\n"
            "void entry.init2(void)\n"
            "{\n"
            "    if (*0x5ec170 == '\\0') {\n"
            "        sym.imp.__cxa_atexit(0x15a990,0x5ec170,0x5ec000);\n"
            "    }\n"
            "    //WARNING: Could not recover jumptable\n"
            "    return;\n"
            "}\n"
        ),
    )

    rendered = format_function_decompilation_html(result)

    assert "//WARNING:" not in rendered
    assert "callconv" not in rendered
    assert "import.__cxa_atexit" in rendered
    assert "g_5EC170" in rendered
    assert "0x5ec000" in rendered


def test_function_decompilation_html_can_render_raw_backend_output() -> None:
    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text="// callconv: rax amd64\nsym.imp.printf('x');\nif (*0x5ec170 == '\\0') {\n}\n",
    )

    rendered = format_function_decompilation_html(result, clean=False)

    assert "callconv" in rendered
    assert "sym.imp.printf" in rendered
    assert "0x5ec170" in rendered


def test_function_decompilation_html_collapses_import_thunk_wrappers() -> None:
    function = FunctionInfo(
        "import.__snprintf_chk",
        0xEC64E8,
        0x20,
        2,
        "sym",
        "void import.__snprintf_chk(char *s,size_t maxlen,int flag,size_t slen,char *format);",
    )
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text=(
            "void import.__snprintf_chk(char *s,size_t maxlen,int flag,size_t slen,char *format)\n"
            "{\n"
            "    (*g_EC64E8)();\n"
            "    return;\n"
            "}\n"
        ),
    )

    rendered = format_function_decompilation_html(result)

    assert "(*g_EC64E8)();" not in rendered
    assert "/* import thunk */" in rendered
    assert "return import.__snprintf_chk(s, maxlen, flag, slen, format);" in rendered


def test_function_decompilation_html_collapses_import_thunk_using_header_name() -> None:
    function = FunctionInfo(
        "sym.imp.as_system_info_get_modaliases",
        0x22050,
        0x20,
        2,
        "sym",
        "void import.as_system_info_get_modaliases(void);",
    )
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text=(
            "void import.as_system_info_get_modaliases(void)\n"
            "{\n"
            "    (*g_22050)();\n"
            "    return;\n"
            "}\n"
        ),
    )

    rendered = format_function_decompilation_html(result)

    assert "(*g_22050)();" not in rendered
    assert "import.as_system_info_get_modaliases();" in rendered


def test_function_decompilation_html_collapses_cpp_atexit_registration_sequence() -> None:
    function = FunctionInfo("entry.init2", 0x13EAB0, 0x40, 6, "sym", "void entry.init2(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text=(
            "void entry.init2(void)\n"
            "{\n"
            "    if (g_5EC170 == 0) {\n"
            "        g_5EC170 = 1;\n"
            "        g_5EC198 = import.operator_new_unsigned_long_(8);\n"
            "        *g_5EC198 = 0x5aecb0;\n"
            "        import.__cxa_atexit(0x15a990,g_5EC198,0x5ec000);\n"
            "    }\n"
            "}\n"
        ),
    )

    rendered = format_function_decompilation_html(result)

    assert "import.operator_new_unsigned_long_" not in rendered
    assert "import.__cxa_atexit" not in rendered
    assert "g_5EC198 = register_atexit_object(0x5aecb0, 0x15a990, 0x5ec000); /* simplified */" in rendered


def test_function_decompilation_html_collapses_fini_teardown_sequence() -> None:
    function = FunctionInfo("entry.fini0", 0x1400, 0x30, 6, "sym", "void entry.fini0(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text=(
            "void entry.fini0(void)\n"
            "{\n"
            "    if (*0x40b0 == 0) {\n"
            "        if (*0x3fd8 != 0) {\n"
            "            import.__cxa_finalize(*0x40a8);\n"
            "        }\n"
            "        fcn.00001420();\n"
            "        *0x40b0 = 1;\n"
            "        return;\n"
            "    }\n"
            "    return;\n"
            "}\n"
        ),
    )

    rendered = format_function_decompilation_html(result)

    assert "import.__cxa_finalize" not in rendered
    assert "fcn.00001420();" not in rendered
    assert "if (g_40B0 == 0) {" in rendered
    assert "finalize_module(g_40A8, fcn.00001420, g_3FD8); /* simplified */" in rendered
    assert "g_40B0 = 1;" in rendered


def test_function_decompilation_html_cleans_stack_canary_and_code_labels() -> None:
    function = FunctionInfo("main", 0x5800, 0x80, 10, "sym", "uint8_t main(int argc,char **argv);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text=(
            "uint8_t main(int argc,char **argv)\n"
            "{\n"
            "    int64_t in_FS_OFFSET;\n"
            "    int64_t iStack_20;\n"
            "    iStack_20 = *(in_FS_OFFSET + 0x28);\n"
            "    if (g_B768 == 1) {\n"
            "        goto code_r0x000058ea;\n"
            "    }\n"
            "code_r0x000058ea:\n"
            "    if (*(in_FS_OFFSET + 0x28) != iStack_20) {\n"
            "        import.__stack_chk_fail();\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        ),
    )

    rendered = format_function_decompilation_html(result)

    assert "in_FS_OFFSET" not in rendered
    assert "iStack_20" not in rendered
    assert "code_r0x000058ea" not in rendered
    assert "check_stack_canary(); /* simplified */" in rendered
    assert "return 0;" in rendered


def test_function_decompilation_html_collapses_temp_declarations_and_return_style_canary() -> None:
    function = FunctionInfo("main", 0x5800, 0x80, 10, "sym", "uchar main(int argc,char **argv);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text=(
            "uchar main(int argc,char **argv)\n"
            "{\n"
            "    char *pcVar1;\n"
            "    int iVar2;\n"
            "    ulong uVar3;\n"
            "    int64_t iStack_20;\n"
            "    uchar uVar11;\n"
            "    iStack_20 = *(in_FS_OFFSET + 0x28);\n"
            "    uVar11 = 0;\n"
            "    if (iStack_20 == *(in_FS_OFFSET + 0x28)) {\n"
            "        return uVar11;\n"
            "    }\n"
            "    import.__stack_chk_fail();\n"
            "}\n"
        ),
    )

    rendered = format_function_decompilation_html(result)

    assert "pcVar1" not in rendered
    assert "iVar2" not in rendered
    assert "uVar3" not in rendered
    assert "1 temporaries omitted" in rendered
    assert "check_stack_canary(); /* simplified */" in rendered
    assert "return uVar11;" in rendered
    assert "__stack_chk_fail" not in rendered


def test_function_decompilation_html_renders_inline_context_links() -> None:
    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdc",
        text='sym.imp.printf("usage");',
    )

    rendered = format_function_decompilation_html(
        result,
        inline_links=(
            DecompilationInlineLink("sym.imp.printf", "ctx://import/printf", "Import: printf"),
            DecompilationInlineLink("usage", "ctx://string/0x404000", "String: usage"),
        ),
    )

    assert "ctx://import/printf" in rendered
    assert "ctx://string/0x404000" in rendered


def test_correlate_function_decompilation_context_finds_loaded_entities() -> None:
    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdc",
        text=(
            'int main(void) {\n'
            '    sym.imp.printf("usage");\n'
            '    helper();\n'
            '    return exported_symbol;\n'
            '}\n'
        ),
    )

    contexts = _correlate_function_decompilation_context(
        result,
        functions=(function, FunctionInfo("helper", 0x402000, 0x10, 1, "sym", "helper();")),
        imports=(ImportInfo("printf", "GLOBAL", "FUNC", 0x403000),),
        strings=(StringInfo("usage", 0x404000, 5, 5, ".rodata", "ascii"),),
        symbols=(SymbolInfo("exported_symbol", "exported_symbol", 0x405000, "OBJ", 8, False),),
    )

    assert [(context.kind, context.name, context.detail, context.address) for context in contexts] == [
        ("Function", "helper", "0x402000", 0x402000),
        ("Import", "printf", "0x403000", 0x403000),
        ("String", "usage", "0x404000", 0x404000),
        ("Symbol", "exported_symbol", "0x405000", 0x405000),
    ]
    assert "helper" in contexts[0].match_names
    assert "import.printf" in contexts[1].match_names
    assert "sym.imp.printf" in contexts[1].match_names


def test_build_hll_inline_links_renders_context_targets() -> None:
    links = _build_hll_inline_links(
        (
            HllContextItem("Import", "printf", "0x403000", 0x403000, ("printf", "sym.imp.printf")),
            HllContextItem("Function", "helper", "0x402000", 0x402000, ("helper",)),
        )
    )

    assert any(link.href == "ctx://import/printf" and link.match_text == "sym.imp.printf" for link in links)
    assert any(link.href == "ctx://function/0x402000" and link.match_text == "helper" for link in links)


def test_parse_decompilation_arguments_and_locals() -> None:
    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(int argc, char **argv);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdc",
        text=(
            "int main(int argc, char **argv) {\n"
            "    char *buffer;\n"
            "    int status = 0;\n"
            "    return status;\n"
            "}\n"
        ),
    )

    assert _parse_decompilation_arguments(result) == ("argc", "argv")
    assert _parse_decompilation_locals(result) == ("buffer", "status")


def test_parse_decompilation_arguments_and_locals_prefers_structured_json() -> None:
    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text="int main(void) {\n    return 0;\n}\n",
        raw_json={
            "args": [{"name": "argc"}, {"name": "argv"}],
            "locals": [{"name": "buffer"}, {"name": "status"}],
        },
    )

    assert _parse_decompilation_arguments(result) == ("argc", "argv")
    assert _parse_decompilation_locals(result) == ("buffer", "status")


def test_extract_hll_calls_summarizes_known_targets() -> None:
    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdc",
        text=(
            "sym.imp.printf(\"usage\");\n"
            "helper();\n"
            "helper();\n"
            "exported_symbol();\n"
        ),
    )
    contexts = (
        HllContextItem("Function", "helper", "0x402000", 0x402000, ("helper",)),
        HllContextItem("Import", "printf", "0x403000", 0x403000, ("printf", "sym.imp.printf")),
        HllContextItem("Symbol", "exported_symbol", "0x405000", 0x405000, ("exported_symbol",)),
    )

    calls = _extract_hll_calls(result, contexts=contexts)

    assert calls == (
        HllCallItem("Import", "printf", 1, "0x403000", 0x403000),
        HllCallItem("Function", "helper", 2, "0x402000", 0x402000),
        HllCallItem("Symbol", "exported_symbol", 1, "0x405000", 0x405000),
    )


def test_extract_hll_calls_prefers_structured_json() -> None:
    function = FunctionInfo("main", 0x401000, 0x20, 2, "sym", "int main(void);")
    result = FunctionDecompilationResult(
        path=Path("/tmp/sample.bin"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        text="printf();\nhelper();\n",
        raw_json={
            "calls": [
                {"name": "sym.imp.printf", "count": 3},
                {"name": "helper", "count": 2},
            ]
        },
    )
    contexts = (
        HllContextItem("Function", "helper", "0x402000", 0x402000, ("helper",)),
        HllContextItem("Import", "printf", "0x403000", 0x403000, ("printf", "sym.imp.printf")),
    )

    calls = _extract_hll_calls(result, contexts=contexts)

    assert calls == (
        HllCallItem("Import", "printf", 3, "0x403000", 0x403000),
        HllCallItem("Function", "helper", 2, "0x402000", 0x402000),
    )


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
            requested_backend=None,
            result=result,
        )
    )
    qt_app.processEvents()

    assert "radare2 pseudo (pdc) HLL-style decompilation" in window.function_decompilation_summary.text()
    assert "Fallback backend in use." in window.function_decompilation_summary.text()
    assert "1 correlated lines." in window.function_decompilation_summary.text()
    assert "return 0;" in window.function_decompilation_preview.toPlainText()
    window.close()


def test_main_window_load_selected_function_decompilation_uses_selected_backend(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    function = FunctionInfo("main", 0x401000, 0x30, 3, "sym", "int main(void);")
    window._current_path = Path("/bin/ls")
    window.function_decompilation_backend_selector.setCurrentIndex(2)
    started: list[FunctionDecompilationWorker] = []

    def capture_start(worker: object) -> None:
        if isinstance(worker, FunctionDecompilationWorker):
            started.append(worker)

    monkeypatch.setattr(window._thread_pool, "start", capture_start)

    window._load_selected_function_decompilation(function)
    qt_app.processEvents()

    assert started
    assert started[0].backend == "pdd"
    assert "using pdd" in window.function_decompilation_summary.text()
    window.close()


def test_main_window_can_toggle_clean_hll_rendering(qt_app: QApplication) -> None:
    window = MainWindow()
    function = FunctionInfo("main", 0x401000, 0x30, 3, "sym", "int main(void);")
    result = FunctionDecompilationResult(
        path=Path("/bin/ls"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdg",
        backend_display_name="r2ghidra (pdg)",
        text="sym.imp.printf(\"x\");\nif (*0x5ec170 == '\\0') {\n    *0x5ec170 = '\\x01';\n}\n",
    )
    window._current_path = Path("/bin/ls")
    window._selected_function_address = function.address

    window._on_function_decompilation_loaded(
        LoadedFunctionDecompilation(
            path=Path("/bin/ls"),
            function_address=function.address,
            requested_backend=None,
            result=result,
        )
    )
    qt_app.processEvents()

    cleaned = window.function_decompilation_preview.toPlainText()
    assert "import.printf" in cleaned
    assert "g_5EC170 == 0" in cleaned
    assert "g_5EC170 = 1" in cleaned

    window.function_decompilation_clean_toggle.setChecked(False)
    qt_app.processEvents()

    raw = window.function_decompilation_preview.toPlainText()
    assert "sym.imp.printf" in raw
    assert "*0x5ec170 == '\\0'" in raw
    assert "*0x5ec170 = '\\x01'" in raw
    window.close()


def test_main_window_direct_function_selection_defaults_to_hll(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    function = FunctionInfo("main", 0x401000, 0x30, 3, "sym", "int main(void);")
    window._current_path = Path("/bin/ls")
    window._populate_functions_table((function,))
    monkeypatch.setattr(window._thread_pool, "start", lambda _worker: None)

    window.functions_table.selectRow(0)
    window._on_function_selection_changed()
    qt_app.processEvents()

    assert window.function_preview_tabs.currentIndex() == 1
    assert window.function_decompilation_insights_tabs.count() == 3
    window.close()


def test_main_window_navigation_selection_keeps_disassembly_active(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    function = FunctionInfo("main", 0x401000, 0x30, 3, "sym", "int main(void);")
    window._current_path = Path("/bin/ls")
    window._populate_functions_table((function,))
    window._pending_function_scroll_address = 0x401004
    monkeypatch.setattr(window._thread_pool, "start", lambda _worker: None)

    window.functions_table.selectRow(0)
    window._on_function_selection_changed()
    qt_app.processEvents()

    assert window.function_preview_tabs.currentIndex() == 0
    window.close()


def test_main_window_can_toggle_browser_pane(qt_app: QApplication) -> None:
    window = MainWindow()
    window.show()
    qt_app.processEvents()

    window.toggle_browser_action.trigger()
    qt_app.processEvents()
    collapsed_sizes = window.left_splitter.sizes()

    assert not window.toggle_browser_action.isChecked()
    assert collapsed_sizes[1] == 0

    window.toggle_browser_action.trigger()
    qt_app.processEvents()
    restored_sizes = window.left_splitter.sizes()

    assert window.toggle_browser_action.isChecked()
    assert restored_sizes[1] > 0
    window.close()


def test_main_window_can_toggle_console_pane(qt_app: QApplication) -> None:
    window = MainWindow()
    window.show()
    qt_app.processEvents()

    window.toggle_console_action.trigger()
    qt_app.processEvents()
    collapsed_sizes = window.body_splitter.sizes()

    assert not window.toggle_console_action.isChecked()
    assert collapsed_sizes[1] == 0

    window.toggle_console_action.trigger()
    qt_app.processEvents()
    restored_sizes = window.body_splitter.sizes()

    assert window.toggle_console_action.isChecked()
    assert restored_sizes[1] > 0
    window.close()


def test_main_window_navigate_function_decompilation_target_switches_to_disassembly(
    qt_app: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = MainWindow()
    function = FunctionInfo("main", 0x401000, 0x30, 3, "sym", "int main(void);")
    window._current_function_disassembly = FunctionDisassemblyResult(
        path=Path("/bin/ls"),
        function=function,
        architecture="x86",
        bits=64,
        instructions=(
            DisassembledInstruction(
                address=0x401004,
                size=3,
                bytes_hex="31 C0",
                text="xor eax, eax",
            ),
        ),
    )
    window.function_preview_tabs.setCurrentIndex(1)
    monkeypatch.setattr(window, "_parse_navigation_target", lambda _url: 0x401004)

    window._navigate_function_decompilation_target(QUrl("nav://0x401004"))
    qt_app.processEvents()

    assert window.function_preview_tabs.currentIndex() == 0
    window.close()


def test_main_window_navigate_function_decompilation_target_import_context(
    qt_app: QApplication,
) -> None:
    window = MainWindow()
    window._populate_imports_table((ImportInfo("printf", "GLOBAL", "FUNC", 0x403000),))

    window._navigate_function_decompilation_target(QUrl("ctx://import/printf"))
    qt_app.processEvents()

    assert window.details_tabs.currentIndex() == 3
    assert window.imports_table.currentRow() == 0
    window.close()


def test_main_window_loads_function_decompilation_context(qt_app: QApplication) -> None:
    window = MainWindow()
    function = FunctionInfo("main", 0x401000, 0x30, 3, "sym", "int main(int argc, char **argv);")
    helper = FunctionInfo("helper", 0x402000, 0x10, 1, "sym", "helper();")
    window._functions = (function, helper)
    window._imports = (ImportInfo("printf", "GLOBAL", "FUNC", 0x403000),)
    window._strings = (StringInfo("usage", 0x404000, 5, 5, ".rodata", "ascii"),)
    window._symbols = (SymbolInfo("exported_symbol", "exported_symbol", 0x405000, "OBJ", 8, False),)
    result = FunctionDecompilationResult(
        path=Path("/bin/ls"),
        function=function,
        architecture="x86",
        bits=64,
        backend="pdc",
        backend_display_name="radare2 pseudo (pdc)",
        text='int main(int argc, char **argv) {\n    int status = 0;\n    sym.imp.printf("usage");\n    helper();\n    return exported_symbol;\n}',
    )
    window._current_path = Path("/bin/ls")
    window._selected_function_address = function.address

    window._on_function_decompilation_loaded(
        LoadedFunctionDecompilation(
            path=Path("/bin/ls"),
            function_address=function.address,
            requested_backend=None,
            result=result,
        )
    )
    qt_app.processEvents()

    assert window.function_decompilation_context_table.rowCount() == 4
    assert window.function_decompilation_calls_table.rowCount() == 2
    assert window.function_decompilation_calls_summary.text() == "2 summarized call targets."
    assert window.function_decompilation_context_summary.text() == "4 correlated context items."
    assert "Args: argc, argv" in window.function_decompilation_declarations_value.text()
    assert "Locals: status" in window.function_decompilation_declarations_value.text()
    html = window.function_decompilation_preview.toHtml()
    assert "ctx://import/printf" in html
    assert "ctx://string/0x404000" in html
    kinds = {
        window.function_decompilation_context_table.item(row, 0).text()
        for row in range(window.function_decompilation_context_table.rowCount())
    }
    assert kinds == {"Function", "Import", "String", "Symbol"}
    window.close()


def test_main_window_navigate_function_decompilation_context_import(
    qt_app: QApplication,
) -> None:
    window = MainWindow()
    window._populate_imports_table((ImportInfo("printf", "GLOBAL", "FUNC", 0x403000),))
    window.function_decompilation_context_table.setRowCount(1)
    for column, value in enumerate(("Import", "printf", "0x403000")):
        item = QTableWidgetItem(value)
        item.setData(Qt.ItemDataRole.UserRole, HllContextItem("Import", "printf", "0x403000", 0x403000))
        window.function_decompilation_context_table.setItem(0, column, item)
    window.function_decompilation_context_table.selectRow(0)

    window._navigate_selected_function_decompilation_context()
    qt_app.processEvents()

    assert window.details_tabs.currentIndex() == 3
    assert window.imports_table.currentRow() == 0
    window.close()


def test_main_window_navigate_function_decompilation_call_import(
    qt_app: QApplication,
) -> None:
    window = MainWindow()
    window._populate_imports_table((ImportInfo("printf", "GLOBAL", "FUNC", 0x403000),))
    window.function_decompilation_calls_table.setRowCount(1)
    for column, value in enumerate(("Import", "printf", "1", "0x403000")):
        item = QTableWidgetItem(value)
        item.setData(Qt.ItemDataRole.UserRole, HllCallItem("Import", "printf", 1, "0x403000", 0x403000))
        window.function_decompilation_calls_table.setItem(0, column, item)
    window.function_decompilation_calls_table.selectRow(0)

    window._navigate_selected_function_decompilation_call()
    qt_app.processEvents()

    assert window.details_tabs.currentIndex() == 3
    assert window.imports_table.currentRow() == 0
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
