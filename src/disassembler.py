from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any, Sequence

import r2pipe
from src.gnu_toolchain import SymbolInfo

RADARE2_FLAGS = ["-N", "-2", "-e", "scr.color=0", "-e", "bin.relocs.apply=true"]
DEFAULT_INSTRUCTION_LIMIT = 64
DECOMPILATION_BACKEND_ORDER = ("pdg", "pdd", "pdc")
DECOMPILATION_UNAVAILABLE_MARKERS = (
    "you need to install the plugin",
    "unknown command",
    "invalid command",
    "command not found",
)
DECOMPILATION_BACKEND_NAMES = {
    "pdg": "r2ghidra (pdg)",
    "pdd": "r2dec (pdd)",
    "pdc": "radare2 pseudo (pdc)",
}
THUNK_TARGET_PATTERN = re.compile(r"(?:reloc|sym\.imp)\.([A-Za-z0-9_$.@?]+)")
SIGNATURE_HEADER_PATTERN = re.compile(r"^\s*([^{]+)\{\s*$")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")
GLOBAL_DEREFERENCE_PATTERN = re.compile(r"(?P<stars>\*+)\s*0x(?P<addr>[0-9a-fA-F]{4,16})")
HEX_ADDRESS_PATTERN = re.compile(r"(?<![A-Za-z0-9_])0x(?P<addr>[0-9a-fA-F]{4,16})(?![A-Za-z0-9_])")
IMPORT_THUNK_CALL_PATTERN = re.compile(r"^\(\*+\s*g_[0-9A-F]+\)\s*\([^)]*\);\s*$")
NEW_OBJECT_PATTERN = re.compile(
    r"^(?P<indent>\s*)(?P<dest>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*import\.operator_new(?:_unsigned_long_)?\((?P<size>[^)]*)\);\s*$"
)
INIT_OBJECT_PATTERN = re.compile(
    r"^(?P<indent>\s*)\*(?P<dest>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>[^;]+);\s*$"
)
ATEXIT_PATTERN = re.compile(
    r"^(?P<indent>\s*)import\.__cxa_atexit\(\s*(?P<callback>[^,]+)\s*,\s*(?P<dest>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?P<dso>[^)]+)\);\s*$"
)
GUARD_IF_ZERO_PATTERN = re.compile(r"^(?P<indent>\s*)if\s+\((?P<guard>[A-Za-z_][A-Za-z0-9_]*)\s*==\s*0\)\s*\{\s*$")
GUARD_IF_NONZERO_PATTERN = re.compile(r"^(?P<indent>\s*)if\s+\((?P<guard>[A-Za-z_][A-Za-z0-9_]*)\s*!=\s*0\)\s*\{\s*$")
CXA_FINALIZE_PATTERN = re.compile(r"^(?P<indent>\s*)import\.__cxa_finalize\(\s*(?P<handle>[^)]+)\);\s*$")
FUNCTION_CALL_PATTERN = re.compile(r"^(?P<indent>\s*)(?P<callee>[A-Za-z_][A-Za-z0-9_.:]*)\(\);\s*$")
ASSIGN_ONE_PATTERN = re.compile(r"^(?P<indent>\s*)(?P<guard>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*1;\s*$")
CODE_LABEL_PATTERN = re.compile(r"^\s*code_r0x[0-9a-fA-F]+:\s*$")
GOTO_CODE_LABEL_PATTERN = re.compile(r"\bgoto\s+code_r0x[0-9a-fA-F]+;")
STACK_CANARY_INIT_PATTERN = re.compile(
    r"^(?P<indent>\s*)(?P<slot>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\*\(in_FS_OFFSET \+ 0x28\);\s*$"
)
STACK_CANARY_PTR_INIT_PATTERN = re.compile(
    r"^(?P<indent>\s*)\*\((?P<slot>[A-Za-z_][A-Za-z0-9_]* \+ [+-]?0x[0-9a-fA-F]+)\)\s*=\s*\*\(in_FS_OFFSET \+ 0x28\);\s*$"
)
STACK_CANARY_CHECK_PATTERN = re.compile(
    r"^(?P<indent>\s*)if\s+\(\*\(in_FS_OFFSET \+ 0x28\)\s*!=\s*(?P<slot>[A-Za-z_][A-Za-z0-9_]*)\)\s*\{\s*$"
)
STACK_CANARY_PTR_RETURN_PATTERN = re.compile(
    r"^(?P<indent>\s*)if\s+\(\*\((?P<slot>[A-Za-z_][A-Za-z0-9_]* \+ [+-]?0x[0-9a-fA-F]+)\)\s*==\s*\*\(in_FS_OFFSET \+ 0x28\)\)\s*\{\s*$"
)
STACK_FAIL_PATTERN = re.compile(r"^\s*import\.__stack_chk_fail\(\);\s*$")
DECLARATION_NAME_PATTERN = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_:<>]*[\s\*\[\]]+)+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*$"
)
STACK_CANARY_RETURN_PATTERN = re.compile(
    r"^(?P<indent>\s*)if\s+\((?P<slot>[A-Za-z_][A-Za-z0-9_]*)\s*==\s*\*\(in_FS_OFFSET \+ 0x28\)\)\s*\{\s*$"
)
RETURN_VALUE_PATTERN = re.compile(r"^(?P<indent>\s*)return\b.*;\s*$")
TEMP_LOCAL_NAME_PATTERN = re.compile(
    r"^(?:"
    r"(?:pc|ppc|pu|pi|pb|psz|ps|p|i|u|b|c|au|ai|f)d?Var\d+"
    r"|(?:pc|u|i|ai|au|f|b)Stack_[0-9A-Fa-f]+"
    r"|in_[A-Z0-9]+"
    r"|in_FS_OFFSET"
    r")$"
)
CONCAT_REGISTER_ARG_PATTERN = re.compile(
    r"\bCONCAT\d+\(\s*in_[A-Z0-9]+\s*,\s*(?P<argument>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
STACK_PROBE_INIT_PATTERN = re.compile(
    r"^(?P<indent>\s*)(?P<ptr>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*&stack0x[0-9a-fA-F]+;\s*$"
)
STACK_PROBE_COPY_PATTERN = re.compile(
    r"^(?P<indent>\s*)(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<src>[A-Za-z_][A-Za-z0-9_]*);\s*$"
)
STACK_PROBE_TOUCH_PATTERN = re.compile(
    r"^(?P<indent>\s*)\*\((?P<ptr>[A-Za-z_][A-Za-z0-9_]*) \+ -0x1000\)\s*=\s*\*\((?P=ptr) \+ -0x1000\);\s*$"
)
STACK_PROBE_STEP_PATTERN = re.compile(
    r"^(?P<indent>\s*)(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<src>[A-Za-z_][A-Za-z0-9_]*) \+ -0x1000;\s*$"
)
STACK_PROBE_WHILE_PATTERN = re.compile(
    r"^(?P<indent>\s*)\}\s*while\s+\((?P<ptr>[A-Za-z_][A-Za-z0-9_]*) \+ -0x1000 != &stack0x[0-9a-fA-F]+\);\s*$"
)
STACK_SLOT_MARKER_PATTERN = re.compile(
    r"^\s*\*\((?P<ptr>[A-Za-z_][A-Za-z0-9_]*) \+ [+-]?0x[0-9a-fA-F]+\)\s*=\s*0x[0-9a-fA-F]+;\s*$"
)


class Radare2DisassemblerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DisassembledInstruction:
    address: int
    size: int
    bytes_hex: str
    text: str
    targets: tuple["InstructionTarget", ...] = ()


@dataclass(frozen=True, slots=True)
class InstructionTarget:
    kind: str
    address: int


@dataclass(frozen=True, slots=True)
class DisassemblyResult:
    path: Path
    section_name: str
    architecture: str
    bits: int
    start_address: int
    instructions: tuple[DisassembledInstruction, ...]


@dataclass(frozen=True, slots=True)
class FunctionInfo:
    name: str
    address: int
    size: int
    instruction_count: int
    kind: str
    signature: str


@dataclass(frozen=True, slots=True)
class FunctionDisassemblyResult:
    path: Path
    function: FunctionInfo
    architecture: str
    bits: int
    instructions: tuple[DisassembledInstruction, ...]


@dataclass(frozen=True, slots=True)
class FunctionDecompilationResult:
    path: Path
    function: FunctionInfo
    architecture: str
    bits: int
    backend: str
    text: str
    requested_backend: str | None = None
    backend_display_name: str = ""
    available_backends: tuple[str, ...] = ()
    used_fallback: bool = False
    warnings: tuple[str, ...] = ()
    raw_json: dict[str, Any] | None = None
    annotations: tuple["DecompilationAnnotation", ...] = ()
    line_mappings: tuple["DecompilationLineMapping", ...] = ()


@dataclass(frozen=True, slots=True)
class DecompilationAnnotation:
    start: int
    end: int
    address: int
    kind: str


@dataclass(frozen=True, slots=True)
class DecompilationLineMapping:
    line_number: int
    start: int
    end: int
    addresses: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DecompilationInlineLink:
    match_text: str
    href: str
    title: str = ""


@dataclass(frozen=True, slots=True)
class ControlFlowBlock:
    address: int
    size: int
    instructions: tuple[DisassembledInstruction, ...]


@dataclass(frozen=True, slots=True)
class ControlFlowEdge:
    source_address: int
    target_address: int
    kind: str


@dataclass(frozen=True, slots=True)
class FunctionGraphResult:
    path: Path
    function: FunctionInfo
    architecture: str
    bits: int
    blocks: tuple[ControlFlowBlock, ...]
    edges: tuple[ControlFlowEdge, ...]


@dataclass(frozen=True, slots=True)
class StringInfo:
    value: str
    address: int
    size: int
    length: int
    section: str
    kind: str


@dataclass(frozen=True, slots=True)
class XrefInfo:
    from_address: int
    xref_type: str
    permission: str
    opcode: str
    function_address: int
    function_name: str
    reference_name: str


@dataclass(frozen=True, slots=True)
class ImportInfo:
    name: str
    bind: str
    kind: str
    plt_address: int


@dataclass(frozen=True, slots=True)
class ExportInfo:
    name: str
    address: int
    size: int
    kind: str
    bind: str


@dataclass(frozen=True, slots=True)
class RelocationInfo:
    name: str
    address: int
    symbol_address: int
    kind: str
    is_ifunc: bool


@dataclass(frozen=True, slots=True)
class BinaryMetadataReport:
    path: Path
    summary: str
    text: str
    libraries: tuple[str, ...]


def format_disassembly(result: DisassemblyResult) -> str:
    header = (
        f"{result.architecture} {result.bits}-bit",
        f"section {result.section_name}",
        f"start {_format_hex(result.start_address)}",
        f"{len(result.instructions)} instructions",
    )
    lines = [" | ".join(header), ""]
    for instruction in result.instructions:
        lines.append(
            f"{instruction.address:08X}  {instruction.bytes_hex:<20}  {instruction.text}"
        )
    return "\n".join(lines)


def format_function_disassembly(result: FunctionDisassemblyResult) -> str:
    header = (
        f"{result.architecture} {result.bits}-bit",
        result.function.name,
        f"start {_format_hex(result.function.address)}",
        f"{len(result.instructions)} instructions",
    )
    lines = [" | ".join(header), ""]
    if result.function.signature:
        lines.append(result.function.signature)
        lines.append("")
    for instruction in result.instructions:
        lines.append(
            f"{instruction.address:08X}  {instruction.bytes_hex:<20}  {instruction.text}"
        )
    return "\n".join(lines)


def format_disassembly_html(result: DisassemblyResult) -> str:
    header = (
        f"{result.architecture} {result.bits}-bit",
        f"section {result.section_name}",
        f"start {_format_hex(result.start_address)}",
        f"{len(result.instructions)} instructions",
    )
    return _format_disassembly_html_lines(header, result.instructions)


def format_function_disassembly_html(result: FunctionDisassemblyResult) -> str:
    header = (
        f"{result.architecture} {result.bits}-bit",
        result.function.name,
        f"start {_format_hex(result.function.address)}",
        f"{len(result.instructions)} instructions",
    )
    lines = [f"<div>{escape(' | '.join(header))}</div>"]
    if result.function.signature:
        lines.append(f"<div>{escape(result.function.signature)}</div>")
    lines.append("<div></div>")
    lines.extend(_format_instruction_html(instruction) for instruction in result.instructions)
    return _wrap_html(lines)


def format_function_decompilation_html(
    result: FunctionDecompilationResult,
    *,
    inline_links: Sequence[DecompilationInlineLink] = (),
    clean: bool = True,
) -> str:
    mapping_by_line = {mapping.line_number: mapping for mapping in result.line_mappings}
    rendered_lines = _clean_decompilation_lines(result.text) if clean else tuple(result.text.splitlines())
    if clean:
        rendered_lines = _collapse_temp_declaration_lines(rendered_lines)
        rendered_lines = _collapse_cpp_registration_lines(rendered_lines)
        rendered_lines = _collapse_fini_teardown_lines(rendered_lines)
        rendered_lines = _collapse_stack_probe_lines(rendered_lines)
        rendered_lines = _collapse_stack_canary_lines(rendered_lines)
        rendered_lines = _summarize_leading_declaration_block(rendered_lines)
        rendered_lines = _collapse_import_thunk_lines(result.function, rendered_lines)
    lines = []
    for line_number, line in enumerate(rendered_lines, start=1):
        mapping = mapping_by_line.get(line_number)
        line_label = f"{line_number:04d}"
        if mapping is not None and mapping.addresses:
            primary_address = mapping.addresses[0]
            title_attr = ""
            if len(mapping.addresses) > 1:
                address_summary = ", ".join(_format_hex(address) for address in mapping.addresses)
                title_attr = f' title="{escape(address_summary)}"'
            prefix = f'<a href="{_navigation_href(primary_address)}"{title_attr}>{escape(line_label)}</a>'
        else:
            prefix = escape(line_label)
        lines.append(f"<div>{prefix}  {_format_decompilation_text_html(line, inline_links)}</div>")
    if not lines:
        lines.append("<div></div>")
    return _wrap_html(lines)


def _global_alias_name(address: str) -> str:
    return f"g_{address.upper()}"


def _clean_decompilation_lines(text: str) -> tuple[str, ...]:
    alias_addresses = {
        match.group("addr").upper()
        for match in GLOBAL_DEREFERENCE_PATTERN.finditer(text)
    }
    cleaned_lines: list[str] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if (
            not stripped
            or stripped.startswith("//WARNING:")
            or stripped.startswith("// callconv:")
            or re.fullmatch(r"loc_0x[0-9a-fA-F]+:", stripped) is not None
            or CODE_LABEL_PATTERN.match(stripped) is not None
        ):
            if not stripped:
                cleaned_lines.append("")
            continue
        line = re.sub(r"\bsym\.imp\.", "import.", raw_line)
        line = re.sub(r"\bimp\.", "import.", line)
        line = re.sub(r"\bimport\.operator_new(?:_unsigned_long_)?\b", "import.operator_new", line)
        line = GOTO_CODE_LABEL_PATTERN.sub("goto exit;", line)
        line = CONCAT_REGISTER_ARG_PATTERN.sub(lambda match: match.group("argument"), line)
        line = re.sub(r"==\s*'\\0'", "== 0", line)
        line = re.sub(r"!=\s*'\\0'", "!= 0", line)
        line = re.sub(r"=\s*'\\0'", "= 0", line)
        line = re.sub(r"=\s*'\\x01'", "= 1", line)
        line = GLOBAL_DEREFERENCE_PATTERN.sub(
            lambda match: f"{'*' * max(len(match.group('stars')) - 1, 0)}{_global_alias_name(match.group('addr'))}",
            line,
        )
        if alias_addresses:
            line = HEX_ADDRESS_PATTERN.sub(
                lambda match: _global_alias_name(match.group("addr"))
                if match.group("addr").upper() in alias_addresses
                else match.group(0),
                line,
            )
        cleaned_lines.append(line)
    return tuple(cleaned_lines)


def _collapse_cpp_registration_lines(lines: Sequence[str]) -> tuple[str, ...]:
    collapsed: list[str] = []
    index = 0
    while index < len(lines):
        if index + 2 < len(lines):
            new_match = NEW_OBJECT_PATTERN.match(lines[index])
            init_match = INIT_OBJECT_PATTERN.match(lines[index + 1])
            atexit_match = ATEXIT_PATTERN.match(lines[index + 2])
            if (
                new_match is not None
                and init_match is not None
                and atexit_match is not None
                and new_match.group("dest") == init_match.group("dest") == atexit_match.group("dest")
            ):
                indent = new_match.group("indent")
                dest = new_match.group("dest")
                value = init_match.group("value").strip()
                callback = atexit_match.group("callback").strip()
                dso = atexit_match.group("dso").strip()
                collapsed.append(
                    f"{indent}{dest} = register_atexit_object({value}, {callback}, {dso}); /* simplified */"
                )
                index += 3
                continue
        collapsed.append(lines[index])
        index += 1
    return tuple(collapsed)


def _collapse_fini_teardown_lines(lines: Sequence[str]) -> tuple[str, ...]:
    collapsed: list[str] = []
    index = 0
    while index < len(lines):
        if index + 8 < len(lines):
            guard_zero = GUARD_IF_ZERO_PATTERN.match(lines[index])
            guard_nonzero = GUARD_IF_NONZERO_PATTERN.match(lines[index + 1])
            finalize = CXA_FINALIZE_PATTERN.match(lines[index + 2])
            inner_close = lines[index + 3].strip() == "}"
            fini_call = FUNCTION_CALL_PATTERN.match(lines[index + 4])
            assign_one = ASSIGN_ONE_PATTERN.match(lines[index + 5])
            early_return = lines[index + 6].strip() == "return;"
            outer_close = lines[index + 7].strip() == "}"
            final_return = lines[index + 8].strip() == "return;"
            if (
                guard_zero is not None
                and guard_nonzero is not None
                and finalize is not None
                and inner_close
                and fini_call is not None
                and assign_one is not None
                and early_return
                and outer_close
                and final_return
                and guard_zero.group("guard") == assign_one.group("guard")
            ):
                indent = guard_zero.group("indent")
                finalize_guard = guard_nonzero.group("guard")
                handle = finalize.group("handle").strip()
                callee = fini_call.group("callee").strip()
                guard = guard_zero.group("guard")
                collapsed.append(lines[index])
                collapsed.append(
                    f"{indent}    finalize_module({handle}, {callee}, {finalize_guard}); /* simplified */"
                )
                collapsed.append(lines[index + 5])
                collapsed.append(lines[index + 7])
                collapsed.append(lines[index + 8])
                index += 9
                continue
        collapsed.append(lines[index])
        index += 1
    return tuple(collapsed)


def _collapse_stack_canary_lines(lines: Sequence[str]) -> tuple[str, ...]:
    canary_slots = {
        match.group("slot")
        for line in lines
        if (match := STACK_CANARY_INIT_PATTERN.match(line)) is not None
    }
    collapsed: list[str] = []
    index = 0
    while index < len(lines):
        init_match = STACK_CANARY_INIT_PATTERN.match(lines[index])
        ptr_init_match = STACK_CANARY_PTR_INIT_PATTERN.match(lines[index])
        if init_match is not None or ptr_init_match is not None:
            index += 1
            continue
        if index + 2 < len(lines):
            check_match = STACK_CANARY_CHECK_PATTERN.match(lines[index])
            fail_match = STACK_FAIL_PATTERN.match(lines[index + 1])
            if check_match is not None and fail_match is not None and lines[index + 2].strip() == "}":
                collapsed.append(f"{check_match.group('indent')}check_stack_canary(); /* simplified */")
                index += 3
                continue
        if index + 3 < len(lines):
            stripped_line = lines[index].strip()
            return_check = STACK_CANARY_RETURN_PATTERN.match(lines[index])
            ptr_return_check = STACK_CANARY_PTR_RETURN_PATTERN.match(lines[index])
            return_line = RETURN_VALUE_PATTERN.match(lines[index + 1])
            fail_match = STACK_FAIL_PATTERN.match(lines[index + 3])
            if (
                (
                    return_check is not None
                    or ptr_return_check is not None
                    or (
                        stripped_line.startswith("if (")
                        and stripped_line.endswith("{")
                        and "in_FS_OFFSET + 0x28" in stripped_line
                        and "==" in stripped_line
                    )
                )
                and return_line is not None
                and lines[index + 2].strip() == "}"
                and fail_match is not None
            ):
                indent = (
                    return_check.group("indent")
                    if return_check is not None
                    else ptr_return_check.group("indent")
                    if ptr_return_check is not None
                    else lines[index][: len(lines[index]) - len(lines[index].lstrip())]
                )
                collapsed.append(f"{indent}check_stack_canary(); /* simplified */")
                collapsed.append(lines[index + 1])
                index += 4
                continue
        declaration_match = DECLARATION_NAME_PATTERN.match(lines[index])
        if declaration_match is not None and declaration_match.group("name") in canary_slots.union({"in_FS_OFFSET"}):
            index += 1
            continue
        collapsed.append(lines[index])
        index += 1
    return tuple(collapsed)


def _collapse_stack_probe_lines(lines: Sequence[str]) -> tuple[str, ...]:
    collapsed: list[str] = []
    index = 0
    while index < len(lines):
        if index + 4 < len(lines):
            init_match = STACK_PROBE_INIT_PATTERN.match(lines[index])
            copy_match = STACK_PROBE_COPY_PATTERN.match(lines[index + 2])
            touch_match = STACK_PROBE_TOUCH_PATTERN.match(lines[index + 3])
            step_match = STACK_PROBE_STEP_PATTERN.match(lines[index + 4])
            while_match = STACK_PROBE_WHILE_PATTERN.match(lines[index + 5]) if index + 5 < len(lines) else None
            if (
                init_match is not None
                and lines[index + 1].strip() == "do {"
                and copy_match is not None
                and touch_match is not None
                and step_match is not None
                and while_match is not None
                and copy_match.group("src") == init_match.group("ptr")
                and touch_match.group("ptr") == copy_match.group("dst")
                and step_match.group("src") == copy_match.group("dst")
                and step_match.group("dst") == init_match.group("ptr")
                and while_match.group("ptr") == copy_match.group("dst")
            ):
                collapsed.append(f"{init_match.group('indent')}/* stack probe omitted */")
                index += 6
                continue
        marker_match = STACK_SLOT_MARKER_PATTERN.match(lines[index])
        if marker_match is not None and TEMP_LOCAL_NAME_PATTERN.match(marker_match.group("ptr")) is not None:
            index += 1
            continue
        collapsed.append(lines[index])
        index += 1
    return tuple(collapsed)


def _collapse_temp_declaration_lines(lines: Sequence[str]) -> tuple[str, ...]:
    collapsed: list[str] = []
    omitted_temps = False
    inside_function_body = False
    for line in lines:
        stripped = line.strip()
        if stripped == "{":
            inside_function_body = True
            omitted_temps = False
            collapsed.append(line)
            continue
        if inside_function_body:
            declaration_match = None
            if not (
                stripped.startswith("return ")
                or stripped.startswith("if ")
                or stripped.startswith("goto ")
                or stripped.startswith("for ")
                or stripped.startswith("while ")
                or stripped.startswith("switch ")
            ):
                declaration_match = DECLARATION_NAME_PATTERN.match(line)
            if declaration_match is not None and TEMP_LOCAL_NAME_PATTERN.match(declaration_match.group("name")) is not None:
                if not omitted_temps:
                    collapsed.append("    /* temporaries omitted */")
                    omitted_temps = True
                continue
            if stripped:
                omitted_temps = False
        collapsed.append(line)
    return tuple(collapsed)


def _summarize_leading_declaration_block(lines: Sequence[str]) -> tuple[str, ...]:
    if len(lines) < 3 or lines[1].strip() != "{":
        return tuple(lines)
    preserved: list[str] = [lines[0], lines[1]]
    kept_locals: list[str] = []
    omitted_count = 0
    index = 2
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped == "/* temporaries omitted */":
            omitted_count += 1
            index += 1
            continue
        declaration_match = DECLARATION_NAME_PATTERN.match(lines[index])
        if declaration_match is None:
            break
        name = declaration_match.group("name")
        if TEMP_LOCAL_NAME_PATTERN.match(name) is not None:
            omitted_count += 1
        else:
            kept_locals.append(name)
        index += 1
    if kept_locals or omitted_count:
        parts: list[str] = []
        if kept_locals:
            visible = ", ".join(kept_locals[:6])
            if len(kept_locals) > 6:
                visible = f"{visible}, ..."
            parts.append(f"locals: {visible}")
        if omitted_count:
            parts.append(f"{omitted_count} temporaries omitted")
        preserved.append(f"    /* {'; '.join(parts)} */")
    preserved.extend(lines[index:])
    return tuple(preserved)


def _collapse_import_thunk_lines(
    function: FunctionInfo,
    lines: Sequence[str],
) -> tuple[str, ...]:
    compact_lines = [line for line in lines if line.strip()]
    if len(compact_lines) < 4:
        return tuple(lines)
    header = compact_lines[0].strip()
    stripped_name = function.name.strip()
    header_name_match = re.search(r"\b(import\.[A-Za-z_][A-Za-z0-9_$.@?:]*)\s*\(", header)
    header_name = header_name_match.group(1).strip() if header_name_match is not None else ""
    import_name = stripped_name if stripped_name.startswith("import.") else header_name
    if not import_name.startswith("import."):
        return tuple(lines)
    if compact_lines[1].strip() != "{":
        return tuple(lines)
    body_lines = [
        line.strip()
        for line in compact_lines[2:-1]
        if line.strip() and not line.strip().startswith("//")
    ]
    if compact_lines[-1].strip() != "}" or not body_lines:
        return tuple(lines)
    if len(body_lines) == 2 and body_lines[-1] == "return;" and IMPORT_THUNK_CALL_PATTERN.match(body_lines[0]):
        parameter_names = _parameter_names_from_header(header)
        arguments = ", ".join(parameter_names)
        call = f"    return {import_name}({arguments});" if arguments else f"    return {import_name}();"
        return (header, "{", "    /* import thunk */", call, "}")
    if len(body_lines) == 1 and IMPORT_THUNK_CALL_PATTERN.match(body_lines[0]):
        parameter_names = _parameter_names_from_header(header)
        arguments = ", ".join(parameter_names)
        return_type = header.split("(", 1)[0].strip().rsplit(" ", 1)[0]
        if return_type == "void":
            call = f"    {import_name}({arguments});" if arguments else f"    {import_name}();"
        else:
            call = f"    return {import_name}({arguments});" if arguments else f"    return {import_name}();"
        return (header, "{", "    /* import thunk */", call, "}")
    return tuple(lines)


def _format_decompilation_text_html(
    line: str,
    inline_links: Sequence[DecompilationInlineLink],
) -> str:
    matches: list[tuple[int, int, DecompilationInlineLink]] = []
    for link in inline_links:
        for token in _decompilation_link_tokens(link.match_text):
            if len(token) < 2:
                continue
            pattern = rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])"
            for match in re.finditer(pattern, line):
                matches.append((match.start(), match.end(), link))
    matches.sort(key=lambda item: (item[0], -(item[1] - item[0]), item[2].match_text))

    selected: list[tuple[int, int, DecompilationInlineLink]] = []
    cursor = 0
    for start, end, link in matches:
        if start < cursor:
            continue
        selected.append((start, end, link))
        cursor = end

    if not selected:
        return escape(line)

    parts: list[str] = []
    cursor = 0
    for start, end, link in selected:
        if start > cursor:
            parts.append(escape(line[cursor:start]))
        title_attr = f' title="{escape(link.title)}"' if link.title else ""
        parts.append(f'<a href="{escape(link.href)}"{title_attr}>{escape(line[start:end])}</a>')
        cursor = end
    if cursor < len(line):
        parts.append(escape(line[cursor:]))
    return "".join(parts)


def _decompilation_link_tokens(token: str) -> tuple[str, ...]:
    stripped = token.strip()
    if not stripped:
        return ()
    candidates = {
        stripped,
        stripped.removeprefix("sym.imp."),
        stripped.removeprefix("imp."),
        stripped.removeprefix("import."),
    }
    if stripped.startswith("sym.imp."):
        candidates.add(f"import.{stripped.removeprefix('sym.imp.')}")
    elif stripped.startswith("imp."):
        candidates.add(f"import.{stripped.removeprefix('imp.')}")
    return tuple(candidate for candidate in candidates if candidate)


def _format_hex(value: int) -> str:
    return f"0x{value:X}"


def _format_disassembly_html_lines(
    header: tuple[str, ...],
    instructions: tuple[DisassembledInstruction, ...],
) -> str:
    lines = [f"<div>{escape(' | '.join(header))}</div>", "<div></div>"]
    lines.extend(_format_instruction_html(instruction) for instruction in instructions)
    return _wrap_html(lines)


def _format_instruction_html(instruction: DisassembledInstruction) -> str:
    bytes_hex = escape(instruction.bytes_hex.ljust(20))
    text = escape(instruction.text)
    line = [
        f'<a id="{_anchor_name(instruction.address)}"></a>',
        f"{instruction.address:08X}  {bytes_hex}  {text}",
    ]
    if instruction.targets:
        links = " ".join(
            f'[{escape(target.kind)} <a href="{_navigation_href(target.address)}">{escape(_format_hex(target.address))}</a>]'
            for target in instruction.targets
        )
        line.append(f"  {links}")
    return f"<div>{''.join(line)}</div>"


def _navigation_href(address: int) -> str:
    return f"nav://0x{address:X}"


def _anchor_name(address: int) -> str:
    return f"addr-{address:X}"


def _wrap_html(lines: list[str]) -> str:
    body = "\n".join(lines)
    return (
        "<html><body>"
        '<div style="white-space: pre; font-family: monospace;">'
        f"{body}"
        "</div></body></html>"
    )


def _normalize_instruction_targets(raw_instruction: dict[str, Any]) -> tuple[InstructionTarget, ...]:
    targets: list[InstructionTarget] = []
    seen_addresses: set[int] = set()
    for key in ("jump", "fail", "ptr"):
        address = raw_instruction.get(key)
        if not isinstance(address, int) or address <= 0 or address in seen_addresses:
            continue
        seen_addresses.add(address)
        targets.append(InstructionTarget(kind=key, address=address))
    return tuple(targets)


def _normalize_instruction(raw_instruction: dict[str, Any]) -> DisassembledInstruction | None:
    address = raw_instruction.get("addr")
    text = raw_instruction.get("disasm")
    if not isinstance(address, int) or not isinstance(text, str):
        return None
    size = raw_instruction.get("size")
    bytes_hex = raw_instruction.get("bytes")
    return DisassembledInstruction(
        address=address,
        size=size if isinstance(size, int) else 0,
        bytes_hex=bytes_hex if isinstance(bytes_hex, str) else "",
        text=text,
        targets=_normalize_instruction_targets(raw_instruction),
    )


def _normalize_function(raw_function: dict[str, Any]) -> FunctionInfo | None:
    name = raw_function.get("name")
    address = raw_function.get("addr")
    if not isinstance(name, str) or not isinstance(address, int):
        return None
    size = raw_function.get("size")
    instruction_count = raw_function.get("ninstrs")
    kind = raw_function.get("type")
    signature = raw_function.get("signature")
    return FunctionInfo(
        name=name,
        address=address,
        size=size if isinstance(size, int) else 0,
        instruction_count=instruction_count if isinstance(instruction_count, int) else 0,
        kind=kind if isinstance(kind, str) else "unknown",
        signature=signature if isinstance(signature, str) else "",
    )


def _normalize_block(raw_block: dict[str, Any]) -> ControlFlowBlock | None:
    address = raw_block.get("addr")
    if not isinstance(address, int):
        return None
    size = raw_block.get("size")
    raw_instructions = raw_block.get("ops")
    if not isinstance(raw_instructions, list):
        raw_instructions = []
    instructions = tuple(
        instruction
        for item in raw_instructions
        if (instruction := _normalize_instruction(item)) is not None
    )
    return ControlFlowBlock(
        address=address,
        size=size if isinstance(size, int) else 0,
        instructions=instructions,
    )


def _normalize_block_edges(raw_block: dict[str, Any]) -> tuple[ControlFlowEdge, ...]:
    source_address = raw_block.get("addr")
    if not isinstance(source_address, int):
        return ()
    edges: list[ControlFlowEdge] = []
    seen: set[tuple[int, int, str]] = set()
    for key in ("jump", "fail"):
        target_address = raw_block.get(key)
        if not isinstance(target_address, int) or target_address <= 0:
            continue
        edge = (source_address, target_address, key)
        if edge in seen:
            continue
        seen.add(edge)
        edges.append(
            ControlFlowEdge(
                source_address=source_address,
                target_address=target_address,
                kind=key,
            )
        )
    return tuple(edges)


def _normalize_string(raw_string: dict[str, Any]) -> StringInfo | None:
    value = raw_string.get("string")
    address = raw_string.get("vaddr")
    if not isinstance(value, str) or not isinstance(address, int):
        return None
    size = raw_string.get("size")
    length = raw_string.get("length")
    section = raw_string.get("section")
    kind = raw_string.get("type")
    return StringInfo(
        value=value,
        address=address,
        size=size if isinstance(size, int) else 0,
        length=length if isinstance(length, int) else 0,
        section=section if isinstance(section, str) else "",
        kind=kind if isinstance(kind, str) else "unknown",
    )


def _normalize_xref(raw_xref: dict[str, Any]) -> XrefInfo | None:
    from_address = raw_xref.get("from")
    if not isinstance(from_address, int):
        return None
    xref_type = raw_xref.get("type")
    permission = raw_xref.get("perm")
    opcode = raw_xref.get("opcode")
    function_address = raw_xref.get("fcn_addr")
    function_name = raw_xref.get("fcn_name")
    reference_name = raw_xref.get("refname")
    return XrefInfo(
        from_address=from_address,
        xref_type=xref_type if isinstance(xref_type, str) else "unknown",
        permission=permission if isinstance(permission, str) else "",
        opcode=opcode if isinstance(opcode, str) else "",
        function_address=function_address if isinstance(function_address, int) else 0,
        function_name=function_name if isinstance(function_name, str) else "",
        reference_name=reference_name if isinstance(reference_name, str) else "",
    )


def _normalize_import(raw_import: dict[str, Any]) -> ImportInfo | None:
    name = raw_import.get("name")
    if not isinstance(name, str):
        return None
    bind = raw_import.get("bind")
    kind = raw_import.get("type")
    plt_address = raw_import.get("plt")
    return ImportInfo(
        name=name,
        bind=bind if isinstance(bind, str) else "",
        kind=kind if isinstance(kind, str) else "unknown",
        plt_address=plt_address if isinstance(plt_address, int) else 0,
    )


def _normalize_export(raw_export: dict[str, Any]) -> ExportInfo | None:
    name = raw_export.get("realname") or raw_export.get("name")
    address = raw_export.get("vaddr")
    if not isinstance(name, str) or not isinstance(address, int):
        return None
    size = raw_export.get("size")
    kind = raw_export.get("type")
    bind = raw_export.get("bind")
    return ExportInfo(
        name=name,
        address=address,
        size=size if isinstance(size, int) else 0,
        kind=kind if isinstance(kind, str) else "unknown",
        bind=bind if isinstance(bind, str) else "",
    )


def _normalize_relocation(raw_relocation: dict[str, Any]) -> RelocationInfo | None:
    name = raw_relocation.get("name")
    if not isinstance(name, str):
        return None
    address = raw_relocation.get("vaddr")
    if not isinstance(address, int):
        address = raw_relocation.get("paddr")
    if not isinstance(address, int):
        return None
    symbol_address = raw_relocation.get("sym_va")
    kind = raw_relocation.get("type")
    is_ifunc = raw_relocation.get("is_ifunc")
    return RelocationInfo(
        name=name,
        address=address,
        symbol_address=symbol_address if isinstance(symbol_address, int) else 0,
        kind=kind if isinstance(kind, str) else "unknown",
        is_ifunc=bool(is_ifunc),
    )


def _normalize_symbol(raw_symbol: dict[str, Any]) -> SymbolInfo | None:
    raw_name = raw_symbol.get("realname") or raw_symbol.get("name")
    if not isinstance(raw_name, str):
        return None
    address = raw_symbol.get("vaddr")
    if not isinstance(address, int):
        return None
    kind = raw_symbol.get("type")
    size = raw_symbol.get("size")
    is_imported = raw_symbol.get("is_imported")
    name = raw_name.removeprefix("imp.") if isinstance(is_imported, bool) and is_imported else raw_name
    return SymbolInfo(
        name=name,
        demangled_name=name,
        address=address,
        kind=kind if isinstance(kind, str) else "unknown",
        size=size if isinstance(size, int) else 0,
        is_dynamic=bool(is_imported),
    )


def _report_value(value: Any) -> str | None:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value:
        return value
    return None


def _is_available_decompilation_help(output: Any) -> bool:
    text = output.strip() if isinstance(output, str) else ""
    if not text:
        return False
    normalized = text.lower()
    return not any(marker in normalized for marker in DECOMPILATION_UNAVAILABLE_MARKERS)


def _normalize_decompilation_text(output: Any) -> str:
    text = output.strip() if isinstance(output, str) else ""
    if not text:
        return ""
    normalized = text.lower()
    if any(marker in normalized for marker in DECOMPILATION_UNAVAILABLE_MARKERS):
        return ""
    return text


def _decompilation_backend_name(backend: str) -> str:
    return DECOMPILATION_BACKEND_NAMES.get(backend, backend)


def _normalize_decompilation_annotation(raw_annotation: dict[str, Any]) -> DecompilationAnnotation | None:
    start = raw_annotation.get("start")
    end = raw_annotation.get("end")
    address = raw_annotation.get("offset")
    kind = raw_annotation.get("type")
    if not isinstance(start, int) or not isinstance(end, int) or not isinstance(address, int):
        return None
    if start < 0 or end < start or address < 0:
        return None
    return DecompilationAnnotation(
        start=start,
        end=end,
        address=address,
        kind=kind if isinstance(kind, str) else "unknown",
    )


def _build_line_mappings(
    text: str,
    annotations: tuple[DecompilationAnnotation, ...],
) -> tuple[DecompilationLineMapping, ...]:
    if not text or not annotations:
        return ()
    mappings: list[DecompilationLineMapping] = []
    offset = 0
    for line_number, line in enumerate(text.splitlines(keepends=True), start=1):
        line_start = offset
        line_end = offset + len(line)
        offset = line_end
        addresses = tuple(
            sorted(
                {
                    annotation.address
                    for annotation in annotations
                    if annotation.start < line_end and annotation.end + 1 > line_start
                }
            )
        )
        if not addresses:
            continue
        mappings.append(
            DecompilationLineMapping(
                line_number=line_number,
                start=line_start,
                end=line_end,
                addresses=addresses,
            )
        )
    if text and not text.endswith(("\n", "\r")):
        line_start = offset
        line_end = len(text)
        addresses = tuple(
            sorted(
                {
                    annotation.address
                    for annotation in annotations
                    if annotation.start < line_end and annotation.end + 1 > line_start
                }
            )
        )
        if addresses:
            mappings.append(
                DecompilationLineMapping(
                    line_number=len(text.splitlines()),
                    start=line_start,
                    end=line_end,
                    addresses=addresses,
                )
            )
    return tuple(mappings)


def _load_decompilation_json(
    r2: r2pipe.open_sync.open,
    backend: str,
    address: int,
) -> dict[str, Any] | None:
    try:
        raw = r2.cmdj(f"{backend}j @ {address}") or {}
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    return raw


def _extract_decompilation_annotations(
    raw_decompilation: dict[str, Any] | None,
) -> tuple[DecompilationAnnotation, ...]:
    if not isinstance(raw_decompilation, dict):
        return ()
    raw_annotations = raw_decompilation.get("annotations")
    if not isinstance(raw_annotations, list):
        return ()
    annotations = tuple(
        annotation
        for item in raw_annotations
        if isinstance(item, dict) and (annotation := _normalize_decompilation_annotation(item)) is not None
    )
    return tuple(sorted(annotations, key=lambda annotation: (annotation.start, annotation.end, annotation.address)))


def _build_decompilation_warnings(
    *,
    backend: str,
    requested_backend: str | None,
    available_backends: tuple[str, ...],
    used_fallback: bool,
) -> tuple[str, ...]:
    warnings: list[str] = []
    if used_fallback:
        preferred = requested_backend or DECOMPILATION_BACKEND_ORDER[0]
        warnings.append(f"Preferred HLL backend {preferred} was unavailable; using {backend} instead.")
    if backend == "pdc":
        warnings.append("pdc output is heuristic pseudo-decompilation and may be less structured than plugin-backed output.")
        if available_backends == ("pdc",):
            warnings.append("Only the built-in pdc backend is installed. Install r2ghidra or r2dec for stronger HLL output.")
    if not available_backends:
        warnings.append("No radare2 decompilation backends were detected.")
    return tuple(warnings)


def _header_from_signature(function: FunctionInfo, text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        match = SIGNATURE_HEADER_PATTERN.match(stripped)
        if match is not None:
            return f"{match.group(1).strip()}{{"
    signature = function.signature.strip()
    if signature:
        return f"{signature.removesuffix(';')} {{"
    return f"{function.name}() {{"


def _parameter_names_from_header(header: str) -> tuple[str, ...]:
    open_paren = header.find("(")
    close_paren = header.rfind(")")
    if open_paren < 0 or close_paren <= open_paren:
        return ()
    params = header[open_paren + 1 : close_paren].strip()
    if not params or params == "void":
        return ()
    names: list[str] = []
    for raw_param in params.split(","):
        param = raw_param.strip()
        if not param or param == "...":
            continue
        cleaned = param.split("=")[0].strip()
        cleaned = cleaned.replace("[", " ").replace("]", " ")
        cleaned = cleaned.rstrip("* ").strip()
        match = IDENTIFIER_PATTERN.search(cleaned)
        if match is None:
            continue
        names.append(match.group(0))
    return tuple(names)


def _simplify_thunk_decompilation(
    function: FunctionInfo,
    text: str,
) -> tuple[str, tuple[str, ...]]:
    normalized_lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not normalized_lines:
        return text, ()
    target_name = ""
    for line in normalized_lines:
        if line.startswith("//"):
            continue
        match = THUNK_TARGET_PATTERN.search(line)
        if match is not None:
            target_name = match.group(1)
            break
    if not target_name:
        return text, ()
    body_lines = [
        line
        for line in normalized_lines
        if not line.startswith("//")
        and not line.endswith("{")
        and line != "}"
        and not line.startswith("loc_")
    ]
    if not body_lines:
        return text, ()
    recognized_lines = 0
    saw_target_jump = False
    for line in body_lines:
        if THUNK_TARGET_PATTERN.search(line):
            recognized_lines += 1
            saw_target_jump = True
            continue
        if line.startswith("return "):
            recognized_lines += 1
            continue
    if not saw_target_jump or recognized_lines != len(body_lines):
        return text, ()
    header = _header_from_signature(function, text)
    args = ", ".join(_parameter_names_from_header(header))
    callee = f"import.{target_name}"
    return_type = header.split("(", 1)[0].strip().rsplit(" ", 1)[0]
    if return_type == "void":
        body = f"    {callee}({args});" if args else f"    {callee}();"
    else:
        body = f"    return {callee}({args});" if args else f"    return {callee}();"
    simplified = "\n".join((header, body, "}"))
    return simplified, ("Function is a thunk/import wrapper; HLL was synthesized from the trampoline target.",)


class Radare2Disassembler:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self._r2: r2pipe.open_sync.open | None = None
        self._architecture = "unknown"
        self._bits = 0
        self._available_decompilation_backends: dict[str, bool] | None = None

    @staticmethod
    def is_available() -> bool:
        return shutil.which("r2") is not None or shutil.which("radare2") is not None

    def __enter__(self) -> "Radare2Disassembler":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def open(self) -> None:
        if self._r2 is not None:
            return
        if not self.path.is_file():
            raise Radare2DisassemblerError(f"binary not found: {self.path}")
        if not self.is_available():
            raise Radare2DisassemblerError("radare2 is not installed on this system")
        try:
            self._r2 = r2pipe.open(str(self.path), flags=RADARE2_FLAGS)
            info = self._r2.cmdj("ij") or {}
            bin_info = info.get("bin") if isinstance(info, dict) else {}
            if isinstance(bin_info, dict):
                arch = bin_info.get("arch")
                bits = bin_info.get("bits")
                if isinstance(arch, str):
                    self._architecture = arch
                if isinstance(bits, int):
                    self._bits = bits
            self._r2.cmd("aa")
        except Exception as exc:
            self.close()
            raise Radare2DisassemblerError(f"failed to initialize radare2: {exc}") from exc

    def close(self) -> None:
        if self._r2 is None:
            return
        r2 = self._r2
        self._r2 = None
        self._available_decompilation_backends = None
        try:
            r2.quit()
        except Exception:
            return

    def available_decompilation_backends(self) -> tuple[str, ...]:
        r2 = self._require_open()
        if self._available_decompilation_backends is None:
            availability: dict[str, bool] = {}
            for backend in DECOMPILATION_BACKEND_ORDER:
                try:
                    help_output = r2.cmd(f"{backend}?")
                except Exception:
                    availability[backend] = False
                    continue
                availability[backend] = _is_available_decompilation_help(help_output)
            self._available_decompilation_backends = availability
        return tuple(
            backend
            for backend in DECOMPILATION_BACKEND_ORDER
            if self._available_decompilation_backends.get(backend)
        )

    def disassemble_section(
        self,
        section_name: str,
        *,
        start_address: int,
        fallback_address: int | None = None,
        instruction_limit: int = DEFAULT_INSTRUCTION_LIMIT,
    ) -> DisassemblyResult:
        if instruction_limit < 1:
            raise ValueError("instruction_limit must be positive")
        instructions = self._disassemble_at(start_address, instruction_limit)
        if not instructions and fallback_address is not None and fallback_address != start_address:
            instructions = self._disassemble_at(fallback_address, instruction_limit)
            start_address = fallback_address
        if not instructions:
            raise Radare2DisassemblerError(
                f"radare2 returned no instructions for {section_name} at {_format_hex(start_address)}"
            )
        return DisassemblyResult(
            path=self.path,
            section_name=section_name,
            architecture=self._architecture,
            bits=self._bits,
            start_address=start_address,
            instructions=instructions,
        )

    def list_functions(self) -> tuple[FunctionInfo, ...]:
        r2 = self._require_open()
        try:
            raw_functions = r2.cmdj("aflj") or []
        except Exception as exc:
            raise Radare2DisassemblerError(f"failed to list functions: {exc}") from exc
        if not isinstance(raw_functions, list):
            raise Radare2DisassemblerError("radare2 returned malformed function data")
        functions = tuple(
            function
            for item in raw_functions
            if (function := _normalize_function(item)) is not None
        )
        return tuple(sorted(functions, key=lambda function: function.address))

    def list_strings(self) -> tuple[StringInfo, ...]:
        r2 = self._require_open()
        try:
            raw_strings = r2.cmdj("izj") or []
        except Exception as exc:
            raise Radare2DisassemblerError(f"failed to list strings: {exc}") from exc
        if not isinstance(raw_strings, list):
            raise Radare2DisassemblerError("radare2 returned malformed string data")
        strings = tuple(
            string
            for item in raw_strings
            if (string := _normalize_string(item)) is not None
        )
        return tuple(sorted(strings, key=lambda string: string.address))

    def list_xrefs_to(self, address: int) -> tuple[XrefInfo, ...]:
        r2 = self._require_open()
        try:
            raw_xrefs = r2.cmdj(f"axtj @ {address}") or []
        except Exception as exc:
            raise Radare2DisassemblerError(f"failed to list xrefs to {_format_hex(address)}: {exc}") from exc
        if not isinstance(raw_xrefs, list):
            raise Radare2DisassemblerError("radare2 returned malformed xref data")
        xrefs = tuple(
            xref
            for item in raw_xrefs
            if (xref := _normalize_xref(item)) is not None
        )
        return tuple(sorted(xrefs, key=lambda xref: xref.from_address))

    def list_imports(self) -> tuple[ImportInfo, ...]:
        r2 = self._require_open()
        try:
            raw_imports = r2.cmdj("iij") or []
        except Exception as exc:
            raise Radare2DisassemblerError(f"failed to list imports: {exc}") from exc
        if not isinstance(raw_imports, list):
            raise Radare2DisassemblerError("radare2 returned malformed import data")
        imports = tuple(
            imp
            for item in raw_imports
            if (imp := _normalize_import(item)) is not None
        )
        return tuple(sorted(imports, key=lambda imp: (imp.name, imp.plt_address)))

    def list_exports(self) -> tuple[ExportInfo, ...]:
        r2 = self._require_open()
        try:
            raw_exports = r2.cmdj("iEj") or []
        except Exception as exc:
            raise Radare2DisassemblerError(f"failed to list exports: {exc}") from exc
        if not isinstance(raw_exports, list):
            raise Radare2DisassemblerError("radare2 returned malformed export data")
        exports = tuple(
            export
            for item in raw_exports
            if (export := _normalize_export(item)) is not None
        )
        return tuple(sorted(exports, key=lambda export: (export.address, export.name, export.kind)))

    def list_relocations(self) -> tuple[RelocationInfo, ...]:
        r2 = self._require_open()
        try:
            raw_relocations = r2.cmdj("irj") or []
        except Exception as exc:
            raise Radare2DisassemblerError(f"failed to list relocations: {exc}") from exc
        if not isinstance(raw_relocations, list):
            raise Radare2DisassemblerError("radare2 returned malformed relocation data")
        relocations = tuple(
            relocation
            for item in raw_relocations
            if (relocation := _normalize_relocation(item)) is not None
        )
        return tuple(sorted(relocations, key=lambda relocation: (relocation.address, relocation.name, relocation.kind)))

    def list_symbols(self) -> tuple[SymbolInfo, ...]:
        r2 = self._require_open()
        try:
            raw_symbols = r2.cmdj("isj") or []
        except Exception as exc:
            raise Radare2DisassemblerError(f"failed to list symbols: {exc}") from exc
        if not isinstance(raw_symbols, list):
            raise Radare2DisassemblerError("radare2 returned malformed symbol data")
        symbols = tuple(
            symbol
            for item in raw_symbols
            if (symbol := _normalize_symbol(item)) is not None
        )
        deduped: dict[tuple[str, int, str, bool], SymbolInfo] = {}
        for symbol in symbols:
            key = (symbol.name, symbol.address, symbol.kind, symbol.is_dynamic)
            deduped[key] = symbol
        return tuple(
            sorted(
                deduped.values(),
                key=lambda symbol: (symbol.address, symbol.name, symbol.kind, symbol.is_dynamic),
            )
        )

    def inspect_binary(self) -> BinaryMetadataReport:
        r2 = self._require_open()
        try:
            info = r2.cmdj("ij") or {}
            sections = r2.cmdj("iSj") or []
            entrypoints = r2.cmdj("iej") or []
            imports = r2.cmdj("iij") or []
            libraries = r2.cmdj("ilj") or []
        except Exception as exc:
            raise Radare2DisassemblerError(f"failed to inspect binary metadata: {exc}") from exc
        if not isinstance(info, dict):
            raise Radare2DisassemblerError("radare2 returned malformed binary info data")
        if not isinstance(sections, list):
            sections = []
        if not isinstance(entrypoints, list):
            entrypoints = []
        if not isinstance(imports, list):
            imports = []
        if not isinstance(libraries, list):
            libraries = []

        core_info = info.get("core")
        bin_info = info.get("bin")
        core = core_info if isinstance(core_info, dict) else {}
        binary = bin_info if isinstance(bin_info, dict) else {}
        format_name = (
            _report_value(binary.get("bintype"))
            or _report_value(binary.get("class"))
            or _report_value(core.get("format"))
            or "unknown"
        )
        summary_parts = [
            format_name,
            f"{self._architecture} {self._bits}-bit" if self._bits > 0 else self._architecture,
            f"{len(sections):,} sections",
            f"{len(entrypoints):,} entrypoints",
            f"{len(libraries):,} libraries",
            f"{len(imports):,} imports",
        ]
        lines = [
            f"Path: {self.path}",
            f"Format: {format_name}",
        ]
        for label, value in (
            ("Binary Type", _report_value(core.get("type")) or _report_value(binary.get("type"))),
            ("Architecture", _report_value(binary.get("arch")) or self._architecture),
            ("Bits", str(self._bits) if self._bits > 0 else None),
            ("Machine", _report_value(binary.get("machine"))),
            ("OS", _report_value(binary.get("os"))),
            ("Subsystem", _report_value(binary.get("subsystem"))),
            ("Endian", _report_value(binary.get("endian"))),
            ("Class", _report_value(binary.get("class"))),
            ("Size", _report_value(core.get("size"))),
            ("Human Size", _report_value(core.get("humansz"))),
            ("PIE", _report_value(binary.get("pie"))),
            ("PIC", _report_value(binary.get("pic"))),
            ("NX", _report_value(binary.get("nx"))),
            ("Canary", _report_value(binary.get("canary"))),
            ("Stripped", _report_value(binary.get("stripped"))),
            ("Static", _report_value(binary.get("static"))),
            ("Compiler", _report_value(binary.get("compiler"))),
            ("Language", _report_value(binary.get("lang"))),
        ):
            if value is not None:
                lines.append(f"{label}: {value}")

        lines.append("")
        lines.append(f"Sections ({len(sections):,})")
        for section in sections[:12]:
            if not isinstance(section, dict):
                continue
            name = _report_value(section.get("name")) or "?"
            vaddr = section.get("vaddr")
            size = section.get("size")
            perm = _report_value(section.get("perm")) or "----"
            lines.append(
                f"  {name:<16} {_format_hex(vaddr) if isinstance(vaddr, int) else '-':<12} size={size if isinstance(size, int) else 0:<8} perm={perm}"
            )
        if len(sections) > 12:
            lines.append(f"  ... {len(sections) - 12} more sections")

        lines.append("")
        lines.append(f"Entrypoints ({len(entrypoints):,})")
        for entry in entrypoints[:8]:
            if not isinstance(entry, dict):
                continue
            entry_type = _report_value(entry.get("type")) or "entry"
            vaddr = entry.get("vaddr")
            lines.append(f"  {entry_type:<12} {_format_hex(vaddr) if isinstance(vaddr, int) else '-'}")
        if len(entrypoints) > 8:
            lines.append(f"  ... {len(entrypoints) - 8} more entrypoints")

        lines.append("")
        lines.append(f"Libraries ({len(libraries):,})")
        if libraries:
            for library in libraries[:12]:
                lines.append(f"  {library}")
            if len(libraries) > 12:
                lines.append(f"  ... {len(libraries) - 12} more libraries")
        else:
            lines.append("  none")

        lines.append("")
        lines.append(f"Imports ({len(imports):,})")
        for imp in imports[:16]:
            if not isinstance(imp, dict):
                continue
            name = _report_value(imp.get("name")) or "?"
            imp_type = _report_value(imp.get("type")) or "?"
            bind = _report_value(imp.get("bind")) or "?"
            lines.append(f"  {name:<32} {imp_type:<8} {bind}")
        if len(imports) > 16:
            lines.append(f"  ... {len(imports) - 16} more imports")

        return BinaryMetadataReport(
            path=self.path,
            summary=" | ".join(summary_parts),
            text="\n".join(lines),
            libraries=tuple(str(library) for library in libraries if isinstance(library, str)),
        )

    def list_xrefs_to_import(self, import_name: str) -> tuple[XrefInfo, ...]:
        r2 = self._require_open()
        symbol = f"sym.imp.{import_name}"
        try:
            raw_xrefs = r2.cmdj(f"axtj @ {symbol}") or []
        except Exception as exc:
            raise Radare2DisassemblerError(f"failed to list xrefs to import {import_name}: {exc}") from exc
        if not isinstance(raw_xrefs, list):
            raise Radare2DisassemblerError("radare2 returned malformed import xref data")
        xrefs = tuple(
            xref
            for item in raw_xrefs
            if (xref := _normalize_xref(item)) is not None
        )
        return tuple(sorted(xrefs, key=lambda xref: xref.from_address))

    def disassemble_function(
        self,
        function: FunctionInfo,
    ) -> FunctionDisassemblyResult:
        r2 = self._require_open()
        try:
            raw_disassembly = r2.cmdj(f"pdfj @ {function.address}") or {}
        except Exception as exc:
            raise Radare2DisassemblerError(
                f"failed to disassemble function {function.name} at {_format_hex(function.address)}: {exc}"
            ) from exc
        if not isinstance(raw_disassembly, dict):
            raise Radare2DisassemblerError("radare2 returned malformed function disassembly data")
        raw_instructions = raw_disassembly.get("ops")
        if not isinstance(raw_instructions, list):
            raise Radare2DisassemblerError(
                f"radare2 returned no function instructions for {function.name}"
            )
        instructions = tuple(
            instruction
            for item in raw_instructions
            if (instruction := _normalize_instruction(item)) is not None
        )
        if not instructions:
            raise Radare2DisassemblerError(
                f"radare2 returned no function instructions for {function.name}"
            )
        return FunctionDisassemblyResult(
            path=self.path,
            function=function,
            architecture=self._architecture,
            bits=self._bits,
            instructions=instructions,
        )

    def decompile_function(
        self,
        function: FunctionInfo,
        *,
        backend: str | None = None,
    ) -> FunctionDecompilationResult:
        r2 = self._require_open()
        if backend is not None and backend not in DECOMPILATION_BACKEND_ORDER:
            raise ValueError(f"unsupported decompilation backend: {backend}")
        available_backends = self.available_decompilation_backends()
        if backend is not None:
            if backend not in available_backends:
                raise Radare2DisassemblerError(f"decompilation backend {backend} is not available")
            candidate_backends = (backend,)
        else:
            candidate_backends = available_backends
        if not candidate_backends:
            raise Radare2DisassemblerError("no radare2 decompilation backend is available")

        failures: list[str] = []
        for candidate in candidate_backends:
            try:
                output = r2.cmd(f"{candidate} @ {function.address}")
            except Exception as exc:
                failures.append(f"{candidate}: {exc}")
                continue
            text = _normalize_decompilation_text(output)
            if text:
                used_fallback = backend is None and candidate != DECOMPILATION_BACKEND_ORDER[0]
                raw_json = _load_decompilation_json(r2, candidate, function.address)
                annotations = _extract_decompilation_annotations(raw_json)
                synthetic_warnings: tuple[str, ...] = ()
                if candidate == "pdc":
                    text, synthetic_warnings = _simplify_thunk_decompilation(function, text)
                return FunctionDecompilationResult(
                    path=self.path,
                    function=function,
                    architecture=self._architecture,
                    bits=self._bits,
                    backend=candidate,
                    text=text,
                    requested_backend=backend,
                    backend_display_name=_decompilation_backend_name(candidate),
                    available_backends=available_backends,
                    used_fallback=used_fallback,
                    warnings=_build_decompilation_warnings(
                        backend=candidate,
                        requested_backend=backend,
                        available_backends=available_backends,
                        used_fallback=used_fallback,
                    )
                    + synthetic_warnings,
                    raw_json=raw_json,
                    annotations=annotations,
                    line_mappings=_build_line_mappings(text, annotations),
                )
            failures.append(f"{candidate}: no decompilation output")

        attempted = ", ".join(candidate_backends)
        details = "; ".join(failures)
        raise Radare2DisassemblerError(
            f"radare2 returned no decompilation for {function.name} after trying {attempted}: {details}"
        )

    def analyze_function_graph(
        self,
        function: FunctionInfo,
    ) -> FunctionGraphResult:
        r2 = self._require_open()
        try:
            raw_graphs = r2.cmdj(f"agfj @ {function.address}") or []
        except Exception as exc:
            raise Radare2DisassemblerError(
                f"failed to analyze control flow for {function.name} at {_format_hex(function.address)}: {exc}"
            ) from exc
        if not isinstance(raw_graphs, list) or not raw_graphs:
            raise Radare2DisassemblerError(f"radare2 returned no graph data for {function.name}")
        raw_graph = raw_graphs[0]
        if not isinstance(raw_graph, dict):
            raise Radare2DisassemblerError("radare2 returned malformed function graph data")
        raw_blocks = raw_graph.get("blocks")
        if not isinstance(raw_blocks, list):
            raise Radare2DisassemblerError("radare2 returned malformed function blocks")
        blocks = tuple(
            block
            for item in raw_blocks
            if (block := _normalize_block(item)) is not None
        )
        if not blocks:
            raise Radare2DisassemblerError(f"radare2 returned no blocks for {function.name}")
        edges = tuple(
            sorted(
                (
                    edge
                    for item in raw_blocks
                    for edge in _normalize_block_edges(item)
                ),
                key=lambda edge: (edge.source_address, edge.target_address, edge.kind),
            )
        )
        return FunctionGraphResult(
            path=self.path,
            function=function,
            architecture=self._architecture,
            bits=self._bits,
            blocks=tuple(sorted(blocks, key=lambda block: block.address)),
            edges=edges,
        )

    def _disassemble_at(
        self,
        address: int,
        instruction_limit: int,
    ) -> tuple[DisassembledInstruction, ...]:
        r2 = self._require_open()
        try:
            raw_instructions = r2.cmdj(f"pdj {instruction_limit} @ {address}") or []
        except Exception as exc:
            raise Radare2DisassemblerError(f"failed to disassemble at {_format_hex(address)}: {exc}") from exc
        if not isinstance(raw_instructions, list):
            raise Radare2DisassemblerError("radare2 returned malformed disassembly data")
        instructions = tuple(
            instruction
            for item in raw_instructions
            if (instruction := _normalize_instruction(item)) is not None
        )
        return instructions

    def _require_open(self) -> r2pipe.open_sync.open:
        if self._r2 is None:
            raise Radare2DisassemblerError("radare2 session is not open")
        return self._r2
