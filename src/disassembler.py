from __future__ import annotations

import shutil
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any

import r2pipe

RADARE2_FLAGS = ["-N", "-2", "-e", "scr.color=0", "-e", "bin.relocs.apply=true"]
DEFAULT_INSTRUCTION_LIMIT = 64


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


class Radare2Disassembler:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self._r2: r2pipe.open_sync.open | None = None
        self._architecture = "unknown"
        self._bits = 0

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
        try:
            r2.quit()
        except Exception:
            return

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
