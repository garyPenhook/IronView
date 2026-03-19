from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import shutil


class GnuToolchainError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SourceLocation:
    function_name: str
    file_path: str
    line_number: int | None
    display_text: str


@dataclass(frozen=True, slots=True)
class SymbolInfo:
    name: str
    demangled_name: str
    address: int
    kind: str
    size: int
    is_dynamic: bool


@dataclass(frozen=True, slots=True)
class ElfReport:
    path: Path
    text: str


def _tool_path(name: str) -> str | None:
    return shutil.which(name)


def _parse_nm_output(output: str, *, is_dynamic: bool) -> tuple[SymbolInfo, ...]:
    symbols: list[SymbolInfo] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or ":" in line and line.endswith(":"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        kind = parts[1]
        address = int(parts[2], 16) if len(parts) >= 3 and _is_hex(parts[2]) else 0
        size = int(parts[3], 16) if len(parts) >= 4 and _is_hex(parts[3]) else 0
        symbols.append(
            SymbolInfo(
                name=name,
                demangled_name=name,
                address=address,
                kind=kind,
                size=size,
                is_dynamic=is_dynamic,
            )
        )
    return tuple(symbols)


def _is_hex(value: str) -> bool:
    if not value:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


class GnuToolchain:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()

    @staticmethod
    def has_addr2line() -> bool:
        return _tool_path("addr2line") is not None

    @staticmethod
    def has_cxxfilt() -> bool:
        return _tool_path("c++filt") is not None

    @staticmethod
    def has_nm() -> bool:
        return _tool_path("nm") is not None

    @staticmethod
    def has_readelf() -> bool:
        return _tool_path("readelf") is not None

    @staticmethod
    def has_gdb() -> bool:
        return _tool_path("gdb") is not None

    def demangle(self, name: str) -> str:
        return self.demangle_many((name,)).get(name, name)

    def demangle_many(self, names: Iterable[str]) -> dict[str, str]:
        ordered_names = tuple(names)
        if not ordered_names:
            return {}
        if not self.has_cxxfilt():
            return {name: name for name in ordered_names}
        result = self._run_command(
            ["c++filt"],
            input_text="\n".join(ordered_names) + "\n",
        )
        decoded = result.stdout.splitlines()
        if len(decoded) != len(ordered_names):
            return {name: name for name in ordered_names}
        return {name: demangled for name, demangled in zip(ordered_names, decoded, strict=True)}

    def lookup_source(self, address: int) -> SourceLocation | None:
        if address < 0:
            raise ValueError("address must be non-negative")
        if not self.has_addr2line():
            return None
        result = self._run_command(
            ["addr2line", "-e", str(self.path), "-f", "-C", f"0x{address:X}"],
        )
        lines = [line.strip() for line in result.stdout.splitlines()]
        if len(lines) < 2:
            return None
        function_name = lines[0] or "??"
        location = lines[1] or "??:?"
        file_path = location
        line_number: int | None = None
        if location != "??:?" and ":" in location:
            file_part, line_part = location.rsplit(":", 1)
            file_path = file_part
            if line_part.isdigit():
                line_number = int(line_part)
        return SourceLocation(
            function_name=function_name,
            file_path=file_path,
            line_number=line_number,
            display_text=location,
        )

    def list_symbols(self) -> tuple[SymbolInfo, ...]:
        if not self.has_nm():
            raise GnuToolchainError("nm is not installed on this system")
        outputs = (
            (False, self._run_nm(is_dynamic=False)),
            (True, self._run_nm(is_dynamic=True)),
        )
        parsed: list[SymbolInfo] = []
        for is_dynamic, output in outputs:
            parsed.extend(_parse_nm_output(output, is_dynamic=is_dynamic))
        if not parsed:
            return ()
        demangled = self.demangle_many(symbol.name for symbol in parsed)
        deduped: dict[tuple[str, int, str, bool], SymbolInfo] = {}
        for symbol in parsed:
            key = (symbol.name, symbol.address, symbol.kind, symbol.is_dynamic)
            deduped[key] = SymbolInfo(
                name=symbol.name,
                demangled_name=demangled.get(symbol.name, symbol.name),
                address=symbol.address,
                kind=symbol.kind,
                size=symbol.size,
                is_dynamic=symbol.is_dynamic,
            )
        return tuple(sorted(deduped.values(), key=lambda symbol: (symbol.address, symbol.demangled_name, symbol.name)))

    def read_elf_report(self) -> ElfReport:
        if not self.has_readelf():
            raise GnuToolchainError("readelf is not installed on this system")
        result = self._run_command(["readelf", "-h", "-l", "-S", "--wide", str(self.path)])
        return ElfReport(path=self.path, text=result.stdout)

    def _run_nm(self, *, is_dynamic: bool) -> str:
        command = ["nm", "--numeric-sort", "--format=posix"]
        if is_dynamic:
            command.append("-D")
        command.append(str(self.path))
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            raise GnuToolchainError("nm is not installed on this system") from exc
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if result.stdout and stderr:
                raise GnuToolchainError(f"nm produced partial output: {stderr}")
            if not result.stdout and stderr:
                raise GnuToolchainError(f"nm failed: {stderr}")
            if not result.stdout:
                return ""
        return result.stdout

    def _run_command(
        self,
        command: list[str],
        *,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                input=input_text,
                capture_output=True,
                text=True,
                check=True,
            )
        except FileNotFoundError as exc:
            raise GnuToolchainError(f"{command[0]} is not installed on this system") from exc
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() or exc.stdout.strip() or str(exc)
            raise GnuToolchainError(f"{command[0]} failed: {stderr}") from exc
