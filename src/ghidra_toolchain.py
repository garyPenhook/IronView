from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_GHIDRA_TIMEOUT_SECONDS = 120
DEFAULT_GHIDRA_PROJECT_ROOT = Path.home() / ".cache" / "ironview" / "ghidra"


class GhidraToolchainError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class GhidraInstallation:
    version: str
    ghidra_path: Path | None
    analyze_headless_path: Path | None

    @property
    def available(self) -> bool:
        return self.ghidra_path is not None

    @property
    def headless_available(self) -> bool:
        return self.analyze_headless_path is not None


@dataclass(frozen=True, slots=True)
class GhidraHeadlessReport:
    path: Path
    summary: str
    text: str
    project_root: Path
    project_name: str
    command: tuple[str, ...]
    installation: GhidraInstallation


def _tool_path(name: str) -> Path | None:
    resolved = shutil.which(name)
    return Path(resolved).resolve() if resolved is not None else None


def _format_command(command: list[str]) -> str:
    return " ".join(command)


def _tail_lines(text: str, *, limit: int = 40) -> str:
    lines = [line.rstrip() for line in text.splitlines()]
    if len(lines) <= limit:
        return "\n".join(lines)
    return "\n".join(["..."] + lines[-limit:])


def _project_name_for_binary(path: Path) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.name)
    return f"{normalized}_ironview"


class GhidraToolchain:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()

    @staticmethod
    def find_ghidra() -> Path | None:
        path = _tool_path("ghidra")
        if path is not None:
            return path
        fallback = Path("/usr/bin/ghidra")
        return fallback if fallback.is_file() else None

    @staticmethod
    def find_analyze_headless() -> Path | None:
        path = _tool_path("analyzeHeadless")
        if path is not None:
            return path
        fallback = Path("/usr/share/ghidra/support/analyzeHeadless")
        if fallback.is_file():
            return fallback
        ghidra = GhidraToolchain.find_ghidra()
        if ghidra is None:
            return None
        sibling = ghidra.resolve().parent / "support" / "analyzeHeadless"
        return sibling if sibling.is_file() else None

    @staticmethod
    def version() -> str:
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Version}\n", "ghidra"],
                capture_output=True,
                text=True,
                check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            return "unknown"
        version = result.stdout.strip()
        return version or "unknown"

    @classmethod
    def detect_installation(cls) -> GhidraInstallation:
        return GhidraInstallation(
            version=cls.version(),
            ghidra_path=cls.find_ghidra(),
            analyze_headless_path=cls.find_analyze_headless(),
        )

    @staticmethod
    def has_ghidra() -> bool:
        return GhidraToolchain.find_ghidra() is not None

    @staticmethod
    def has_analyze_headless() -> bool:
        return GhidraToolchain.find_analyze_headless() is not None

    def build_headless_command(
        self,
        *,
        timeout_seconds: int = DEFAULT_GHIDRA_TIMEOUT_SECONDS,
        project_root: Path = DEFAULT_GHIDRA_PROJECT_ROOT,
        delete_project: bool = True,
        noanalysis: bool = False,
    ) -> tuple[list[str], Path, str]:
        installation = self.detect_installation()
        if installation.analyze_headless_path is None:
            raise GhidraToolchainError("Ghidra headless analyzer is not available on this system")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        project_root = project_root.resolve()
        project_name = _project_name_for_binary(self.path)
        command = [
            str(installation.analyze_headless_path),
            str(project_root),
            project_name,
            "-import",
            str(self.path),
            "-overwrite",
            "-readOnly",
            "-analysisTimeoutPerFile",
            str(timeout_seconds),
        ]
        if noanalysis:
            command.append("-noanalysis")
        if delete_project:
            command.append("-deleteProject")
        return command, project_root, project_name

    def run_headless_analysis(
        self,
        *,
        timeout_seconds: int = DEFAULT_GHIDRA_TIMEOUT_SECONDS,
        project_root: Path = DEFAULT_GHIDRA_PROJECT_ROOT,
        delete_project: bool = True,
        noanalysis: bool = False,
    ) -> GhidraHeadlessReport:
        installation = self.detect_installation()
        if installation.analyze_headless_path is None:
            raise GhidraToolchainError("Ghidra headless analyzer is not available on this system")
        command, project_root, project_name = self.build_headless_command(
            timeout_seconds=timeout_seconds,
            project_root=project_root,
            delete_project=delete_project,
            noanalysis=noanalysis,
        )
        project_root.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds + 30,
            )
        except FileNotFoundError as exc:
            raise GhidraToolchainError("Ghidra headless analyzer is not available on this system") from exc
        except subprocess.TimeoutExpired as exc:
            raise GhidraToolchainError(
                f"Ghidra headless analysis timed out after {timeout_seconds} seconds"
            ) from exc
        output = "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part).strip()
        if result.returncode != 0:
            detail = _tail_lines(output or f"exit code {result.returncode}")
            raise GhidraToolchainError(f"Ghidra headless analysis failed: {detail}")
        action = "imported without analysis" if noanalysis else "analyzed"
        summary = f"Ghidra {installation.version} headless {action} {self.path.name}"
        report_lines = [
            f"Ghidra version: {installation.version}",
            f"Binary: {self.path}",
            f"Project root: {project_root}",
            f"Project name: {project_name}",
            f"Delete project after run: {'yes' if delete_project else 'no'}",
            f"Command: {_format_command(command)}",
            "",
            "Output:",
            _tail_lines(output or "(no output)"),
        ]
        return GhidraHeadlessReport(
            path=self.path,
            summary=summary,
            text="\n".join(report_lines),
            project_root=project_root,
            project_name=project_name,
            command=tuple(command),
            installation=installation,
        )
