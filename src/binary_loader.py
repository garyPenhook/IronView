import ctypes
import ctypes.util
from dataclasses import dataclass
from pathlib import Path
from typing import Final


class BinaryLoaderError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SectionInfo:
    name: str
    index: int
    size: int
    vma: int
    lma: int
    flags: int
    alignment_power: int
    file_offset: int


@dataclass(frozen=True, slots=True)
class BinaryImage:
    path: Path
    arch_size: int
    sections: tuple[SectionInfo, ...]


class _ASection(ctypes.Structure):
    pass


_ASectionPointer = ctypes.POINTER(_ASection)

_ASection._fields_ = [
    ("name", ctypes.c_char_p),
    ("next", _ASectionPointer),
    ("prev", _ASectionPointer),
    ("id", ctypes.c_uint),
    ("section_id", ctypes.c_uint),
    ("index", ctypes.c_uint),
    ("flags", ctypes.c_uint),
    ("user_set_vma", ctypes.c_uint, 1),
    ("linker_mark", ctypes.c_uint, 1),
    ("linker_has_input", ctypes.c_uint, 1),
    ("gc_mark", ctypes.c_uint, 1),
    ("compress_status", ctypes.c_uint, 2),
    ("segment_mark", ctypes.c_uint, 1),
    ("sec_info_type", ctypes.c_uint, 3),
    ("use_rela_p", ctypes.c_uint, 1),
    ("sec_flg0", ctypes.c_uint, 1),
    ("sec_flg1", ctypes.c_uint, 1),
    ("sec_flg2", ctypes.c_uint, 1),
    ("sec_flg3", ctypes.c_uint, 1),
    ("sec_flg4", ctypes.c_uint, 1),
    ("sec_flg5", ctypes.c_uint, 1),
    ("vma", ctypes.c_uint64),
    ("lma", ctypes.c_uint64),
    ("size", ctypes.c_uint64),
    ("rawsize", ctypes.c_uint64),
    ("compressed_size", ctypes.c_uint64),
    ("output_offset", ctypes.c_uint64),
    ("output_section", _ASectionPointer),
    ("relocation", ctypes.c_void_p),
    ("orelocation", ctypes.c_void_p),
    ("reloc_count", ctypes.c_uint),
    ("alignment_power", ctypes.c_uint),
    ("filepos", ctypes.c_long),
    ("rel_filepos", ctypes.c_long),
    ("line_filepos", ctypes.c_long),
    ("userdata", ctypes.c_void_p),
    ("contents", ctypes.c_void_p),
]


_BFD_OBJECT: Final[int] = 1
_SECTION_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_void_p, _ASectionPointer, ctypes.py_object)


class _LibBfd:
    def __init__(self) -> None:
        self._lib = ctypes.CDLL(self._resolve_library())
        self._configure()
        self._lib.bfd_init()

    @staticmethod
    def _resolve_library() -> str:
        candidates = [
            ctypes.util.find_library("bfd"),
            "/usr/lib/x86_64-linux-gnu/libbfd-2.46-system.so",
            "/usr/lib/x86_64-linux-gnu/libbfd.so",
        ]
        for candidate in candidates:
            if candidate:
                return candidate
        raise BinaryLoaderError("libbfd shared library was not found on this system")

    def _configure(self) -> None:
        self._lib.bfd_init.restype = ctypes.c_uint
        self._lib.bfd_openr.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self._lib.bfd_openr.restype = ctypes.c_void_p
        self._lib.bfd_close.argtypes = [ctypes.c_void_p]
        self._lib.bfd_close.restype = ctypes.c_int
        self._lib.bfd_check_format.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self._lib.bfd_check_format.restype = ctypes.c_int
        self._lib.bfd_get_arch_size.argtypes = [ctypes.c_void_p]
        self._lib.bfd_get_arch_size.restype = ctypes.c_int
        self._lib.bfd_get_error.restype = ctypes.c_int
        self._lib.bfd_errmsg.argtypes = [ctypes.c_int]
        self._lib.bfd_errmsg.restype = ctypes.c_char_p
        self._lib.bfd_map_over_sections.argtypes = [ctypes.c_void_p, _SECTION_CALLBACK, ctypes.py_object]
        self._lib.bfd_map_over_sections.restype = None
        self._lib.bfd_get_section_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self._lib.bfd_get_section_by_name.restype = _ASectionPointer
        self._lib.bfd_get_section_contents.argtypes = [
            ctypes.c_void_p,
            _ASectionPointer,
            ctypes.c_void_p,
            ctypes.c_long,
            ctypes.c_uint64,
        ]
        self._lib.bfd_get_section_contents.restype = ctypes.c_int

    def last_error(self) -> str:
        error_code = self._lib.bfd_get_error()
        message = self._lib.bfd_errmsg(error_code)
        if not message:
            return f"libbfd error {error_code}"
        return message.decode(errors="replace")


_LIBBFD: _LibBfd | None = None


def _libbfd() -> _LibBfd:
    global _LIBBFD
    if _LIBBFD is not None:
        return _LIBBFD
    try:
        _LIBBFD = _LibBfd()
    except BinaryLoaderError:
        raise
    except (AttributeError, OSError) as exc:
        raise BinaryLoaderError(f"failed to initialize libbfd: {exc}") from exc
    return _LIBBFD


class BinaryLoader:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self._handle: int | None = None

    def __enter__(self) -> "BinaryLoader":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def open(self) -> None:
        if self._handle is not None:
            return
        if not self.path.is_file():
            raise BinaryLoaderError(f"binary not found: {self.path}")

        libbfd = _libbfd()
        handle = libbfd._lib.bfd_openr(str(self.path).encode(), None)
        if not handle:
            raise BinaryLoaderError(f"failed to open {self.path}: {libbfd.last_error()}")
        if not libbfd._lib.bfd_check_format(handle, _BFD_OBJECT):
            libbfd._lib.bfd_close(handle)
            raise BinaryLoaderError(f"unsupported or invalid object format: {libbfd.last_error()}")

        self._handle = handle

    def close(self) -> None:
        if self._handle is None:
            return
        _libbfd()._lib.bfd_close(self._handle)
        self._handle = None

    def image(self) -> BinaryImage:
        handle = self._require_open_handle()
        libbfd = _libbfd()
        return BinaryImage(
            path=self.path,
            arch_size=libbfd._lib.bfd_get_arch_size(handle),
            sections=tuple(self.sections()),
        )

    def sections(self) -> list[SectionInfo]:
        handle = self._require_open_handle()
        libbfd = _libbfd()
        sections: list[SectionInfo] = []

        @_SECTION_CALLBACK
        def collect(_abfd: int, section: _ASectionPointer, out: list[SectionInfo]) -> None:
            raw = section.contents
            out.append(
                SectionInfo(
                    name=(raw.name or b"").decode(errors="replace"),
                    index=raw.index,
                    size=int(raw.size),
                    vma=int(raw.vma),
                    lma=int(raw.lma),
                    flags=raw.flags,
                    alignment_power=raw.alignment_power,
                    file_offset=int(raw.filepos),
                )
            )

        libbfd._lib.bfd_map_over_sections(handle, collect, sections)
        return sections

    def read_section(self, name: str) -> bytes:
        handle = self._require_open_handle()
        libbfd = _libbfd()
        section = libbfd._lib.bfd_get_section_by_name(handle, name.encode())
        if not section:
            raise BinaryLoaderError(f"section not found: {name}")

        size = int(section.contents.size)
        if size == 0:
            return b""

        buffer = (ctypes.c_ubyte * size)()
        ok = libbfd._lib.bfd_get_section_contents(handle, section, buffer, 0, size)
        if not ok:
            raise BinaryLoaderError(f"failed to read section {name}: {libbfd.last_error()}")
        return bytes(buffer)

    def _require_open_handle(self) -> int:
        if self._handle is None:
            raise BinaryLoaderError("binary is not open")
        return self._handle
