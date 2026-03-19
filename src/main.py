import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict

from src.binary_loader import BinaryLoader, BinaryLoaderError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect binaries through libbfd")
    parser.add_argument("path", nargs="?", help="Path to the binary to inspect")
    parser.add_argument("--section", help="Dump a section's bytes as hex in CLI mode")
    parser.add_argument("--gui", action="store_true", help="Launch the Qt desktop interface")
    return parser


def run_gui(initial_path: str | None = None) -> int:
    from src.gui import run_gui as run_binary_gui

    return run_binary_gui(initial_path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.gui or not args.path:
        if args.section:
            parser.error("--section requires a path in CLI mode")
        return run_gui(args.path)

    try:
        with BinaryLoader(args.path) as loader:
            if args.section:
                print(loader.read_section(args.section).hex())
                return 0

            image = loader.image()
            print(
                json.dumps(
                    {
                        "path": str(image.path),
                        "arch_size": image.arch_size,
                        "sections": [asdict(section) for section in image.sections],
                    },
                    indent=2,
                )
            )
            return 0
    except BinaryLoaderError as exc:
        parser.exit(status=1, message=f"{exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
