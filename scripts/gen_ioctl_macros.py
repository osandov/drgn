#!/usr/bin/env python3

import argparse
from pathlib import Path
import re
import sys
from typing import List

MACROS = (
    "NONE",
    "READ",
    "WRITE",
    "NRBITS",
    "TYPEBITS",
    "SIZEBITS",
    "DIRBITS",
)


SRCARCH_TO_MACHINE_NAMES = {
    "alpha": ["alpha"],
    "mips": ["mips", "mips64"],
    "parisc": ["parisc", "parisc64"],
    "powerpc": ["ppc", "ppc64"],
    "sparc": ["sparc", "sparc64"],
}


def add_ioc_macros(macros, machine_names: List[str], path: Path) -> None:
    contents = path.read_text()
    for name, definition in re.findall(
        rf"^\s*#\s*define\s+_IOC_({'|'.join(MACROS)})\s+(\S+)",
        contents,
        flags=re.M,
    ):
        match = re.fullmatch(r"([0-9]+)[UL]*", definition)
        for machine_name in machine_names:
            macros.setdefault(name, {})[machine_name] = int(match.group(1))


def main() -> None:
    argparse.ArgumentParser(
        description="Generate Python functions for ioctl numbers from the kernel source code"
    ).parse_args()

    macros = {}
    add_ioc_macros(macros, ["generic"], Path("include/uapi/asm-generic/ioctl.h"))
    for path in Path(".").glob("arch/*/include/uapi/asm/ioctl.h"):
        add_ioc_macros(macros, SRCARCH_TO_MACHINE_NAMES[path.parts[1]], path)

    for name in MACROS:
        by_machine_name = macros[name]
        generic = by_machine_name["generic"]
        values = [
            (arch, value) for arch, value in by_machine_name.items() if value != generic
        ]
        values.sort()
        if values:
            print(f"_IOC_{name} = {{")
            for arch, value in values:
                print(f"    {arch!r}: {value},")
            print(f"}}.get(NORMALIZED_MACHINE_NAME, {generic})")
        else:
            print(f"_IOC_{name} = {generic}")
        print()

    sys.stdout.write(
        """\
_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS


def _IOC(dir: int, type: int, nr: int, size: int) -> int:
    return (
        (dir << _IOC_DIRSHIFT)
        | (type << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


def _IO(type: int, nr: int) -> int:
    return _IOC(_IOC_NONE, type, nr, 0)


def _IOR(type: int, nr: int, size: int) -> int:
    return _IOC(_IOC_READ, type, nr, size)


def _IOW(type: int, nr: int, size: int) -> int:
    return _IOC(_IOC_WRITE, type, nr, size)


def _IOWR(type: int, nr: int, size: int) -> int:
    return _IOC(_IOC_READ | _IOC_WRITE, type, nr, size)
"""
    )


if __name__ == "__main__":
    main()
