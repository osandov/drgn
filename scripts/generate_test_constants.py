#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import keyword
from pathlib import Path
import re

ENUMS = {
    "elf": (
        "ET",
        "PT",
        "SHN",
        "SHT",
        "STB",
        "STT",
        "STV",
    ),
    "dwarf": (
        "DW_AT",
        "DW_ATE",
        "DW_CHILDREN",
        "DW_END",
        "DW_FORM",
        "DW_LANG",
        "DW_LNE",
        "DW_LNS",
        "DW_OP",
        "DW_TAG",
    ),
}


VALUE_REGEX = r"(?P<value>0x[0-9a-fA-F]+|[0-9]+)"
REGEXES = {
    "elf": r"^\s*#\s*define\s+(?P<enum>"
    + "|".join(ENUMS["elf"])
    + r")_(?P<name>\w+)\s+"
    + VALUE_REGEX,
    "dwarf": r"^\s*(?P<enum>"
    + "|".join(ENUMS["dwarf"])
    + r")_(?P<name>\w+)\s*=\s*"
    + VALUE_REGEX,
}


def read_header(name: str) -> str:
    contents = (Path("libdrgn/include") / name).read_text()
    contents = re.sub(r"/\*.*?\*/", "", contents, flags=re.DOTALL)
    contents = re.sub(r"\\\n", "", contents)
    return contents


def generate_constants(file: str) -> None:
    contents = read_header(file + ".h")

    enums = {}
    for match in re.finditer(REGEXES[file], contents, re.MULTILINE):
        enum = match.group("enum")
        name = match.group("name")
        value = int(match.group("value"), 0)
        try:
            enums[enum].append((name, value))
        except KeyError:
            enums[enum] = [(name, value)]

    print(
        f"""\
# Automatically generated from {file}.h

import enum
from typing import Text

"""
    )
    first = True
    for enum in ENUMS[file]:
        assert enums[enum]
        if not first:
            print()
            print()
        first = False
        print(f"class {enum}(enum.IntEnum):")
        for name, value in enums[enum]:
            if keyword.iskeyword(name):
                name += "_"
            print(f"    {name} = 0x{value:X}", end="")
            if name == "name":
                print("  # type: ignore")
            else:
                print()
        print()
        print("    @classmethod")
        print("    def str(cls, value: int) -> Text:")
        print("        try:")
        print(f'            return f"{enum}_{{cls(value).name}}"')
        print("        except ValueError:")
        print("            return hex(value)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="generate constants for Python tests from header file"
    )
    parser.add_argument("file", choices=list(ENUMS))
    args = parser.parse_args()
    generate_constants(args.file)
