#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import keyword
import re

prefixes = [
    "DW_AT",
    "DW_ATE",
    "DW_CHILDREN",
    "DW_FORM",
    "DW_LANG",
    "DW_LNE",
    "DW_LNS",
    "DW_OP",
    "DW_TAG",
]

if __name__ == "__main__":
    with open("libdrgn/elfutils/libdw/dwarf.h", "r") as f:
        dwarf_h = f.read()
    dwarf_h = re.sub(r"/\*.*?\*/", "", dwarf_h, flags=re.DOTALL)
    dwarf_h = re.sub(r"\\\n", "", dwarf_h)
    matches = re.findall(
        r"^\s*(" + "|".join(prefixes) + r")_(\w+)\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)",
        dwarf_h,
        re.MULTILINE,
    )

    enums = {}
    for enum, name, value in matches:
        try:
            enums[enum].append((name, int(value, 0)))
        except KeyError:
            enums[enum] = [(name, int(value, 0))]

    print(
        """\
# Automatically generated from dwarf.h

import enum
from typing import Text

"""
    )
    first = True
    for enum in prefixes:
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
