#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import itertools
import sys

SPELLINGS = [
    ("DRGN_C_TYPE_VOID", ["void"]),
    ("DRGN_C_TYPE_CHAR", ["char"]),
    ("DRGN_C_TYPE_SIGNED_CHAR", ["signed char"]),
    ("DRGN_C_TYPE_UNSIGNED_CHAR", ["unsigned char"]),
    ("DRGN_C_TYPE_SHORT", ["short", "signed short", "short int", "signed short int"]),
    ("DRGN_C_TYPE_UNSIGNED_SHORT", ["unsigned short", "unsigned short int"]),
    ("DRGN_C_TYPE_INT", ["int", "signed", "signed int"]),
    ("DRGN_C_TYPE_UNSIGNED_INT", ["unsigned int", "unsigned"]),
    ("DRGN_C_TYPE_LONG", ["long", "signed long", "long int", "signed long int"]),
    ("DRGN_C_TYPE_UNSIGNED_LONG", ["unsigned long", "unsigned long int"]),
    (
        "DRGN_C_TYPE_LONG_LONG",
        ["long long", "signed long long", "long long int", "signed long long int"],
    ),
    (
        "DRGN_C_TYPE_UNSIGNED_LONG_LONG",
        ["unsigned long long", "unsigned long long int"],
    ),
    ("DRGN_C_TYPE_BOOL", ["_Bool"]),
    ("DRGN_C_TYPE_FLOAT", ["float"]),
    ("DRGN_C_TYPE_DOUBLE", ["double"]),
    ("DRGN_C_TYPE_LONG_DOUBLE", ["long double"]),
    ("DRGN_C_TYPE_SIZE_T", ["size_t"]),
    ("DRGN_C_TYPE_PTRDIFF_T", ["ptrdiff_t"]),
]


if __name__ == "__main__":
    output_file = sys.stdout
    output_file.write("LIBDRGN_PUBLIC const char * const * const\n")
    output_file.write("drgn_primitive_type_spellings[DRGN_PRIMITIVE_TYPE_NUM] = {\n")
    for primitive, spellings in SPELLINGS:
        output_file.write(f"\t[{primitive}] = (const char * []){{")
        seen = set()
        for spelling in spellings:
            for permutation in itertools.permutations(spelling.split()):
                s = " ".join(permutation)
                if s not in seen:
                    output_file.write(f' "{s}",')
                    seen.add(s)
        output_file.write(" NULL, },\n")
    output_file.write("};\n")
