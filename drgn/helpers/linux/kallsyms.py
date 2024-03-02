#!/usr/bin/env python3
# Copyright (c) 2023 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Kallsyms
--------

The kallsyms module contains helpers which allow you to use the built-in
kallsyms symbol table for drgn object lookup. Combined with an alternative type
information source, this can enable debugging Linux kernel core dumps without
the corresponding DWARF debuginfo files.
"""
import re
from typing import Dict

from drgn import KallsymsFinder, Program

__all__ = ("make_kallsyms_vmlinux_finder",)


def _vmcoreinfo_symbols(prog: Program) -> Dict[str, int]:
    vmcoreinfo_data = prog["VMCOREINFO"].string_().decode("ascii")
    vmcoreinfo_symbols = {}
    sym_re = re.compile(r"SYMBOL\(([^)]+)\)=([A-Fa-f0-9]+)")
    for line in vmcoreinfo_data.strip().split("\n"):
        match = sym_re.fullmatch(line)
        if match:
            vmcoreinfo_symbols[match.group(1)] = int(match.group(2), 16)
    return vmcoreinfo_symbols


def make_kallsyms_vmlinux_finder(prog: Program) -> KallsymsFinder:
    """
    Create a vmlinux kallsyms finder, which may be passed to
    :meth:`drgn.Program.add_symbol_finder`.

    This function automatically finds the necessary information to create a
    ``KallsymsFinder`` from the program's VMCOREINFO data. It may fail if the
    information is not present. Please note that the debugged Linux kernel must
    be 6.0 or later to find this information.

    :returns: a callable symbol finder object
    """
    symbol_reqd = [
        "kallsyms_names",
        "kallsyms_token_table",
        "kallsyms_token_index",
        "kallsyms_num_syms",
        "kallsyms_offsets",
        "kallsyms_relative_base",
        "kallsyms_addresses",
        "_stext",
    ]
    symbols = _vmcoreinfo_symbols(prog)
    args = []
    for sym in symbol_reqd:
        args.append(symbols.get(sym, 0))
    return KallsymsFinder(prog, *args)
