# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Kallsyms
--------

The ``drgn.helpers.linux.kallsyms`` module contains helpers which allow you to
use the built-in kallsyms symbol table for drgn symbol lookup. Combined with an
alternative type information source, this can enable debugging Linux kernel core
dumps without the corresponding DWARF debuginfo files. Even without type
information, kallsyms can be used to help locate objects, and drgn's low-level
memory reading functions can be used to do basic debugging tasks.
"""
import os
import re
from typing import Dict

from _drgn import (
    _linux_helper_load_builtin_kallsyms,
    _linux_helper_load_proc_kallsyms as load_proc_kallsyms,
)
from drgn import Program, ProgramFlags, SymbolIndex

__all__ = (
    "load_builtin_kallsyms",
    "load_proc_kallsyms",
    "load_vmlinux_kallsyms",
)


def _vmcoreinfo_symbols(prog: Program) -> Dict[str, int]:
    vmcoreinfo_data = prog["VMCOREINFO"].string_().decode("ascii")
    vmcoreinfo_symbols = {}
    sym_re = re.compile(r"SYMBOL\(([^)]+)\)=([A-Fa-f0-9]+)")
    for line in vmcoreinfo_data.strip().split("\n"):
        match = sym_re.fullmatch(line)
        if match:
            vmcoreinfo_symbols[match.group(1)] = int(match.group(2), 16)
    return vmcoreinfo_symbols


def load_builtin_kallsyms(prog: Program) -> SymbolIndex:
    """
    Create a symbol index using built-in kallsyms data

    This function automatically finds the locations of the built-in kallsyms
    data structures using the program's VMCOREINFO data. It parses these data
    structures and returns an index of all vmlinux symbols. It can do this
    without any pre-existing symbol or type information.

    It supports live kernels and core dumps, but may fail if necessary data is
    not present within VMCOREINFO. The debugged Linux kernel must be 6.0 or
    later to find this information.  If the information is not available, then
    you could still be able to fall back to :func:`load_proc_kallsyms()`, which
    supports older kernels, but only for live debugging (not core dumps).

    :returns: a symbol index containing kallsyms for the core kernel (vmlinux)
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
    return _linux_helper_load_builtin_kallsyms(prog, *args)


def load_vmlinux_kallsyms(prog: Program) -> SymbolIndex:
    """
    Create a kallsyms index for vmlinux

    There are two options for loading vmlinux kallsyms data:
    :func:`load_proc_kallsyms()` and :func:`load_builtin_kallsyms()`. Which to
    use depends on whether the debugged program is live, and whether the current
    user has root privileges. This helper picks the choice to load vmlinux
    kallsyms.

    :returns: a symbol index containing kallsyms for the core kernel (vmlinux)
    """
    if prog.flags & ProgramFlags.IS_LIVE and os.geteuid() == 0:
        return load_proc_kallsyms()
    else:
        return load_builtin_kallsyms(prog)
