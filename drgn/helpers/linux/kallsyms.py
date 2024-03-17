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
    _linux_helper_load_proc_kallsyms as _load_proc_kallsyms,
)
from drgn import Program, ProgramFlags, SymbolIndex

__all__ = (
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


def _load_builtin_kallsyms(prog: Program) -> SymbolIndex:
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

    This function loads the kallsyms for the core kernel and returns a symbol
    index. This function does not require that any debuginfo is loaded for the
    kernel: it either relies on ``/proc/kallsyms`` (which requires running drgn
    as root) or it parses internal data structures using information found from
    the VMCOREINFO note (which requires Linux 6.0 or later, or a backport of
    commit ``f09bddbd86619 ("vmcoreinfo: add kallsyms_num_syms symbol")`` and
    its dependencies).

    :returns: a symbol index containing kallsyms for the core kernel (vmlinux)
    """
    if prog.flags & ProgramFlags.IS_LIVE and os.geteuid() == 0:
        return _load_proc_kallsyms()
    else:
        return _load_builtin_kallsyms(prog)
