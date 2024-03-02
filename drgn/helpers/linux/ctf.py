# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
CTF
---

This module contains Python helpers to simplify loading CTF debuginfo and
associated kallsyms symbol info.
"""
import os
from typing import Optional

from _drgn import _linux_helper_load_ctf
from drgn import Program
from drgn.helpers.linux.kallsyms import load_module_kallsyms, load_vmlinux_kallsyms

__all__ = ("load_ctf",)


_CTF_PATHS = [
    "./vmlinux.ctfa",
    "/lib/modules/{uname}/kernel/vmlinux.ctfa",
]


def load_ctf(prog: Program, path: Optional[str] = None) -> None:
    """
    Use Compact Type Format data for debugging.

    This searches the current directory and well-known paths for the
    "vmlinux.ctfa" file associated with this kernel version. If found, we load
    the CTF info, and by default, we also load the built-in kallsyms for our
    symbol table.

    :param prog: Program for debugging
    :param path: specify an alternative path to ``vmlinux.ctfa``
    :param use_kallsyms: whether we should try to load kallsyms too
    """
    uname = prog["UTS_RELEASE"].string_().decode()
    if path and not os.path.isfile(path):
        raise ValueError("CTF Path does not exist")
    elif not path:
        for path in _CTF_PATHS:
            path = path.format(uname=uname)
            if os.path.isfile(path):
                break
        else:
            raise ValueError(f"Could not find CTF data for {uname}")

    _linux_helper_load_ctf(prog, path)

    finder = load_vmlinux_kallsyms(prog)
    prog.register_symbol_finder("vmlinux_kallsyms", finder, enable_index=0)

    # Initialize the module API. While CTF doesn't really require it, the
    # built-in ORC support is based on the kernel module API.
    list(prog.loaded_modules())
    prog.main_module().address_range = (
        prog.symbol("_stext").address,
        prog.symbol("_end").address,
    )

    module_finder = load_module_kallsyms(prog)
    prog.register_symbol_finder("module_kallsyms", module_finder, enable_index=1)
