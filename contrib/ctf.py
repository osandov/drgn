# Copyright (c) 2025 Oracle and/or its affiliates
"""
Plugin for loading CTF debuginfo
"""
import logging
import os
from typing import List

from drgn import Program
from drgn import ProgramFlags
from drgn import MainModule
from drgn import Module
from drgn import ModuleFileStatus
from drgn import RelocatableModule
from drgn.helpers.linux.kallsyms import load_module_kallsyms
from drgn.helpers.linux.kallsyms import load_vmlinux_kallsyms

try:
    from _drgn import _linux_helper_load_ctf

    HAVE_CTF = True
except ImportError:
    HAVE_CTF = False


CTF_PATHS = [
    "./vmlinux.ctfa",
    "/lib/modules/{uname}/kernel/vmlinux.ctfa",
]

TAINT_OOT_MODULE = 12
logger = logging.getLogger("drgn.plugin.ctf")


def ctf_debuginfo_finder(modules: List[Module]):
    prog = modules[0].prog

    ctf_loaded = "vmlinux_kallsyms" in prog.registered_symbol_finders()
    logger.debug("ctf: enter debuginfo finder ctf_loaded=%r", ctf_loaded)

    for module in modules:
        if isinstance(module, MainModule) and not ctf_loaded:
            uname = prog["UTS_RELEASE"].string_().decode()
            for path in CTF_PATHS:
                path = path.format(uname=uname)
                if os.path.isfile(path):
                    _linux_helper_load_ctf(prog, path)
                    finder = load_vmlinux_kallsyms(prog)
                    prog.register_symbol_finder("vmlinux_kallsyms", finder, enable_index=0)
                    module.address_range = (
                        prog.symbol("_stext").address,
                        prog.symbol("_end").address,
                    )
                    finder = load_module_kallsyms(prog)
                    prog.register_symbol_finder("module_kallsyms", finder, enable_index=1)
                    ctf_loaded = True
                    module.debug_file_status = ModuleFileStatus.DONT_NEED
                    logger.debug("ctf: load %s", path)
                    break
            else:
                logger.debug("failed to find vmlinux.ctfa")
        elif isinstance(module, RelocatableModule) and ctf_loaded:
            # CTF contains symbols for all in-tree modules. Mark them DONT_NEED
            if not module.object.taints & TAINT_OOT_MODULE:
                module.debug_file_status = ModuleFileStatus.DONT_NEED


def drgn_prog_set(prog: Program) -> None:
    if prog.flags & ProgramFlags.IS_LINUX_KERNEL and HAVE_CTF:
        prog.register_debug_info_finder("ctf", ctf_debuginfo_finder)
