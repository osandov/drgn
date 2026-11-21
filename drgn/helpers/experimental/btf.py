# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
BTF
---

This module contains Python helpers to simplify loading BTF debuginfo and
associated kallsyms symbol info.
"""
import os
import re
from typing import Callable, Optional

from drgn import FindObjectFlags, ModuleFileStatus, Object, Program, ProgramFlags
from drgn.helpers.linux.kallsyms import load_module_kallsyms, load_vmlinux_kallsyms
from drgn.helpers.linux.list import list_for_each_entry

__all__ = ("build_c_declaration_object_finder", "load_builtin_btf")


def build_c_declaration_object_finder(
    decls: str,
) -> Callable[[Program, str, FindObjectFlags, Optional[str]], Optional[Object]]:
    """
    Create an object finder from C variable declarations

    For all released Linux kernel versions, in-kernel BTF does not contain a
    mapping of variable names to their types or addresses. To make up for this,
    objects whose types are known ahead of time can be created via their
    kallsyms symbol entry. This function creates an object finder using that
    strategy. All that is necessary is to provide a set of C-style declarations,
    such as::

        struct list_head modules, btf_modules;

    The declarations may contain only variable declarations. Fun ction
    declarations, as well as type declarations, are not allowed. C style line
    comments and blank lines are permitted, though multi-line comments are not.

    The returned object finder can be registered with
    :meth:`Program.register_object_finder` and used to access the declared
    variables.

    :param decls: a string containing C-style variable declarations
    :returns: a corresponding object finder
    """
    name_to_type = {}

    single_decl = r"\*?\s*[a-zA-Z_]\w*(?:\s*\[\s*\d*\s*\])*\s*"
    declarator_list = re.compile(
        r"(?:" + single_decl + r",\s*)*" + single_decl + r";\s*$"
    )
    for decl in decls.strip().split("\n"):
        comment_start = decl.find("//")
        if comment_start >= 0:
            decl = decl[:comment_start]
        decl = decl.strip()
        if not decl:
            continue
        m = declarator_list.search(decl)
        if not m:
            raise ValueError("Invalid declaration: {}".format(decl))
        type_string = decl[: -len(m.group(0))]
        for name in m.group(0).rstrip(";").split(","):
            this_type = type_string
            name = name.strip()
            if name.startswith("*"):
                this_type += " *"
                name = name[1:].lstrip()
            start_bracket = name.find("[")
            if start_bracket > 0:
                this_type += " " + name[start_bracket:]
                name = name[:start_bracket]
            name_to_type[name.strip()] = this_type

    def ofind(
        prog: Program, name: str, flags: FindObjectFlags, filename: Optional[str]
    ) -> Optional[Object]:
        if flags & FindObjectFlags.VARIABLE and name in name_to_type:
            return Object(prog, name_to_type[name], address=prog.symbol(name).address)
        return None

    return ofind


def load_builtin_btf(prog: Program) -> None:
    """
    Use built-in BPF Type Format (BTF) data for debugging the kernel

    This loads the built-in BTF data for the kernel and uses it for type
    finding, as well as limited object finding. This function requires that
    global variable BTF information is present in the debugged kernel. This is
    an unmerged extension to Linux BTF.
    """
    # First, we need the built-in kallsyms
    finder = load_vmlinux_kallsyms(prog)
    prog.register_symbol_finder("vmlinux_kallsyms", finder, enable_index=0)

    # Create the main module if not already existing
    kernel = prog.main_module("kernel", create=True)

    use_kernfs = (
        prog.flags & (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)
        == (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)
    ) and os.path.isdir("/sys/kernel/btf")

    # Load vmlinux base BTF first.
    if use_kernfs:
        with open("/sys/kernel/btf/vmlinux", "rb") as f:
            btf = f.read()
    else:
        btf = prog.read(
            prog.symbol("__start_BTF").address,
            prog.symbol("__stop_BTF").address - prog.symbol("__start_BTF").address,
        )
    kernel.add_btf("main", btf)
    kernel.address_ranges = (
        (prog.symbol("_stext").address, prog.symbol("_etext").address),
    )

    # Now add global variables.
    if use_kernfs:
        with open("/sys/kernel/btf/vmlinux.global", "rb") as f:
            btf = f.read()
    else:
        try:
            # CONFIG_DEBUG_INFO_BTF_GLOBAL=y
            btf = prog.read(
                prog.symbol("__start_BTF_global").address,
                prog.symbol("__stop_BTF_global").address
                - prog.symbol("__start_BTF_global").address,
            )
        except LookupError:
            # CONFIG_DEBUG_INFO_BTF_GLOBAL=m - we can only load global variables
            # if the "btf_vmlinux_global" module is loaded.
            extra_obj = Object(
                prog,
                "struct btf_vmlinux_extra",
                address=prog.symbol("vmlinux_global").address,
            )
            if not extra_obj.attr:
                raise RuntimeError(
                    "The vmcore did not load btf_vmlinux_global module; "
                    "BTF global variables cannot be loaded."
                )
            attr = extra_obj.attr[0].read_()
            btf = prog.read(
                attr.private.value_(),
                attr.size.value_(),
            )
    kernel.add_btf("global", btf)
    kernel.loaded_file_status = ModuleFileStatus.DONT_NEED
    kernel.debug_file_status = ModuleFileStatus.DONT_NEED

    # Load module BTF
    mod_to_btf = {}
    mod_to_global = {}
    if use_kernfs:
        for name in os.listdir("/sys/kernel/btf"):
            if name in ("vmlinux", "btf_vmlinux_global"):
                continue
            if name[-7:] in (".global", ".inline"):
                continue
            with open(f"/sys/kernel/btf/{name}", "rb") as f:
                mod_to_btf[name] = f.read()
            with open(f"/sys/kernel/btf/{name}.global", "rb") as f:
                mod_to_global[name] = f.read()
    else:
        btf_module_tp = prog.type("struct btf_module")
        for btf_mod in list_for_each_entry(
            btf_module_tp, prog["btf_modules"].address_of_(), "list"
        ):
            name = btf_mod.module.name.string_().decode()
            mod_to_btf[name] = prog.read(
                btf_mod.btf,
                btf_mod.btf_data_size.value_(),
            )
            mod_to_global[name] = prog.read(
                btf_mod.btf_global_data,
                btf_mod.btf_global_data_size.value_(),
            )

    prog.create_loaded_modules()
    for name, data in mod_to_btf.items():
        module = prog.module(name)
        module.add_btf("main", data)
        module.add_btf("global", mod_to_global[name])
        module.loaded_file_status = ModuleFileStatus.DONT_NEED
        module.debug_file_status = ModuleFileStatus.DONT_NEED

    # Finally, load module_kallsyms
    module_finder = load_module_kallsyms(prog)
    prog.register_symbol_finder("module_kallsyms", module_finder, enable_index=1)
