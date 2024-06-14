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

from drgn import FindObjectFlags, Object, Program, ProgramFlags
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

    single_decl = "\\*?\\s*[a-zA-Z_]\\w*(?:\\s*\\[\\d*\\])*\\s*"
    declarator_list = re.compile(
        "(?:" + single_decl + ",\\s*)*" + single_decl + ";\\s*$"
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


def load_builtin_btf(prog: Program, declarations: Optional[str] = None) -> None:
    """
    Use built-in BPF Type Format (BTF) data for debugging the kernel

    This loads the built-in BTF data for the kernel and uses it for type
    finding, as well as limited object finding. As of Linux 7.1, the kernel BTF
    does not contain mappings of variable names to types, but it does contain
    the definitions of all types.

    In order to provide a fuller debugging experience, kallsyms is loaded as
    well, and a small number of hardcoded declarations are used to help
    bootstrap kernel module discovery.

    :param prog: Program for debugging
    :param declarations: C-style declarations to create a supplemental object
      finder. If not provided, a minimal set of declarations will be provided in
      order to allow drgn to load module BTF. See
      :func:`build_c_declaration_object_finder`
    """
    # First, we need the built-in kallsyms
    finder = load_vmlinux_kallsyms(prog)
    prog.register_symbol_finder("vmlinux_kallsyms", finder, enable_index=0)

    # Create the main module if not already existing
    kernel = prog.main_module("kernel", create=True)
    kernel.address_range = (
        prog.symbol("_stext").address,
        prog.symbol("_end").address,
    )

    use_kernfs = (
        prog.flags & (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)
        == (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)
    ) and os.path.isdir("/sys/kernel/btf")

    # Load vmlinux BTF
    if use_kernfs:
        btf = open("/sys/kernel/btf/vmlinux", "rb").read()
    else:
        btf = prog.read(
            prog.symbol("__start_BTF").address,
            prog.symbol("__stop_BTF").address - prog.symbol("__start_BTF").address,
        )
    kernel.load_btf(data=btf, main_module_base=False)

    # Finders for necessary objects to iterate modules and BTF
    if not declarations:
        declarations = "struct list_head modules, btf_modules, slab_caches;"
    ofind = build_c_declaration_object_finder(declarations)
    prog.register_object_finder("btf_manual_globals", ofind, enable_index=1)

    # Load module BTF
    mod_to_btf = {}
    if use_kernfs:
        for name in os.listdir("/sys/kernel/btf"):
            if name != "vmlinux":
                mod_to_btf[name] = open(f"/sys/kernel/btf/{name}", "rb").read()
    else:
        for btf_mod in list_for_each_entry(
            "struct btf_module", prog["btf_modules"].address_of_(), "list"
        ):
            name = btf_mod.module.name.string_().decode()
            mod_to_btf[name] = prog.read(
                btf_mod.btf.data, btf_mod.btf.data_size.value_()
            )

    for module, created in prog.loaded_modules():
        if created:
            module.load_btf(data=mod_to_btf[module.name], main_module_base=True)
    module_finder = load_module_kallsyms(prog)
    prog.register_symbol_finder("module_kallsyms", module_finder, enable_index=1)
