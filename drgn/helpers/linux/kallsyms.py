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
from typing import Dict, List, Tuple

from _drgn import (
    _linux_helper_load_builtin_kallsyms,
    _linux_helper_load_proc_kallsyms as _load_proc_kallsyms,
)
from drgn import (
    Object,
    Program,
    ProgramFlags,
    Symbol,
    SymbolBinding,
    SymbolIndex,
    SymbolKind,
)
from drgn.helpers.linux.module import for_each_module

__all__ = (
    "load_vmlinux_kallsyms",
    "load_module_kallsyms",
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


def _nm_type_to_binding_kind(code: str) -> Tuple[SymbolBinding, SymbolKind]:
    binding = SymbolBinding.UNKNOWN
    kind = SymbolKind.UNKNOWN
    if code == "v":
        binding = SymbolBinding.WEAK
        kind = SymbolKind.OBJECT
    elif code == "w":
        binding = SymbolBinding.WEAK
    elif code in "tT":
        kind = SymbolKind.FUNC
    elif code.lower() in "srbgncd":
        kind = SymbolKind.OBJECT
    if binding == SymbolBinding.UNKNOWN and code.isupper():
        binding = SymbolBinding.GLOBAL
    return binding, kind


def _st_info_to_binding_kind(info: int) -> Tuple[SymbolBinding, SymbolKind]:
    binding_int = info >> 4
    STB_WEAK = 2
    STB_GNU_UNIQUE = 10
    if binding_int <= STB_WEAK or binding_int == STB_GNU_UNIQUE:
        binding = SymbolBinding(binding_int + 1)
    else:
        binding = SymbolBinding.UNKNOWN
    type_ = info & 0xF
    STT_TLS = 6
    STT_GNU_IFUNC = 10
    if type_ <= STT_TLS or type_ == STT_GNU_IFUNC:
        kind = SymbolKind(type_)
    else:
        kind = SymbolKind.UNKNOWN
    return binding, kind


def _elf_sym_to_symbol(name: str, obj: Object, has_typetab: bool) -> Symbol:
    # Linux likes to have the nm(1) character code for its symbols, which it
    # refers to as the symbol's "type" (this is of course distinct from the ELF
    # notion of a symbol type, let alone what drgn considers a "type"...).
    #
    # Prior to 5439c985c5a8 ("module: Overwrite st_size instead of st_info"),
    # merged in v5.0, the kernel simply overwrote the "st_info" field with a
    # single-character code that represents the nm(1) character code for that
    # symbol. However, starting with that commit, it was switched to overwrite
    # the "st_size" field instead! This was thankfully fixed in v5.2 with
    # 1c7651f43777 ("kallsyms: store type information in its own array").
    #
    # Unfortunately, this leaves us with three possibilities:
    # 1. Pre-v5.0: interpret the "st_info" as a character from nm(1) and try to
    #    infer the kind and bindings.
    # 2. 5.0-5.2: interpret the "st_info" as normal, but ignore the "st_size"
    #    field since it is bogus.
    # 3. 5.2+: both fields are valid, and the nm(1) code is stored in "typetab".
    #
    # Case 3 can be determined easily by the presence of "typetab" in "struct
    # mod_kallsyms". However, cases 1 & 2 are indistinguishable. For our
    # purposes, it makes more sense to fall back to case 1. After all, neither
    # 5.0 or 5.1 were LTS kernels, nor are they actively used by any major
    # distro. We have no way to deal with 5.0 or 5.1, whereas we can make some
    # informed guesses for pre-5.0 based on the nm(1) code.
    if has_typetab:
        binding, kind = _st_info_to_binding_kind(obj.st_info.value_())
    else:
        binding, kind = _nm_type_to_binding_kind(chr(obj.st_info.value_()))
    return Symbol(  # type: ignore
        name,
        obj.st_value.value_(),
        obj.st_size.value_(),
        binding,
        kind,
    )


def _module_kallsyms(module: Object) -> List[Symbol]:
    try:
        ks = module.kallsyms
    except AttributeError:
        # Prior to 8244062ef1e54 ("modules: fix longstanding /proc/kallsyms vs
        # module insertion race."), the kallsyms variables were stored directly
        # on the module object. This commit was introduced in 4.5, but was
        # backported to some stable kernels too. Fall back to the module object
        # in cases where kallsyms field isn't available.
        ks = module

    prog = module.prog_
    num_symtab = ks.num_symtab.value_()
    try:
        ks.member_("typetab")
        has_typetab = True
    except LookupError:
        has_typetab = False

    # The symtab field is a pointer, but it points at an array of Elf_Sym
    # objects. Indexing it requires drgn to do pointer arithmetic and issue a
    # lot of very small /proc/kcore reads, which can be a real performance
    # issue. So convert it into an object representing a correctly-sized array,
    # and then read that object all at once. This does one /proc/kcore read,
    # which is a major improvement!
    symtab = Object(
        prog,
        type=prog.array_type(ks.symtab.type_.type, num_symtab),
        address=ks.symtab.value_(),
    ).read_()

    # The strtab is similarly a pointer into a contigous array of strings packed
    # next to each other. Reading individual strings from /proc/kcore can be
    # quite slow. So read the entire array of bytes into a Python bytes value,
    # and we'll extract the individual symbol strings from there.
    last_string_start = symtab[num_symtab - 1].st_name.value_()
    last_string_len = len(ks.strtab[last_string_start].address_of_().string_()) + 1
    strtab = prog.read(ks.strtab.value_(), last_string_start + last_string_len)
    syms = []
    for i in range(ks.num_symtab.value_()):
        elfsym = symtab[i]
        if not elfsym.st_name:
            continue
        str_index = elfsym.st_name.value_()
        nul_byte = strtab.find(b"\x00", str_index)
        name = strtab[str_index:nul_byte].decode("ascii")
        syms.append(_elf_sym_to_symbol(name, elfsym, has_typetab))
    return syms


def load_module_kallsyms(prog: Program) -> SymbolIndex:
    """
    Return a symbol index containing all module symbols from kallsyms

    For kernels built with ``CONFIG_KALLSYMS``, loaded kernel modules contain
    an ELF symbol table in kernel memory. This function can parse those data
    structures and create a symbol index usable by drgn. However, it requires
    that you already have debuginfo for the vmlinux image.

    :returns: a symbol index containing all symbols from module kallsyms
    """
    all_symbols = []
    for module in for_each_module(prog):
        all_symbols.extend(_module_kallsyms(module))
    return SymbolIndex(all_symbols)
