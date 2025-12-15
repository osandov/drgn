# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Modules
-------

The ``drgn.helpers.linux.module`` module contains helpers for working with
loaded kernel modules.
"""
import operator
from typing import Iterable, List, Tuple, Union

from drgn import NULL, IntegerLike, Object, ObjectNotFoundError, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.rbtree import rb_find

__all__ = (
    "address_to_module",
    "find_module",
    "for_each_module",
    "module_address_regions",
    "module_percpu_region",
    "module_taints",
)


@takes_program_or_default
def for_each_module(prog: Program) -> Iterable[Object]:
    """
    Returns all loaded kernel modules

    :returns: Iterable of ``struct module *`` objects
    """
    return list_for_each_entry("struct module", prog["modules"].address_of_(), "list")


@takes_program_or_default
def find_module(prog: Program, name: Union[str, bytes]) -> Object:
    """
    Lookup a kernel module by name, or return NULL if not found

    :param name: name to search for
    :returns: the ``struct module *`` by that name, or NULL
    """
    if isinstance(name, str):
        name = name.encode()
    for module in for_each_module(prog):
        if module.name.string_() == name:
            return module
    return NULL(prog, "struct module *")


def module_percpu_region(mod: Object) -> Tuple[int, int]:
    """
    Lookup the percpu memory region of a module.

    Given a ``struct module *``, return the address (as a an int) and the length
    of the percpu memory region. Modules may have a NULL percpu region, in which
    case (0, 0) is returned. Rarely, on kernels without ``CONFIG_SMP``, there is
    no percpu region at all, and this function returns (0, 0)

    :param mod: Object of type ``struct module *``
    :returns: (base, size) of the module percpu region
    """
    try:
        return mod.percpu.value_(), mod.percpu_size.value_()
    except AttributeError:
        return 0, 0


def _range_from_module_layout(layout: Object) -> Tuple[int, int]:
    # For "struct module_layout" (old) or "struct module_memory"
    return layout.base.value_(), layout.size.value_()


def _range_from_module(module: Object, kind: str) -> Tuple[int, int]:
    # For reading a range directly from "struct module" (old kernels)
    return (
        module.member_(f"module_{kind}").value_(),
        module.member_(f"{kind}_size").value_(),
    )


def _ranges_from_module_memory(mod: Object) -> List[Tuple[int, int]]:
    # For reading all ranges from a modules "struct module_memory"
    return [_range_from_module_layout(mem) for mem in mod.mem]


def module_address_regions(mod: Object) -> List[Tuple[int, int]]:
    """
    Returns a list of address ranges for a module

    Given a ``struct module *``, return every address range associated with the
    module. Note that the number of address ranges and their interpretations
    vary across kernel versions. Some kernel versions provide additional
    information about some regions (e.g. text, data, R/O, init). This API
    doesn't distinguish. However, this API does not provide the module's percpu
    region: use ``module_percpu_region()`` for that.

    :param mod: Object of type ``struct module *``
    :returns: list of tuples: (starting memory address, length of address range)
    """
    try:
        # Since Linux 6.4, ac3b432839234 ("module: replace module_layout with
        # module_memory"), module address regions are broken into several types,
        # each with their own base and size.
        mod.prog_.constant("MOD_MEM_NUM_TYPES")
    except LookupError:
        pass
    else:
        return _ranges_from_module_memory(mod)

    try:
        # Prior to 6.4, there were two "struct module_layout" objects,
        # core_layout and init_layout, which contained the module's memory
        # layout and any memory which could be freed after init. The init_layout
        # is usually NULL / size 0. The module_layout structure has more
        # information to say where text ends, where rodata ends, etc. We ignore
        # these.
        core = _range_from_module_layout(mod.core_layout)
        init = _range_from_module_layout(mod.init_layout)
    except AttributeError:
        # Prior to 4.5, 7523e4dc5057 ("module: use a structure to encapsulate
        # layout."), the layout information was stored as variables directly in
        # the struct module. They were prefixed with "core_" and "init_".
        core = _range_from_module(mod, "core")
        init = _range_from_module(mod, "init")

    ret = [core]
    if init:
        ret.append(init)
    return ret


def _addrmod_tree(mod_tree: Object, addr: int) -> Object:
    prog = mod_tree.prog_

    # The module tree is "latched": there are two parallel trees. Which one is
    # in use depends on the seqcount, which gets incremented for each
    # modification. This is a really neat approach that allows reads in parallel
    # with a writer. In our use case, it's probably not worth verifying the
    # seqcount after the fact. What we do need is the index (0 or 1). This may
    # be a seqcount_latch_t, or before 24bf401cebfd6 ("rbtree_latch: Use
    # seqcount_latch_t"), a regular seqcount_t.
    try:
        idx = mod_tree.root.seq.seqcount.sequence.value_() & 1
    except AttributeError:
        idx = mod_tree.root.seq.sequence.value_() & 1

    # In ac3b432839234 ("module: replace module_layout with module_memory"),
    # struct module_layout was replaced by module_memory. The module_layout
    # encoded the separate regions (text, data, rodata, etc) in a single
    # structure, whereas module_memory is a simple base pointer followed by a
    # size: one module_memory structure is used per kind of memory. However,
    # both of them contain a "base" pointer that indicates the start of the
    # region, a "size" that indicates its total size, and a "mtn.mod" pointer
    # which refers to the relevant module. So for our use case, they are
    # interchangeable, except for their names.
    try:
        tp = prog.type("struct module_memory")
    except LookupError:
        tp = prog.type("struct module_layout")

    def cmp(v: int, node: Object) -> int:
        start = node.base.value_()
        end = start + node.size.value_()
        if v < start:
            return -1
        elif v >= end:
            return 1
        else:
            return 0

    mem = rb_find(
        tp,
        mod_tree.root.tree[idx].address_of_(),
        f"mtn.node.node[{idx}]",  # container_of allows array indices!
        addr,
        cmp,
    )
    if mem:
        return mem.mtn.mod
    else:
        return NULL(prog, "struct module *")


@takes_program_or_default
def address_to_module(prog: Program, addr: IntegerLike) -> Object:
    """
    Return the ``struct module *`` associated with a memory address

    If the address is a text, data, or read-only data address associated with a
    kernel module, then this function returns the module it is associated with.
    Otherwise, returns NULL. Note that dynamic memory (e.g. slab objects)
    generally can't be associated with the module that allocated it. Further,
    static & dynamic per-cpu address cannot be associated with their associated
    module either.

    Normally, this lookup is efficient, thanks to
    ``CONFIG_MODULES_TREE_LOOKUP``, which provides a red-black tree of module
    address ranges, and is `very commonly`__ enabled. However, on some uncommon
    configurations the rbtree may not be present. In those cases, we fall back
    to a linear search of each kernel module's memory regions.

    .. __: https://oracle.github.io/kconfigs/?config=MODULES_TREE_LOOKUP&config=UTS_RELEASE

    :param addr: memory address to lookup
    :returns: the ``struct module *`` associated with the memory, or NULL
    """
    addr = operator.index(addr)
    try:
        mod_tree = prog["mod_tree"]
    except LookupError:
        pass
    else:
        return _addrmod_tree(mod_tree, addr)

    for module in for_each_module(prog):
        for start, length in module_address_regions(module):
            if start <= addr < start + length:
                return module

    return NULL(prog, "struct module *")


def module_taints(module: Object) -> str:
    """
    Get a kernel module's taint flags as a string.

    If the module did not taint the kernel, then this returns an empty string:

    >>> module_taints(module)
    ''

    Otherwise, it returns the flags as letters (without spaces):

    >>> module_taints(module)
    'O'

    See the `kernel documentation
    <https://docs.kernel.org/admin-guide/tainted-kernels.html>`_ for an
    explanation of the flags.

    :param module: ``struct module *``
    """
    mask = module.taints.value_()
    if not mask:
        return ""

    # Before Linux kernel commit 37ade54f386c ("taint/module: remove
    # unnecessary taint_flag.module field") (in v6.19), there was a distinction
    # between what taint flags could and couldn't be set on a module. The
    # distinction is unnecessary for us since we don't need a statically-sized
    # buffer.
    parts = []
    try:
        taint_flags = module.prog_["taint_flags"]
    except ObjectNotFoundError:
        # Before Linux kernel commit 7fd8329ba502 ("taint/module: Clean up
        # global and module taint flags handling") (in v4.10), the array and
        # members had different names and the bit number was a member.
        for t in module.prog_["tnts"]:
            if mask & (1 << t.bit.value_()):
                parts.append(chr(t.true))  # type: ignore[arg-type]  # python/typeshed#13494
    else:
        for i, t in enumerate(taint_flags):
            if mask & (1 << i):
                parts.append(chr(t.c_true))  # type: ignore[arg-type]  # python/typeshed#13494
    return "".join(parts)
