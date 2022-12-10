# Copyright (c) 2022, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Module
------

The ``drgn.helpers.linux.module`` module contains helpers for working with Linux
Kernel Modules.
"""

from typing import Iterable, NamedTuple, Optional, Tuple, Union, overload

from drgn import IntegerLike, Object, Program
from drgn.helpers.linux.list import list_for_each_entry

__all__ = (
    "ModuleLayout",
    "address_to_module",
    "for_each_module",
    "module_address_region",
)


class ModuleLayout(NamedTuple):
    """
    Represents a module's layout in memory.

    Module memory layout is organized into three sections. First is the text
    section, which is read-only (RO). Next is the RO data section, which is
    usually protected with no-execute (NX) permissions. Next is additional data
    which becomes RO after init, and finally is the RW data. The below diagram
    from the kernel source code demonstrates this layout (note that for clarity,
    we refer to ``size`` as ``total_size``).

    .. code-block::

      General layout of module is:
               [text] [read-only-data] [ro-after-init] [writable data]
      text_size -----^                ^               ^               ^
      ro_size ------------------------|               |               |
      ro_after_init_size -----------------------------|               |
      size -----------------------------------------------------------|
    """

    base: Object
    """The base address of the memory region, as a ``void *``."""
    total_size: int
    """The total length of the memory region."""
    text_size: int
    """The length of the text section."""
    ro_size: int
    """The length of the read-only memory (text, and RO data)"""
    ro_after_init_size: int
    """The length of the read-only memory, plus memory which is RO after init"""

    def contains(self, address: IntegerLike) -> bool:
        offset = int(address) - self.base.value_()
        return 0 <= offset < self.total_size


def _layout_from_module_layout(layout: Object) -> ModuleLayout:
    try:
        ro_after_init_size = layout.ro_after_init_size.value_()
    except AttributeError:
        # Prior to 4.8, 444d13ff10fb ("modules: add ro_after_init support"),
        # there was no ro_after_init support. Pretend it existed and it was just
        # zero-length.
        ro_after_init_size = layout.ro_size.value_()
    return ModuleLayout(
        layout.base,
        layout.size.value_(),
        layout.text_size.value_(),
        layout.ro_size.value_(),
        ro_after_init_size,
    )


def _layout_from_module(module: Object, kind: str) -> ModuleLayout:
    return ModuleLayout(
        module.member_(f"module_{kind}"),
        module.member_(f"{kind}_size").value_(),
        module.member_(f"{kind}_text_size").value_(),
        module.member_(f"{kind}_ro_size").value_(),
        module.member_(f"{kind}_ro_size").value_(),
    )


def module_address_region(mod: Object) -> ModuleLayout:
    """
    Lookup the core memory region of a module.

    Given a ``struct module *``, return the address and length of its code and
    data. This region ignores the "__init" data of the module; see
    :func:`module_init_region()` to find that.

    :param mod: Object of type ``struct module *``
    :returns: A tuple representing the address and size of the memory, along
      with the size of various protection zones within.
    """
    try:
        return _layout_from_module_layout(mod.core_layout)
    except AttributeError:
        # Prior to 4.5, 7523e4dc5057 ("module: use a structure to encapsulate
        # layout."), the layout information was stored as plain fields on the
        # module.
        return _layout_from_module(mod, "core")


def module_init_region(mod: Object) -> Optional[ModuleLayout]:
    """
    Lookup the init memory region of a module.

    Given a ``struct module *``, return the address and length of the ``__init``
    memory regions. This memory is typically freed after the module is loaded,
    so under most circumstances, this will return None.

    :param mod: Object of type ``struct module *``
    :returns: A tuple representing the layout of the init memory
    """
    try:
        layout = _layout_from_module_layout(mod.init_layout)
    except AttributeError:
        layout = _layout_from_module(mod, "init")
    if not layout.base.value_():
        return None
    return layout


def module_percpu_region(mod: Object) -> Optional[Tuple[Object, int]]:
    """
    Lookup the percpu memory region of a module.

    Given a ``struct module *``, return the address and the length of the percpu
    memory region. Modules may have a NULL percpu region, in which case ``(void
    *)NULL`` is returned. Rarely, on kernels without ``CONFIG_SMP``, there is no
     percpu region at all, and this function returns ``None``.

    :param mod: Object of type ``struct module *``
    :returns: A tuple containing the base address and length of the region
    """
    try:
        return mod.percpu, mod.percpu_size.value_()
    except AttributeError:
        return None


def for_each_module(prog: Program) -> Iterable[Object]:
    """
    Get all loaded kernel module objects

    :param prog: Program being debugged
    :returns: Iterable of ``struct module *`` objects
    """
    return list_for_each_entry("struct module", prog["modules"].address_of_(), "list")


def find_module(prog: Program, name: Union[str, bytes]) -> Optional[Object]:
    """
    Return the module with the given name

    :param name: Module name
    :returns: if found, ``struct module *``
    """
    if isinstance(name, str):
        name = name.encode()
    for module in for_each_module(prog):
        if module.name.string_() == name:
            return module
    return None


@overload
def address_to_module(addr: Object) -> Optional[Object]:
    """"""
    ...


@overload
def address_to_module(prog: Program, addr: IntegerLike) -> Optional[Object]:
    """
    Try to find the module corresponding to a memory address.

    Search for the given address in the list of loaded kernel modules. If it is
    within the address range corresponding to a kernel module, return that
    module. This function searches the module's core (normal memory) region, the
    module's init region (if present) and the module's percpu region (if
    present).

    This helper performs a linear search of the list of modules, which could
    grow quite large. As a result, the performance may suffer on repeated
    lookups.

    :param addr: address to lookup
    :returns: if the address corresponds to a module, ``struct module *``
    """
    ...


def address_to_module(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object],
    addr: Optional[IntegerLike] = None,
) -> Optional[Object]:
    if addr is None:
        assert isinstance(prog_or_addr, Object)
        prog = prog_or_addr.prog_
        addr = prog_or_addr.value_()
    else:
        assert isinstance(prog_or_addr, Program)
        prog = prog_or_addr
        addr = int(addr)

    for module in for_each_module(prog):
        region = module_address_region(module)
        if region.contains(addr):
            return module
        pcpu_region = module_percpu_region(module)
        if pcpu_region:
            pcpu, pcpu_len = pcpu_region
            if 0 <= addr - pcpu.value_() < pcpu_len:
                return module
        init_region = module_init_region(module)
        if init_region and init_region.contains(addr):
            return module

    return None
