# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Memory
------

The ``drgn.helpers.common.memory`` module provides helpers for working with memory and addresses.
"""

import operator
import os
import typing
from typing import Any, Dict, Optional

import drgn
from drgn import (
    FaultError,
    IntegerLike,
    Object,
    PlatformFlags,
    Program,
    SymbolKind,
    cast,
)
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.mm import (
    PageSlab,
    compound_head,
    find_vmap_area,
    pfn_to_virt,
    virt_to_page,
)
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.slab import _get_slab_cache_helper, _get_slab_type

__all__ = (
    "identify_address",
    "print_annotated_memory",
)


_SYMBOL_KIND_STR = {
    SymbolKind.OBJECT: "object symbol",
    SymbolKind.FUNC: "function symbol",
}


def _identify_kernel_vmap(
    prog: Program, addr: int, cache: Optional[Dict[Any, Any]] = None
) -> Optional[str]:
    va = find_vmap_area(prog, addr)
    if not va:
        return None

    vm = va.vm.read_()
    if not vm:
        return None

    task: Optional[Object]
    # The cached and uncached cases are separate so that we can avoid creating
    # a large cache and stop early in the uncached case.
    if cache is None:
        for task in for_each_task(prog):
            try:
                if task.stack_vm_area == vm:
                    break
            except AttributeError:
                # CONFIG_VMAP_STACK must be disabled.
                break
            except FaultError:
                continue
        else:
            task = None
    else:
        try:
            stack_vm_area_to_task = cache["stack_vm_area_to_task"]
        except KeyError:
            stack_vm_area_to_task = {}
            for task in for_each_task(prog):
                try:
                    stack_vm_area_to_task[task.stack_vm_area.value_()] = task
                except AttributeError:
                    # CONFIG_VMAP_STACK must be disabled.
                    break
                except FaultError:
                    continue
            cache["stack_vm_area_to_task"] = stack_vm_area_to_task
        task = stack_vm_area_to_task.get(vm.value_())

    if task is not None:
        return (
            f"vmap stack: {task.pid.value_()}"
            f" ({os.fsdecode(task.comm.string_())})"
            f" +{hex(addr - task.stack.value_())}"
        )

    caller = ""
    caller_value = vm.caller.value_()
    try:
        caller_sym = prog.symbol(caller_value)
    except LookupError:
        pass
    else:
        caller = f" caller {caller_sym.name}+{hex(caller_value - caller_sym.address)}"
    return f"vmap: {hex(va.va_start)}-{hex(va.va_end)}{caller}"


def _identify_kernel_address(
    prog: Program, addr: int, cache: Optional[Dict[Any, Any]] = None
) -> Optional[str]:
    try:
        direct_map_start = pfn_to_virt(prog["min_low_pfn"]).value_()
        direct_map_end = (pfn_to_virt(prog["max_low_pfn"]) + prog["PAGE_SIZE"]).value_()
        in_direct_map = direct_map_start <= addr < direct_map_end
    except NotImplementedError:
        # Virtual address translation isn't implemented for this
        # architecture.
        in_direct_map = False
    if in_direct_map:
        page = virt_to_page(prog, addr)

        try:
            head_page = compound_head(page)
            is_slab = PageSlab(head_page)
        except FaultError:
            return None

        if is_slab:
            slab = cast(_get_slab_type(prog), head_page)
            slab_info = _get_slab_cache_helper(slab.slab_cache).object_info(
                head_page, slab, addr
            )
            if slab_info:
                cache_name = escape_ascii_string(
                    slab_info.slab_cache.name.string_(), escape_backslash=True
                )
                maybe_free = "" if slab_info.allocated else "free "
                return f"{maybe_free}slab object: {cache_name}+{hex(addr - slab_info.address)}"
    else:
        return _identify_kernel_vmap(prog, addr, cache)
    return None


@takes_program_or_default
def identify_address(
    prog: Program, addr: IntegerLike, *, cache: Optional[Dict[Any, Any]] = None
) -> Optional[str]:
    """
    Try to identify what an address refers to.

    For all programs, this will identify addresses as follows:

    * Object symbols (e.g., addresses in global variables):
      ``object symbol: {symbol_name}+{hex_offset}`` (where ``hex_offset`` is
      the offset from the beginning of the symbol in hexadecimal).
    * Function symbols (i.e., addresses in functions):
      ``function symbol: {symbol_name}+{hex_offset}``.
    * Other symbols: ``symbol: {symbol_name}+{hex_offset}``.

    Additionally, for the Linux kernel, this will identify:

    * Allocated slab objects: ``slab object: {slab_cache_name}+{hex_offset}``
      (where ``hex_offset`` is the offset from the beginning of the object in
      hexadecimal).
    * Free slab objects: ``free slab object: {slab_cache_name}+{hex_offset}``.
    * Vmap addresses (e.g., vmalloc, ioremap):
      ``vmap: {hex_start_address}-{hex_end_address}``. If the function that
      allocated the vmap is known, this also includes
      ``caller {function_name}+{hex_offset}``.
    * Vmap kernel stacks: ``vmap stack: {pid} ({comm}) +{hex_offset}`` (where
      ``pid`` and ``comm`` identify the task and ``hex_offset`` is the offset
      from the beginning of the stack in hexadecimal).

    This may recognize other types of addresses in the future.

    :param addr: ``void *``
    :param cache: Opaque cache used to amortize expensive lookups. If you're
        going to call this function many times in a short period, create an
        empty dictionary and pass the same dictionary as *cache* to each call.
        Don't reuse it indefinitely or you may get stale results.
    :return: Identity as string, or ``None`` if the address is unrecognized.
    """
    addr = operator.index(addr)

    # Check if address is of a symbol:
    try:
        symbol = prog.symbol(addr)
    except LookupError:  # not a symbol
        pass
    else:
        symbol_kind = _SYMBOL_KIND_STR.get(symbol.kind, "symbol")
        return f"{symbol_kind}: {symbol.name}+{hex(addr - symbol.address)}"

    if prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL:
        # Linux kernel-specific identification:
        return _identify_kernel_address(prog, addr, cache)
    return None


@takes_program_or_default
def print_annotated_memory(
    prog: Program, address: IntegerLike, size: IntegerLike, physical: bool = False
) -> None:
    """
    Print the contents of a range of memory, annotating values that can be
    identified.

    Currently, this will identify any addresses in the memory range with
    :func:`~drgn.helpers.common.memory.identify_address()`.

    See :func:`~drgn.helpers.common.stack.print_annotated_stack()` for a
    similar function that annotates stack traces.

    >>> print_annotated_memory(0xffffffff963eb200, 56)
    ADDRESS           VALUE
    ffffffff963eb200: 00000000000000b8
    ffffffff963eb208: 000000000000a828
    ffffffff963eb210: 0000000000000000
    ffffffff963eb218: ffff8881042948e0 [slab object: mnt_cache+0x20]
    ffffffff963eb220: ffff88810074a540 [slab object: dentry+0x0]
    ffffffff963eb228: ffff8881042948e0 [slab object: mnt_cache+0x20]
    ffffffff963eb230: ffff88810074a540 [slab object: dentry+0x0]

    :param address: Starting address.
    :param size: Number of bytes to read.
    :param physical: Whether *address* is a physical memory address. If
        ``False``, then it is a virtual memory address.
    """
    address = operator.index(address)
    mem = prog.read(address, size, physical)

    # The platform must be known if we were able to read memory.
    assert prog.platform is not None

    byteorder: 'typing.Literal["little", "big"]'
    if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
        byteorder = "little"
    else:
        byteorder = "big"

    if prog.platform.flags & PlatformFlags.IS_64_BIT:
        word_size = 8
        line_format = "{:016x}: {:016x}{}"
        print("ADDRESS           VALUE")
    else:
        word_size = 4
        line_format = "{:08x}: {:08x}{}"
        print("ADDRESS   VALUE")

    cache: Dict[Any, Any] = {}
    for offset in range(0, len(mem), word_size):
        value = int.from_bytes(mem[offset : offset + word_size], byteorder)
        identified = identify_address(prog, value, cache=cache)
        if identified is None:
            identified = ""
        else:
            identified = f" [{identified}]"
        print(line_format.format(address + offset, value, identified))
