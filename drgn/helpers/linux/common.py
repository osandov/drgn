# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Common
------

Linux kernel specializations of :mod:`~drgn.helpers.common` helpers.
"""

import dataclasses
import os
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple, Union

from drgn import FaultError, Object, Program, Symbol, sizeof
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.mm import (
    find_vmap_area,
    for_each_valid_page_range,
    in_direct_map,
)
from drgn.helpers.linux.pid import find_task, for_each_task
from drgn.helpers.linux.sched import idle_task, task_cpu
from drgn.helpers.linux.slab import (
    SlabObjectInfo,
    _find_containing_slab,
    _get_slab_cache_helper,
)

__all__ = ()


@dataclasses.dataclass
class IdentifiedTaskStruct:
    """
    :class:`~drgn.helpers.common.memory.IdentifiedAddress` for an address in a
    ``struct task_struct``.
    """

    address: int

    task: Object
    """``struct task_struct *`` containing the address."""

    def __str__(self) -> str:
        s = (
            f"task: {self.task.pid.value_()}"
            f" ({os.fsdecode(self.task.comm.string_())})"
        )
        task_address = self.task.value_()
        if self.address > task_address:
            s += f" +{hex(self.address - task_address)}"
        return s


@dataclasses.dataclass
class IdentifiedTaskStack:
    """
    :class:`~drgn.helpers.common.memory.IdentifiedAddress` for an address in a
    kernel stack.
    """

    address: int

    task: Object
    """``struct task_struct *`` of the task whose stack contains the address."""

    def __str__(self) -> str:
        return (
            f"vmap stack: {self.task.pid.value_()}"
            f" ({os.fsdecode(self.task.comm.string_())})"
            f" +{hex(self.address - self.task.stack.value_())}"
        )


@dataclasses.dataclass
class IdentifiedSlabObject:
    """
    :class:`~drgn.helpers.common.memory.IdentifiedAddress` for an address from
    the slab allocator.
    """

    address: int

    slab_object_info: SlabObjectInfo
    """Information about slab object containing the address."""

    def __str__(self) -> str:
        cache_name = escape_ascii_string(
            self.slab_object_info.slab_cache.name.string_(), escape_backslash=True
        )
        if self.slab_object_info.allocated:
            maybe_free = ""
        elif self.slab_object_info.allocated is None:
            maybe_free = "corrupted "
        else:
            maybe_free = "free "
        return f"{maybe_free}slab object: {cache_name}+{hex(self.address - self.slab_object_info.address)}"


@dataclasses.dataclass
class IdentifiedVmap:
    """
    :class:`~drgn.helpers.common.memory.IdentifiedAddress` for an address in a
    vmap/vmalloc allocation.
    """

    address: int

    vmap_area: Object
    """``struct vmap_area *`` containing the address."""

    vm_struct: Object
    """``struct vm_struct *`` containing the address."""

    def __str__(self) -> str:
        caller = ""
        caller_value = self.vm_struct.caller.value_()
        try:
            caller_sym = self.vm_struct.prog_.symbol(caller_value)
        except LookupError:
            pass
        else:
            caller = (
                f" caller {caller_sym.name}+{hex(caller_value - caller_sym.address)}"
            )
        return (
            f"vmap: {hex(self.vmap_area.va_start)}-{hex(self.vmap_area.va_end)}{caller}"
        )


@dataclasses.dataclass
class IdentifiedPage:
    """
    :class:`~drgn.helpers.common.memory.IdentifiedAddress` for an address in a
    ``struct page`` object.
    """

    address: int

    page: Object
    """``struct page *`` containing the address."""

    pfn: int
    """Page frame number of the page."""

    def __str__(self) -> str:
        s = f"page: pfn {self.pfn}"
        page_address = self.page.value_()
        if self.address > page_address:
            s += f" +{hex(self.address - page_address)}"
        return s


def _is_task_struct(
    prog: Program, slab_object_info: SlabObjectInfo
) -> Optional[Object]:
    try:
        task_struct_cachep = prog.cache["task_struct_cachep"]
    except KeyError:
        task_struct_cachep = prog["task_struct_cachep"].read_()
        prog.cache["task_struct_cachep"] = task_struct_cachep
    if slab_object_info.slab_cache != task_struct_cachep:
        return None

    task = Object(prog, "struct task_struct *", slab_object_info.address)

    # If the task_struct slab cache is merged, we need to make sure that we got
    # an actual task_struct.
    if task_struct_cachep.refcount.value_() > 1:
        pid = task.pid.value_()
        if pid:
            if find_task(prog, pid) != task:
                return None
        else:
            if idle_task(prog, task_cpu(task)) != task:
                return None

    return task


def _identify_page(
    prog: Program, addr: int, cache: Optional[Dict[Any, Any]] = None
) -> Optional[IdentifiedPage]:
    if cache is None:
        valid_page_ranges: Iterable[Tuple[int, int, Object]] = (
            for_each_valid_page_range(prog)
        )
    else:
        try:
            valid_page_ranges = cache["valid_page_ranges"]
        except KeyError:
            valid_page_ranges = list(for_each_valid_page_range(prog))
            cache["valid_page_ranges"] = valid_page_ranges

    for start_pfn, end_pfn, mem_map in valid_page_ranges:
        start_page = mem_map[start_pfn]
        start_address: int = start_page.address_  # type: ignore[assignment]
        if start_address <= addr < mem_map[end_pfn].address_:  # type: ignore[operator]
            break
    else:
        return None

    sizeof_page = sizeof(start_page)
    index = (addr - start_address) // sizeof_page
    return IdentifiedPage(
        addr,
        Object(prog, mem_map.type_, start_address + index * sizeof_page),
        start_pfn + index,
    )


def _identify_vmap(
    prog: Program, addr: int, cache: Optional[Dict[Any, Any]] = None
) -> Iterator[Union[IdentifiedTaskStack, IdentifiedVmap]]:
    va = find_vmap_area(prog, addr)
    if not va:
        return

    vm = va.vm.read_()
    if not vm:
        return

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
                task = None
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
        yield IdentifiedTaskStack(addr, task)

    yield IdentifiedVmap(addr, va, vm)


def _identify_kernel_symbol(
    prog: Program, addr: int, symbol: Symbol
) -> Iterator[Union[IdentifiedTaskStruct, IdentifiedTaskStack]]:
    # init_task is identified as a symbol, but we want to identify it as a
    # task/stack first.
    task: Object
    init_task_range: Tuple[int, int]
    try:
        task, init_task_range = prog.cache["init_task_ranges"]
    except KeyError:
        task = prog["init_task"]

        task_address: int = task.address_  # type: ignore
        init_task_range = (task_address, task_address + sizeof(task))

        task = task.address_of_()
        prog.cache["init_task_ranges"] = (task, init_task_range)

    if init_task_range[0] <= addr < init_task_range[1]:
        yield IdentifiedTaskStruct(addr, task)


def _identify_kernel_address(
    prog: Program, addr: int, cache: Optional[Dict[Any, Any]] = None
) -> Iterator[
    Union[
        IdentifiedTaskStruct,
        IdentifiedTaskStack,
        IdentifiedSlabObject,
        IdentifiedPage,
        IdentifiedVmap,
    ]
]:
    try:
        direct_map = in_direct_map(prog, addr)
    except NotImplementedError:
        # Virtual address translation isn't implemented for this
        # architecture.
        direct_map = False

    if direct_map:
        result = _find_containing_slab(prog, addr)
        if result is not None:
            slab_cache, page, slab = result
            slab_info = _get_slab_cache_helper(slab_cache).object_info(page, slab, addr)
            if slab_info:
                if slab_info.allocated:
                    task = _is_task_struct(prog, slab_info)
                    if task is not None:
                        yield IdentifiedTaskStruct(addr, task)
                yield IdentifiedSlabObject(addr, slab_info)
    else:
        identified = _identify_page(prog, addr, cache)
        if identified is not None:
            yield identified
            return
        yield from _identify_vmap(prog, addr, cache)
