# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Memory Management
-----------------

The ``drgn.helpers.linux.mm`` module provides helpers for working with the
Linux memory management (MM) subsystem. Only AArch64 and x86-64 are currently
supported.
"""

import operator
from typing import Iterator, List, Optional, Union, overload

from _drgn import _linux_helper_direct_mapping_offset, _linux_helper_read_vm
from drgn import IntegerLike, Object, Program, cast
from drgn.helpers import decode_enum_type_flags

__all__ = (
    "PFN_PHYS",
    "PHYS_PFN",
    "access_process_vm",
    "access_remote_vm",
    "cmdline",
    "decode_page_flags",
    "environ",
    "for_each_page",
    "page_to_pfn",
    "page_to_phys",
    "page_to_virt",
    "pfn_to_page",
    "pfn_to_virt",
    "phys_to_page",
    "phys_to_virt",
    "virt_to_page",
    "virt_to_pfn",
    "virt_to_phys",
)


def for_each_page(prog: Program) -> Iterator[Object]:
    """
    Iterate over all pages in the system.

    :return: Iterator of ``struct page *`` objects.
    """
    vmemmap = prog["vmemmap"]
    for i in range(prog["min_low_pfn"], prog["max_pfn"]):
        yield vmemmap + i


def decode_page_flags(page: Object) -> str:
    """
    Get a human-readable representation of the flags set on a page.

    >>> decode_page_flags(page)
    'PG_uptodate|PG_dirty|PG_lru|PG_reclaim|PG_swapbacked|PG_readahead|PG_savepinned|PG_isolated|PG_reported'

    :param page: ``struct page *``
    """
    NR_PAGEFLAGS = page.prog_["__NR_PAGEFLAGS"]
    PAGEFLAGS_MASK = (1 << NR_PAGEFLAGS.value_()) - 1
    return decode_enum_type_flags(
        page.flags.value_() & PAGEFLAGS_MASK, NR_PAGEFLAGS.type_
    )


@overload
def PFN_PHYS(pfn: Object) -> Object:
    """
    Get the physical address of a page frame number (PFN) given as an
    :class:`.Object`.

    :param pfn: ``unsigned long``
    :return: ``phys_addr_t``
    """
    ...


@overload
def PFN_PHYS(prog: Program, pfn: IntegerLike) -> Object:
    """
    Get the physical address of a page frame number (PFN) given as a
    :class:`.Program` and an integer.

    :param pfn: Page frame number.
    :return: ``phys_addr_t``
    """
    ...


def PFN_PHYS(  # type: ignore  # Need positional-only arguments.
    prog_or_pfn: Union[Program, Object], pfn: Optional[IntegerLike] = None
) -> Object:
    if pfn is None:
        assert isinstance(prog_or_pfn, Object)
        prog = prog_or_pfn.prog_
        pfn = prog_or_pfn
    else:
        assert isinstance(prog_or_pfn, Program)
        prog = prog_or_pfn
    return Object(prog, "phys_addr_t", operator.index(pfn)) << prog["PAGE_SHIFT"]


@overload
def PHYS_PFN(addr: Object) -> Object:
    """
    Get the page frame number (PFN) of a physical address given as an
    :class:`.Object`.

    :param addr: ``phys_addr_t``
    :return: ``unsigned long``
    """
    ...


@overload
def PHYS_PFN(prog: Program, addr: int) -> Object:
    """
    Get the page frame number (PFN) of a physical address given as a
    :class:`.Program` and an integer.

    :param addr: Physical address.
    :return: ``unsigned long``
    """
    ...


def PHYS_PFN(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object], addr: Optional[IntegerLike] = None
) -> Object:
    if addr is None:
        assert isinstance(prog_or_addr, Object)
        prog = prog_or_addr.prog_
        addr = prog_or_addr
    else:
        assert isinstance(prog_or_addr, Program)
        prog = prog_or_addr
    return Object(prog, "unsigned long", operator.index(addr)) >> prog["PAGE_SHIFT"]


def page_to_pfn(page: Object) -> Object:
    """
    Get the page frame number (PFN) of a page.

    :param page: ``struct page *``
    :return: ``unsigned long``
    """
    return cast("unsigned long", page - page.prog_["vmemmap"])


def page_to_phys(page: Object) -> Object:
    """
    Get the physical address of a page.

    :param page: ``struct page *``
    :return: ``phys_addr_t``
    """
    return PFN_PHYS(page_to_pfn(page))


def page_to_virt(page: Object) -> Object:
    """
    Get the directly mapped virtual address of a page.

    :param page: ``struct page *``
    :return: ``void *``
    """
    return pfn_to_virt(page_to_pfn(page))


@overload
def pfn_to_page(pfn: Object) -> Object:
    """
    Get the page with a page frame number (PFN) given as an :class:`.Object`.

    :param pfn: ``unsigned long``
    :return: ``struct page *``
    """
    ...


@overload
def pfn_to_page(prog: Program, pfn: IntegerLike) -> Object:
    """
    Get the page with a page frame number (PFN) given as a :class:`.Program`
    and an integer.

    :param pfn: Page frame number.
    :return: ``struct page *``
    """
    ...


def pfn_to_page(  # type: ignore  # Need positional-only arguments.
    prog_or_pfn: Union[Program, Object], pfn: Optional[IntegerLike] = None
) -> Object:
    if pfn is None:
        assert isinstance(prog_or_pfn, Object)
        prog = prog_or_pfn.prog_
        pfn = prog_or_pfn
    else:
        assert isinstance(prog_or_pfn, Program)
        prog = prog_or_pfn
    return prog["vmemmap"] + pfn


@overload
def pfn_to_virt(pfn: Object) -> Object:
    """
    Get the directly mapped virtual address of a page frame number (PFN) given
    as an :class:`.Object`.

    :param pfn: ``unsigned long``
    :return: ``void *``
    """
    ...


@overload
def pfn_to_virt(prog: Program, pfn: IntegerLike) -> Object:
    """
    Get the directly mapped virtual address of a page frame number (PFN) given
    as a :class:`.Program` and an integer.

    :param pfn: Page frame number.
    :return: ``void *``
    """


def pfn_to_virt(  # type: ignore  # Need positional-only arguments.
    prog_or_pfn: Union[Program, Object], pfn: Optional[IntegerLike] = None
) -> Object:
    return phys_to_virt(PFN_PHYS(prog_or_pfn, pfn))  # type: ignore


@overload
def phys_to_page(addr: Object) -> Object:
    """
    Get the page containing a directly mapped physical address given as an
    :class:`.Object`.

    :param addr: ``phys_addr_t``
    :return: ``struct page *``
    """
    ...


@overload
def phys_to_page(prog: Program, addr: IntegerLike) -> Object:
    """
    Get the page containing a directly mapped physical address given as a
    :class:`.Program` and an integer.

    :param addr: Physical address.
    :return: ``struct page *``
    """
    ...


def phys_to_page(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object], addr: Optional[IntegerLike] = None
) -> Object:
    return pfn_to_page(PHYS_PFN(prog_or_addr, addr))  # type: ignore


@overload
def phys_to_virt(addr: Object) -> Object:
    """
    Get the directly mapped virtual address of a physical address given as an
    :class:`.Object`.

    :param addr: ``phys_addr_t``
    :return: ``void *``
    """
    ...


@overload
def phys_to_virt(prog: Program, addr: IntegerLike) -> Object:
    """
    Get the directly mapped virtual address of a physical address given as a
    :class:`.Program` and an integer.

    :param addr: Physical address.
    :return: ``void *``
    """
    ...


def phys_to_virt(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object], addr: Optional[IntegerLike] = None
):
    if addr is None:
        assert isinstance(prog_or_addr, Object)
        prog = prog_or_addr.prog_
        addr = prog_or_addr
    else:
        assert isinstance(prog_or_addr, Program)
        prog = prog_or_addr
    return Object(
        prog, "void *", operator.index(addr) + _linux_helper_direct_mapping_offset(prog)
    )


@overload
def virt_to_page(addr: Object) -> Object:
    """
    Get the page containing a directly mapped virtual address given as an
    :class:`.Object`.

    :param addr: ``void *``
    :return: ``struct page *``
    """
    ...


@overload
def virt_to_page(prog: Program, addr: IntegerLike) -> Object:
    """
    Get the page containing a directly mapped virtual address given as a
    :class:`.Program` and an integer.

    :param addr: Virtual address.
    :return: ``struct page *``
    """
    ...


def virt_to_page(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object], addr: Optional[IntegerLike] = None
) -> Object:
    return pfn_to_page(virt_to_pfn(prog_or_addr, addr))  # type: ignore[arg-type]


@overload
def virt_to_pfn(addr: Object) -> Object:
    """
    Get the page frame number (PFN) of a directly mapped virtual address given
    as an :class:`.Object`.

    :param addr: ``void *``
    :return: ``unsigned long``
    """
    ...


@overload
def virt_to_pfn(prog: Program, addr: IntegerLike) -> Object:
    """
    Get the page frame number (PFN) of a directly mapped virtual address given
    as a :class:`.Program` and an integer.

    :param addr: Virtual address.
    :return: ``unsigned long``
    """
    ...


def virt_to_pfn(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object], addr: Optional[IntegerLike] = None
) -> Object:
    return PHYS_PFN(virt_to_phys(prog_or_addr, addr))  # type: ignore


@overload
def virt_to_phys(addr: Object) -> Object:
    """
    Get the physical address of a directly mapped virtual address given as an
    :class:`.Object`.

    :param addr: ``void *``
    :return: ``phys_addr_t``
    """
    ...


@overload
def virt_to_phys(prog: Program, addr: IntegerLike) -> Object:
    """
    Get the physical address of a directly mapped virtual address given as a
    :class:`.Program` and an integer.

    :param addr: Virtual address.
    :return: ``phys_addr_t``
    """
    ...


def virt_to_phys(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object], addr: Optional[IntegerLike] = None
) -> Object:
    if addr is None:
        assert isinstance(prog_or_addr, Object)
        prog = prog_or_addr.prog_
        addr = prog_or_addr
    else:
        assert isinstance(prog_or_addr, Program)
        prog = prog_or_addr
    return Object(
        prog,
        "unsigned long",
        operator.index(addr) - _linux_helper_direct_mapping_offset(prog),
    )


def access_process_vm(task: Object, address: IntegerLike, size: IntegerLike) -> bytes:
    """
    Read memory from a task's virtual address space.

    >>> task = find_task(prog, 1490152)
    >>> access_process_vm(task, 0x7f8a62b56da0, 12)
    b'hello, world'

    :param task: ``struct task_struct *``
    :param address: Starting address.
    :param size: Number of bytes to read.
    """
    return _linux_helper_read_vm(task.prog_, task.mm.pgd, address, size)


def access_remote_vm(mm: Object, address: IntegerLike, size: IntegerLike) -> bytes:
    """
    Read memory from a virtual address space. This is similar to
    :func:`access_process_vm()`, but it takes a ``struct mm_struct *`` instead
    of a ``struct task_struct *``.

    >>> task = find_task(prog, 1490152)
    >>> access_remote_vm(task.mm, 0x7f8a62b56da0, 12)
    b'hello, world'

    :param mm: ``struct mm_struct *``
    :param address: Starting address.
    :param size: Number of bytes to read.
    """
    return _linux_helper_read_vm(mm.prog_, mm.pgd, address, size)


def cmdline(task: Object) -> List[bytes]:
    """
    Get the list of command line arguments of a task.

    >>> cmdline(find_task(prog, 1495216))
    [b'vim', b'drgn/helpers/linux/mm.py']

    .. code-block:: console

        $ tr '\\0' ' ' < /proc/1495216/cmdline
        vim drgn/helpers/linux/mm.py

    :param task: ``struct task_struct *``
    """
    mm = task.mm.read_()
    arg_start = mm.arg_start.value_()
    arg_end = mm.arg_end.value_()
    return access_remote_vm(mm, arg_start, arg_end - arg_start).split(b"\0")[:-1]


def environ(task: Object) -> List[bytes]:
    """
    Get the list of environment variables of a task.

    >>> environ(find_task(prog, 1497797))
    [b'HOME=/root', b'PATH=/usr/local/sbin:/usr/local/bin:/usr/bin', b'LOGNAME=root']

    .. code-block:: console

        $ tr '\\0' '\\n' < /proc/1497797/environ
        HOME=/root
        PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
        LOGNAME=root

    :param task: ``struct task_struct *``
    """
    mm = task.mm.read_()
    env_start = mm.env_start.value_()
    env_end = mm.env_end.value_()
    return access_remote_vm(mm, env_start, env_end - env_start).split(b"\0")[:-1]
