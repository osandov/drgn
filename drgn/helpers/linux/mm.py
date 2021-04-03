# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Memory Management
-----------------

The ``drgn.helpers.linux.mm`` module provides helpers for working with the
Linux memory management (MM) subsystem. Only x86-64 support is currently
implemented.
"""

import operator
from typing import Any, Iterator, List, Optional, Union, overload

from _drgn import _linux_helper_read_vm
from drgn import IntegerLike, Object, Program, cast

__all__ = (
    "access_process_vm",
    "access_remote_vm",
    "cmdline",
    "environ",
    "for_each_page",
    "page_to_pfn",
    "page_to_virt",
    "pfn_to_page",
    "pfn_to_virt",
    "virt_to_page",
    "virt_to_pfn",
)


def for_each_page(prog: Program) -> Iterator[Object]:
    """
    Iterate over all pages in the system.

    :return: Iterator of ``struct page *`` objects.
    """
    vmemmap = prog["vmemmap"]
    for i in range(prog["max_pfn"].value_()):
        yield vmemmap + i


def page_to_pfn(page: Object) -> Object:
    """
    Get the page frame number (PFN) of a page.

    :param page: ``struct page *``
    :return: ``unsigned long``
    """
    return cast("unsigned long", page - page.prog_["vmemmap"])


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
    if addr is None:
        assert isinstance(prog_or_addr, Object)
        prog = prog_or_addr.prog_
        addr = prog_or_addr
    else:
        assert isinstance(prog_or_addr, Program)
        prog = prog_or_addr
    return cast("unsigned long", (operator.index(addr) - prog["PAGE_OFFSET"]) >> 12)


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
    if pfn is None:
        assert isinstance(prog_or_pfn, Object)
        prog = prog_or_pfn.prog_
        pfn = prog_or_pfn
    else:
        assert isinstance(prog_or_pfn, Program)
        prog = prog_or_pfn
    return cast("void *", (operator.index(pfn) << 12) + prog["PAGE_OFFSET"])


def page_to_virt(page: Object) -> Object:
    """
    Get the directly mapped virtual address of a page.

    :param page: ``struct page *``
    :return: ``void *``
    """
    return pfn_to_virt(page_to_pfn(page))


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
