# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Memory Management
-----------------

The ``drgn.helpers.linux.mm`` module provides helpers for working with the
Linux memory management (MM) subsystem. Only x86-64 support is currently
implemented.
"""

from typing import List

from _drgn import _linux_helper_read_vm
from drgn import Object, cast


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


def for_each_page(prog):
    """
    Iterate over all pages in the system.

    :return: Iterator of ``struct page *`` objects.
    """
    vmemmap = prog["vmemmap"]
    for i in range(prog["max_pfn"]):
        yield vmemmap + i


def page_to_pfn(page):
    """
    .. c:function:: unsigned long page_to_pfn(struct page *page)

    Get the page frame number (PFN) of a page.
    """
    return cast("unsigned long", page - page.prog_["vmemmap"])


def pfn_to_page(prog_or_pfn, pfn=None):
    """
    .. c:function:: struct page *pfn_to_page(unsigned long pfn)

    Get the page with the given page frame number (PFN). This can take the PFN
    as an :class:`Object`, or a :class:`Program` and the PFN as an ``int``.
    """
    if pfn is None:
        prog = prog_or_pfn.prog_
        pfn = prog_or_pfn
    else:
        prog = prog_or_pfn
    return prog["vmemmap"] + pfn


def virt_to_pfn(prog_or_addr, addr=None):
    """
    .. c:function:: unsigned long virt_to_pfn(void *addr)

    Get the page frame number (PFN) of a directly mapped virtual address. This
    can take the address as an :class:`Object`, or a :class:`Program` and the
    address as an ``int``.
    """
    if addr is None:
        prog = prog_or_addr.prog_
        addr = prog_or_addr.value_()
    else:
        prog = prog_or_addr
    return Object(prog, "unsigned long", value=(addr - prog["PAGE_OFFSET"]) >> 12)


def pfn_to_virt(prog_or_pfn, pfn=None):
    """
    .. c:function:: void *pfn_to_virt(unsigned long pfn)

    Get the directly mapped virtual address of the given page frame number
    (PFN). This can take the PFN as an :class:`Object`, or a :class:`Program`
    and the PFN as an ``int``.
    """
    if pfn is None:
        prog = prog_or_pfn.prog_
        pfn = prog_or_pfn.value_()
    else:
        prog = prog_or_pfn
    return Object(prog, "void *", value=(pfn << 12) + prog["PAGE_OFFSET"])


def page_to_virt(page):
    """
    .. c:function:: void *page_to_virt(struct page *page)

    Get the directly mapped virtual address of a page.
    """
    return pfn_to_virt(page_to_pfn(page))


def virt_to_page(prog_or_addr, addr=None):
    """
    .. c:function:: struct page *virt_to_page(void *addr)

    Get the page containing a directly mapped virtual address. This can take
    the address as an :class:`Object`, or a :class:`Program` and the address as
    an ``int``.
    """
    return pfn_to_page(virt_to_pfn(prog_or_addr, addr))


def access_process_vm(task, address, size) -> bytes:
    """
    .. c:function:: char *access_process_vm(struct task_struct *task, void *address, size_t size)

    Read memory from a task's virtual address space.

    >>> task = find_task(prog, 1490152)
    >>> access_process_vm(task, 0x7f8a62b56da0, 12)
    b'hello, world'
    """
    return _linux_helper_read_vm(task.prog_, task.mm.pgd, address, size)


def access_remote_vm(mm, address, size) -> bytes:
    """
    .. c:function:: char *access_remote_vm(struct mm_struct *mm, void *address, size_t size)

    Read memory from a virtual address space. This is similar to
    :func:`access_process_vm()`, but it takes a ``struct mm_struct *`` instead
    of a ``struct task_struct *``.

    >>> task = find_task(prog, 1490152)
    >>> access_remote_vm(task.mm, 0x7f8a62b56da0, 12)
    b'hello, world'
    """
    return _linux_helper_read_vm(mm.prog_, mm.pgd, address, size)


def cmdline(task) -> List[bytes]:
    """
    Get the list of command line arguments of a task.

    >>> cmdline(find_task(prog, 1495216))
    [b'vim', b'drgn/helpers/linux/mm.py']

    .. code-block:: console

        $ tr '\\0' ' ' < /proc/1495216/cmdline
        vim drgn/helpers/linux/mm.py
    """
    mm = task.mm.read_()
    arg_start = mm.arg_start.value_()
    arg_end = mm.arg_end.value_()
    return access_remote_vm(mm, arg_start, arg_end - arg_start).split(b"\0")[:-1]


def environ(task) -> List[bytes]:
    """
    Get the list of environment variables of a task.

    >>> environ(find_task(prog, 1497797))
    [b'HOME=/root', b'PATH=/usr/local/sbin:/usr/local/bin:/usr/bin', b'LOGNAME=root']

    .. code-block:: console

        $ tr '\\0' '\\n' < /proc/1497797/environ
        HOME=/root
        PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
        LOGNAME=root
    """
    mm = task.mm.read_()
    env_start = mm.env_start.value_()
    env_end = mm.env_end.value_()
    return access_remote_vm(mm, env_start, env_end - env_start).split(b"\0")[:-1]
