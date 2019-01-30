# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel memory management helpers

This module provides helpers for working with the Linux memory management (mm)
subsystem. Only x86-64 support is currently implemented.
"""

__all__ = [
    'for_each_page',
    'page_to_pfn',
    'pfn_to_page',
    'virt_to_pfn',
    'pfn_to_virt',
    'page_to_virt',
    'virt_to_page',
]


def _vmemmap(prog):
    try:
        # KASAN
        return prog['vmemmap_base'].cast_('struct page *')
    except KeyError:
        # x86-64
        return prog.object('struct page *', value=0xffffea0000000000)


def _page_offset(prog):
    try:
        # KASAN
        return prog['page_offset_base'].value_()
    except KeyError:
        # x86-64
        return 0xffff880000000000


def for_each_page(prog):
    """
    for_each_page()

    Return an iterator over each struct page * in the system.
    """
    vmemmap = _vmemmap(prog)
    for i in range(prog['max_pfn']):
        yield vmemmap + i


def page_to_pfn(page):
    """
    unsigned long page_to_pfn(struct page *)

    Get the page frame number (PFN) of a page.
    """
    return (page - _vmemmap(page.prog_)).cast_('unsigned long')


def pfn_to_page(prog_or_pfn, pfn=None):
    """
    struct page *pfn_to_page(unsigned long)

    Get the page with the given page frame number (PFN). This can take the PFN
    as an Object or a Program and the PFN as an int.
    """
    if pfn is None:
        prog = prog_or_pfn.prog_
        pfn = prog_or_pfn
    else:
        prog = prog_or_pfn
    return _vmemmap(prog) + pfn


def virt_to_pfn(prog_or_addr, addr=None):
    """
    unsigned long virt_to_pfn(void *)

    Get the page frame number (PFN) of a directly mapped virtual address. This
    can take the address as an Object or a Program and the address as an int.
    """
    if addr is None:
        prog = prog_or_addr.prog_
        addr = prog_or_addr.value_()
    else:
        prog = prog_or_addr
    return prog.object('unsigned long', value=(addr - _page_offset(prog)) >> 12)


def pfn_to_virt(prog_or_pfn, pfn=None):
    """
    void *pfn_to_virt(unsigned long)

    Get the directly mapped virtual address of the given page frame number
    (PFN). This can take the PFN as an Object or a Program and the PFN as an
    int.
    """
    if pfn is None:
        prog = prog_or_pfn.prog_
        pfn = prog_or_pfn.value_()
    else:
        prog = prog_or_pfn
    return prog.object('void *', value=(pfn << 12) + _page_offset(prog))


def page_to_virt(page):
    """
    void *page_to_virt(struct page *)

    Get the directly mapped virtual address of a page.
    """
    return pfn_to_virt(page_to_pfn(page))


def virt_to_page(prog_or_addr, addr=None):
    """
    struct page *virt_to_page(void *)

    Get the page containing a directly mapped virtual address. This can take
    the address as an Object or a Program and the address as an int.
    """
    return pfn_to_page(virt_to_pfn(prog_or_addr, addr))
