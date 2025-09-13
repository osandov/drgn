# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


"""
HugeTLB
-------

The ``drgn.helpers.linux.hugetlb`` module provides helpers for working with
HugeTLB pages.
"""

from typing import Iterator

from drgn import Object, ObjectNotFoundError, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.mm import PageUsage

__all__ = (
    "for_each_hstate",
    "huge_page_size",
    "hugetlb_total_pages",
    "hugetlb_total_usage",
)


@takes_program_or_default
def for_each_hstate(prog: Program) -> Iterator[Object]:
    """
    Iterate over all HugeTLB page size states.

    >>> [h.name.string_() for h in for_each_hstate()]
    [b'hugepages-1048576kB', b'hugepages-2048kB']

    :return: Iterator of ``struct hstate *`` objects.
    """
    try:
        hstates = prog["hstates"]
    except ObjectNotFoundError:
        # CONFIG_HUGETLBFS=n.
        return iter(())
    return (h.address_of_() for h in hstates[: prog["hugetlb_max_hstate"]])


def huge_page_size(hstate: Object) -> Object:
    """
    Return the size of a HugeTLB state in bytes.

    :param hstate: ``struct hstate *``
    :return: ``unsigned long``
    """
    return hstate.prog_["PAGE_SIZE"] << hstate.order


@takes_program_or_default
def hugetlb_total_pages(prog: Program) -> int:
    """Get the total number of HugeTLB pages (in ``PAGE_SIZE`` units)."""
    return sum(
        h.nr_huge_pages.value_() << h.order.value_() for h in for_each_hstate(prog)
    )


@takes_program_or_default
def hugetlb_total_usage(prog: Program) -> PageUsage:
    """
    Get the total number of HugeTLB pages and the number of free HugeTLB pages
    (in ``PAGE_SIZE`` units).
    """
    pages = 0
    free_pages = 0
    for h in for_each_hstate(prog):
        order = h.order.value_()
        pages += h.nr_huge_pages.value_() << order
        free_pages += h.free_huge_pages.value_() << order
    return PageUsage(pages=pages, free_pages=free_pages)
