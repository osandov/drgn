# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Swap Space
----------

The ``drgn.helpers.linux.swap`` module provides helpers for inspecting swap
partitions and swap files.
"""

from typing import Iterator

from drgn import Object, ObjectNotFoundError, PlatformFlags, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.fs import d_path
from drgn.helpers.linux.mm import PageUsage, global_node_page_state

__all__ = (
    "for_each_swap_info",
    "swap_file_path",
    "swap_is_file",
    "swap_total_usage",
    "swap_usage_in_pages",
    "total_swapcache_pages",
)


@takes_program_or_default
def for_each_swap_info(prog: Program) -> Iterator[Object]:
    """
    Iterate over all swap devices.

    :return: Iterator of ``struct swap_info_struct *`` objects.
    """
    swap_info = prog["swap_info"]
    SWP_USED = prog["SWP_USED"]
    for type in range(prog["nr_swapfiles"]):
        si = swap_info[type]
        if si.flags & SWP_USED:
            yield si


def swap_file_path(si: Object) -> bytes:
    """
    Get the path of the swap partition or file.

    >>> swap_file_path(si)
    b'/dev/sda3'

    :param si: ``struct swap_info_struct *``
    """
    return d_path(si.swap_file.f_path)


def swap_is_file(si: Object) -> bool:
    """
    Return whether a swap device is a regular file.

    :param si: ``struct swap_info_struct *``
    """
    return not (si.flags & si.prog_["SWP_BLKDEV"])


def swap_usage_in_pages(si: Object) -> int:
    """
    Get the number of pages currently in use on a swap device.

    >>> swap_usage_in_pages(si)
    394319

    :param si: ``struct swap_info_struct *``
    """
    inuse_pages = si.inuse_pages
    try:
        counter = inuse_pages.counter
    except AttributeError:
        return inuse_pages.value_()
    else:
        SWAP_USAGE_COUNTER_MASK = (
            0xBFFFFFFFFFFFFFFF
            if (
                si.prog_.platform.flags  # type: ignore[union-attr]  # platform can't be None.
                & PlatformFlags.IS_64_BIT
            )
            else 0xBFFFFFFF
        )
        return counter.value_() & SWAP_USAGE_COUNTER_MASK


@takes_program_or_default
def swap_total_usage(prog: Program) -> PageUsage:
    """
    Get the total number of swap pages and the number of free swap pages on all
    swap devices.

    >>> usage = swap_total_usage()
    >>> usage
    PageUsage(pages=2097151, free_pages=1704798)
    >>> usage.used_pages
    392353
    """
    SWP_USED = prog["SWP_USED"]
    mask = SWP_USED | prog["SWP_WRITEOK"]
    nr_to_be_unused = 0
    for si in for_each_swap_info(prog):
        if si.flags & mask == SWP_USED:
            nr_to_be_unused += swap_usage_in_pages(si)

    return PageUsage(
        pages=prog["total_swap_pages"].value_() + nr_to_be_unused,
        free_pages=prog["nr_swap_pages"].counter.value_() + nr_to_be_unused,
    )


@takes_program_or_default
def total_swapcache_pages(prog: Program) -> int:
    """
    Get the number of swap cached pages (pages that are swapped in but still
    present on a swap device).
    """
    # Since Linux kernel commit ("mm: memcg: add swapcache stat for memcg v2")
    # (in v5.12), we just have to get the NR_SWAPCACHE statistic. Before that,
    # we have to sum over the swapper spaces.
    try:
        NR_SWAPCACHE = prog["NR_SWAPCACHE"]
    except ObjectNotFoundError:
        # Since Linux kernel commit 4b3ef9daa4fc ("mm/swap: split swap cache
        # into 64MB trunks") (in v4.11), there are multiple swapper spaces per
        # swap file. Before that, there was only one per swap file.
        try:
            nr_swapper_spaces = prog["nr_swapper_spaces"]
        except ObjectNotFoundError:
            # Before Linux kernel commit 4b3ef9daa4fc ("mm/swap: split swap
            # cache into 64MB trunks") (in v4.11),
            return sum(space.nrpages.value_() for space in prog["swapper_spaces"])
        else:
            return sum(
                spaces[j].nrpages.value_()
                for nr, spaces in zip(nr_swapper_spaces, prog["swapper_spaces"])
                for j in range(nr)
            )
    else:
        return global_node_page_state(NR_SWAPCACHE)
