# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Virtual Memory Statistics
-------------------------

The ``drgn.helpers.linux.vmstat`` module provides helpers for reading virtual
memory statistics.
"""

from drgn import IntegerLike, Object, Program
from drgn.helpers.common.prog import takes_program_or_default

__all__ = (
    "global_node_page_state",
    "global_zone_page_state",
    "nr_free_pages",
)


@takes_program_or_default
def global_node_page_state(prog: Program, item: IntegerLike) -> int:
    """
    Get the global value of a node VM statistic.

    >>> global_node_page_state(prog["NR_FILE_PAGES"])
    2257904

    :param item: ``enum node_stat_item``
    """
    return max(prog["vm_node_stat"][item].counter.value_(), 0)


def zone_page_state(zone: Object, item: IntegerLike) -> int:
    """
    Get the value of a zone VM statistic in a single zone.
    """
    return max(zone.vm_stat[item].counter.value_(), 0)


@takes_program_or_default
def global_zone_page_state(prog: Program, item: IntegerLike) -> int:
    """
    Get the global value of a zone VM statistic.

    >>> global_zone_page_state(prog["NR_MLOCK"])
    1562

    :param item: ``enum zone_stat_item``
    """
    return max(prog["vm_zone_stat"][item].counter.value_(), 0)


@takes_program_or_default
def nr_free_pages(prog: Program) -> int:
    """Get the number of free memory pages."""
    return global_zone_page_state(prog["NR_FREE_PAGES"])
