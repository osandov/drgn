# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Memory Zones
------------

The ``drgn.helpers.linux.mmzone`` module provides helpers for working with
memory zones.
"""

from typing import Iterator

from drgn import IntegerLike, Object, ObjectNotFoundError, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.nodemask import for_each_online_node

__all__ = (
    "NODE_DATA",
    "for_each_online_pgdat",
)


@takes_program_or_default
def NODE_DATA(prog: Program, nid: IntegerLike) -> Object:
    """
    Get the NUMA node memory layout data of a given NUMA node.

    :param nid: NUMA node ID.
    :return: ``struct pglist_data *``
    """
    try:
        return prog["node_data"][nid]
    except ObjectNotFoundError:
        # CONFIG_NUMA=n
        return prog["contig_page_data"].address_of_()


@takes_program_or_default
def for_each_online_pgdat(prog: Program) -> Iterator[Object]:
    """
    Get the NUMA node memory layout data of each online NUMA node.

    :return: Iterator of ``struct pglist_data *`` objects
    """
    for nid in for_each_online_node(prog):
        yield NODE_DATA(prog, nid)
