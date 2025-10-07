# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Virtual Memory Statistics
-------------------------

The ``drgn.helpers.linux.vmstat`` module provides helpers for reading virtual
memory statistics.
"""

from drgn import IntegerLike, Object, ObjectNotFoundError, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu

__all__ = (
    "global_node_page_state",
    "global_numa_event_state",
    "global_vm_event_state",
    "global_zone_page_state",
    "nr_free_pages",
    "zone_page_state",
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

    :param zone: ``struct zone *``
    :param item: ``enum zone_stat_item``
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


@takes_program_or_default
def global_numa_event_state(prog: Program, item: IntegerLike) -> int:
    """
    Get the global value of a NUMA statistic.

    .. note::

        This is only valid if the kernel was compiled with ``CONFIG_NUMA``.
        Before Linux 4.14, these items (e.g., ``NUMA_HIT``) were zone
        statistics, so on kernel versions before 4.14, this is an alias of
        :func:`global_zone_page_state()`.

    :param item: ``enum numa_stat_item`` (or ``enum zone_stat_item`` on Linux <
        4.14)
    """
    # The variable was renamed from "vm_numa_stat" to "vm_numa_event" in Linux
    # kernel commit f19298b9516c ("mm/vmstat: convert NUMA statistics to basic
    # NUMA counters") (in v5.14). Additionally, before Linux kernel commit
    # 3a321d2a3dde ("mm: change the call sites of numa statistics items") (in
    # v4.14), the items were zone statistics and the variable didn't exist.
    try:
        array = prog["vm_numa_event"]
    except ObjectNotFoundError:
        try:
            array = prog["vm_numa_stat"]
        except ObjectNotFoundError:
            return global_zone_page_state(prog, item)
    return array[item].counter.value_()


@takes_program_or_default
def global_vm_event_state(prog: Program, item: IntegerLike) -> int:
    """
    Get the global value of a virtual memory event statistic.

    .. note::

        This is only valid if the kernel was compiled with
        ``CONFIG_VM_EVENT_COUNTERS``.

    :param item: ``enum vm_event_item``
    """
    event = prog["vm_event_states"].event[item]
    return sum(per_cpu(event, cpu).value_() for cpu in for_each_online_cpu(prog))
