# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Runqueue
--------

The ``drgn.helpers.linux.runqueue`` module provides helpers for working with the
Linux runqueue.
"""

from typing import Iterator

from drgn import Object
from drgn.helpers.linux.list import list_for_each_entry


def rq_for_each_rt_task(runqueue: Object) -> Iterator[Object]:
    """
    Get real-time runqueue tasks in real-time scheduler.

    :param runqueue: ``struct rq *``
    :return: Iterator of ``struct task_struct``
    """
    rt_prio_array = runqueue.rt.active.queue
    for que in rt_prio_array:
        yield from list_for_each_entry(
            "struct task_struct", que.address_of_(), "rt.run_list"
        )


def rq_for_each_fair_task(runqueue: Object) -> Iterator[Object]:
    """
    Get CFS runqueue tasks in cfs scheduler.

    :param runqueue: ``struct rq *``
    :return: Iterator of (``struct task_struct``, int) tuples
    """
    return list_for_each_entry(
        "struct task_struct", runqueue.cfs_tasks.address_of_(), "se.group_node"
    )
