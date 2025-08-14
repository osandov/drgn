# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Runqueue
--------

The ``drgn.helpers.linux.runqueue`` module provides helpers for working with the
Linux runqueue.
"""

from typing import Iterator, List, Tuple

from drgn import Object, Program, container_of
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.percpu import per_cpu


def get_rt_runq_tasks(runqueue: Object) -> Iterator[Object]:
    """
    Get RT runqueue tasks in rt scheduler.

    :param runqueue: Object
    :return: Iterator of ``struct task_struct``
    """
    rt_prio_array = runqueue.rt.active.queue
    for que in rt_prio_array:
        for t in list_for_each_entry(
            "struct sched_rt_entity", que.address_of_(), "run_list"
        ):
            yield container_of(t, "struct task_struct", "rt")


def get_cfs_runq_tasks(runqueue: Object) -> Iterator[Object]:
    """
    Get CFS runqueue tasks in cfs scheduler.

    :param runqueue: Object
    :return: Iterator of (``struct task_struct``, int) tuples
    """
    runq = runqueue.address_of_()
    for t in list_for_each_entry(
        "struct task_struct", runq.cfs_tasks.address_of_(), "se.group_node"
    ):
        if t == runqueue.curr:
            continue
        yield container_of(t, "struct task_struct", "rt")


def get_rq_per_cpu(prog: Program, cpus: List[int] = []) -> Iterator[Tuple[int, Object]]:
    """
    Get runqueue for selected cpus

    :param prog: drgn program
    :param cpus: a list of int
    :return: Iterator of (int, ``struct rq``) tuples
    """
    online_cpus = list(for_each_online_cpu(prog))

    if cpus:
        selected_cpus = [cpu for cpu in online_cpus if cpu in cpus]
    else:
        selected_cpus = online_cpus

    for cpu in selected_cpus:
        runqueue = per_cpu(prog["runqueues"], cpu)
        yield (cpu, runqueue)
