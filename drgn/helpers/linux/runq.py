# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Run Queues
----------
The ``drgn.helpers.linux.runq`` module provides helpers for working with the
Linux run queues.
"""
from drgn import Object, Program
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.sched import task_cpu


def runq_clock(prog: Program, cpu: int) -> int:
    """
    Get clock of cpu runqueue ``struct rq``

    :param prog: drgn program
    :param cpu: cpu index
    :returns: cpu runqueue clock in ns granularity
    """
    rq = per_cpu(prog["runqueues"], cpu)
    return rq.clock.value_()


def task_lastrun2now(task: Object) -> int:
    """
    Get the duration from task last run timestamp to now

    The return duration will cover task's last run time on cpu and also
    the time staying in current status, usually the time slice for task
    on cpu will be short, so this can roughly tell how long this task
    has been staying in current status.
    For task status in "RU" status, if it's still on cpu, then this return
    the duration time this task has been running, otherwise it roughly tell
    how long this task has been staying in runqueue.

    :param prog: drgn program
    :param task: ``struct task_struct *``
    :returns: duration in ns granularity
    """
    prog = task.prog_
    arrival_time = task.sched_info.last_arrival.value_()
    rq_clock = runq_clock(prog, task_cpu(task))

    return rq_clock - arrival_time
