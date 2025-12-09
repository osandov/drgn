# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
CPU Scheduler
-------------

The ``drgn.helpers.linux.sched`` module provides helpers for working with the
Linux CPU scheduler.
"""

from typing import Tuple

from _drgn import (
    _linux_helper_cpu_curr,
    _linux_helper_idle_task,
    _linux_helper_task_cpu as task_cpu,
    _linux_helper_task_on_cpu as task_on_cpu,
    _linux_helper_task_thread_info as task_thread_info,
)
from drgn import IntegerLike, Object, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.percpu import per_cpu

__all__ = (
    "cpu_curr",
    "cpu_rq",
    "get_task_state",
    "idle_task",
    "loadavg",
    "task_cpu",
    "task_on_cpu",
    "task_rq",
    "task_since_last_arrival_ns",
    "task_state_to_char",
    "task_thread_info",
    "thread_group_leader",
)

_TASK_NOLOAD = 0x400


@takes_program_or_default
def cpu_curr(prog: Program, cpu: IntegerLike) -> Object:
    """
    Return the task running on the given CPU.

    >>> cpu_curr(7).comm
    (char [16])"python3"

    :param cpu: CPU number.
    :return: ``struct task_struct *``
    """
    return _linux_helper_cpu_curr(prog, cpu)


@takes_program_or_default
def idle_task(prog: Program, cpu: IntegerLike) -> Object:
    """
    Return the idle thread (PID 0, a.k.a swapper) for the given CPU.

    >>> idle_task(1).comm
    (char [16])"swapper/1"

    :param cpu: CPU number.
    :return: ``struct task_struct *``
    """
    return _linux_helper_idle_task(prog, cpu)


def task_state_to_char(task: Object) -> str:
    """
    Get the state of the task as a character (e.g., ``'R'`` for running). See
    `ps(1)
    <http://man7.org/linux/man-pages/man1/ps.1.html#PROCESS_STATE_CODES>`_ for
    a description of the process state codes.

    :param task: ``struct task_struct *``
    """
    prog = task.prog_
    task_state_chars: str
    TASK_REPORT: int
    try:
        task_state_chars, TASK_REPORT, task_state_name = prog.cache[
            "task_state_to_char"
        ]
    except KeyError:
        task_state_array = prog["task_state_array"]
        # Walk through task_state_array backwards looking for the largest state
        # that we know is in TASK_REPORT, then populate the task state mapping.
        chars = None
        for i in range(len(task_state_array) - 1, -1, -1):
            c: int = task_state_array[i][0].value_()
            if chars is None and c in b"RSDTtXZP":
                chars = bytearray(i + 1)
                TASK_REPORT = (1 << i) - 1
            if chars is not None:
                chars[i] = c
        if chars is None:
            raise Exception("could not parse task_state_array")
        task_state_chars = chars.decode("ascii")

        # Since Linux kernel commit 2f064a59a11f ("sched: Change
        # task_struct::state") (in v5.14), the task state is named "__state".
        # Before that, it is named "state".
        try:
            task_state = task.__state
            task_state_name = "__state"
        except AttributeError:
            task_state = task.state
            task_state_name = "state"

        prog.cache["task_state_to_char"] = (
            task_state_chars,
            TASK_REPORT,
            task_state_name,
        )
    else:
        task_state = task.member_(task_state_name)
    task_state = task_state.value_()
    exit_state = task.exit_state.value_()
    state = (task_state | exit_state) & TASK_REPORT
    char = task_state_chars[state.bit_length()]
    # States beyond TASK_REPORT are special. As of Linux v5.14, TASK_IDLE is
    # the only one; it is defined as TASK_UNINTERRUPTIBLE | TASK_NOLOAD.
    if char == "D" and (task_state & ~state) == _TASK_NOLOAD:
        return "I"
    else:
        return char


_TASK_STATE_CHAR_TO_STATE = {
    "R": "R (running)",
    "S": "S (sleeping)",
    "D": "D (disk sleep)",
    "T": "T (stopped)",
    "t": "t (tracing stop)",
    "X": "X (dead)",
    "Z": "Z (zombie)",
    "P": "P (parked)",
    "I": "I (idle)",
}


def get_task_state(task: Object) -> str:
    """
    Get the state of the task as a character plus a parenthesized name (e.g.,
    ``'R (running)'``).

    See also :func:`task_state_to_char()`.

    :param task: ``struct task_struct *``
    """
    char = task_state_to_char(task)
    return _TASK_STATE_CHAR_TO_STATE.get(char, char)


@takes_program_or_default
def loadavg(prog: Program) -> Tuple[float, float, float]:
    """
    Return system load averaged over 1, 5 and 15 minutes as
    tuple of three float values.

    >>> loadavg()
    (2.34, 0.442, 1.33)
    """

    avenrun = prog["avenrun"]
    vals = [avenrun[i].value_() / (1 << 11) for i in range(3)]
    return (vals[0], vals[1], vals[2])


@takes_program_or_default
def cpu_rq(prog: Program, cpu: IntegerLike) -> Object:
    """
    Get the runqueue for a given cpu.

    :param cpu: CPU number.
    :returns: ``struct rq``
    """
    return per_cpu(prog["runqueues"], cpu)


def task_rq(task: Object) -> Object:
    """
    Get the runqueue for a given task.

    :param task: ``struct task_struct *``
    :returns: ``struct rq``
    """
    return cpu_rq(task.prog_, task_cpu(task))


def task_since_last_arrival_ns(task: Object) -> int:
    """
    Get the difference between the runqueue timestamp when a task last started
    running and the current runqueue timestamp.

    This is approximately the time that the task has been in its current status
    (running, queued, or blocked). However, if a CPU is either idle or running
    the same task for a long time, then the timestamps will not be accurate.

    This is only supported if the kernel was compiled with
    ``CONFIG_SCHEDSTATS`` or ``CONFIG_TASK_DELAY_ACCT``.

    :param task: ``struct task_struct *``
    :returns: Duration in nanoseconds.
    """
    arrival_time = task.sched_info.last_arrival.value_()
    rq_clock = task_rq(task).clock.value_()

    return rq_clock - arrival_time


def thread_group_leader(task: Object) -> bool:
    """
    Return whether a task is a thread group leader.

    :param task: ``struct task_struct *``
    """
    return task.exit_signal >= 0
