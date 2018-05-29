# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel process ID helpers

This module provides helpers for looking up process IDs. This currently only
supports Linux v4.15+, which is when the PID bitmap was replaced with an IDR.
"""

from drgn.helpers.kernel.idr import idr_find
from drgn.program import Program

__all__ = [
    'find_pid',
    'pid_task',
    'task',
]


def find_pid(prog_or_ns, nr):
    """
    struct pid *find_pid(struct pid_namespace *, int)
    struct pid *find_pid(int)

    Return the struct pid for the given PID in the given namespace. If given a
    Program object instead, the initial PID namespace is used.
    """
    if isinstance(prog_or_ns, Program):
        ns = prog_or_ns['init_pid_ns']
    else:
        ns = prog_or_ns
    return idr_find(ns.idr, nr).cast_('struct pid *')


def pid_task(pid, pid_type):
    """
    struct task_struct *pid_task(struct pid *, enum pid_type)

    Return the struct task_struct containing the given struct pid of the given
    type.
    """
    if not pid:
        return pid.program_.null('struct task_struct *')
    first = pid.tasks[0].first
    if not first:
        return pid.program_.null('struct task_struct *')
    return first.container_of_('struct task_struct', f'pids[{pid_type}].node')


def task(prog_or_ns, pid):
    """
    struct task_struct *task(int)
    struct task_struct *task(struct pid_namespace *, int)

    Return the task with the given PID in the given namespace. If given a
    Program object instead, the initial PID namespace is used.
    """
    if isinstance(prog_or_ns, Program):
        prog = prog_or_ns
    else:
        prog = prog_or_ns.program_
    PIDTYPE_PID = prog.type('enum pid_type').enum.PIDTYPE_PID
    return pid_task(find_pid(prog_or_ns, pid), PIDTYPE_PID)
