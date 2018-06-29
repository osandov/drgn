# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel process ID helpers

This module provides helpers for looking up process IDs.
"""

from drgn.helpers.kernel.idr import idr_find, idr_for_each
from drgn.helpers.kernel.list import hlist_for_each_entry
from drgn.program import Program

__all__ = [
    'find_pid',
    'for_each_pid',
    'pid_task',
    'find_task',
    'for_each_task',
]


def find_pid(prog_or_ns, nr):
    """
    struct pid *find_pid(struct pid_namespace *, int)

    Return the struct pid for the given PID in the given namespace. If given a
    Program object instead, the initial PID namespace is used.
    """
    if isinstance(prog_or_ns, Program):
        prog = prog_or_ns
        ns = prog_or_ns['init_pid_ns'].address_of_()
    else:
        prog = prog_or_ns.program_
        ns = prog_or_ns
    if hasattr(ns, 'idr'):
        return idr_find(ns.idr, nr).cast_('struct pid *')
    else:
        # We could implement pid_hashfn() and only search that bucket, but it's
        # different for 32-bit and 64-bit systems, and it has changed at least
        # once, in v4.7. Searching the whole hash table is slower but
        # foolproof.
        pid_hash = prog['pid_hash']
        for i in range(1 << prog['pidhash_shift'].value_()):
            for upid in hlist_for_each_entry('struct upid',
                                             pid_hash[i].address_of_(),
                                             'pid_chain'):
                if upid.nr == nr and upid.ns == ns:
                    return upid.container_of_('struct pid',
                                              f'numbers[{ns.level.value_()}]')
        return prog.null('struct pid *')


def for_each_pid(prog_or_ns):
    """
    for_each_pid(struct pid_namespace *)

    Return an iterator over all of the PIDs in the given namespace. If given a
    Program object instead, the initial PID namespace is used. The generated
    values are struct pid * objects.
    """
    if isinstance(prog_or_ns, Program):
        prog = prog_or_ns
        ns = prog_or_ns['init_pid_ns'].address_of_()
    else:
        prog = prog_or_ns.program_
        ns = prog_or_ns
    if hasattr(ns, 'idr'):
        for nr, entry in idr_for_each(ns.idr):
            yield entry.cast_('struct pid *')
    else:
        pid_hash = prog['pid_hash']
        for i in range(1 << prog['pidhash_shift'].value_()):
            for upid in hlist_for_each_entry('struct upid',
                                             pid_hash[i].address_of_(),
                                             'pid_chain'):
                if upid.ns == ns:
                    yield upid.container_of_('struct pid',
                                             f'numbers[{ns.level.value_()}]')


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


def find_task(prog_or_ns, pid):
    """
    struct task_struct *find_task(struct pid_namespace *, int pid)

    Return the task with the given PID in the given namespace. If given a
    Program object instead, the initial PID namespace is used.
    """
    if isinstance(prog_or_ns, Program):
        prog = prog_or_ns
    else:
        prog = prog_or_ns.program_
    return pid_task(find_pid(prog_or_ns, pid), prog['PIDTYPE_PID'].value_())


def for_each_task(prog_or_ns):
    """
    for_each_task(struct pid_namespace *)

    Return an iterator over all of the tasks visible in the given namespace. If
    given a Program object instead, the initial PID namespace is used. The
    generated values are struct task_struct * objects.
    """
    if isinstance(prog_or_ns, Program):
        prog = prog_or_ns
    else:
        prog = prog_or_ns.program_
    PIDTYPE_PID = prog['PIDTYPE_PID'].value_()
    for pid in for_each_pid(prog_or_ns):
        task = pid_task(pid, PIDTYPE_PID)
        if task:
            yield task
