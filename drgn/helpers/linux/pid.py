# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Process IDS
-----------

The ``drgn.helpers.linux.pid`` module provides helpers for looking up process
IDs and processes.
"""

from drgn import NULL, Program, cast, container_of
from drgn.helpers.linux.idr import idr_find, idr_for_each
from drgn.helpers.linux.list import hlist_for_each_entry
from _drgn import (
    _linux_helper_find_pid,
    _linux_helper_find_task,
    _linux_helper_pid_task,
)

__all__ = (
    "find_pid",
    "find_task",
    "for_each_pid",
    "for_each_task",
    "pid_task",
)


def find_pid(prog_or_ns, nr):
    """
    .. c:function:: struct pid *find_pid(struct pid_namespace *ns, int nr)

    Return the ``struct pid *`` for the given PID number in the given
    namespace. If given a :class:`Program` instead, the initial PID namespace
    is used.
    """
    return _linux_helper_find_pid(prog_or_ns, nr)


def for_each_pid(prog_or_ns):
    """
    .. c:function:: for_each_pid(struct pid_namespace *ns)

    Iterate over all of the PIDs in the given namespace. If given a
    :class:`Program` instead, the initial PID namespace is used.

    :return: Iterator of ``struct pid *`` objects.
    """
    if isinstance(prog_or_ns, Program):
        prog = prog_or_ns
        ns = prog_or_ns["init_pid_ns"].address_of_()
    else:
        prog = prog_or_ns.prog_
        ns = prog_or_ns
    if hasattr(ns, "idr"):
        for nr, entry in idr_for_each(ns.idr):
            yield cast("struct pid *", entry)
    else:
        pid_hash = prog["pid_hash"]
        for i in range(1 << prog["pidhash_shift"].value_()):
            for upid in hlist_for_each_entry(
                "struct upid", pid_hash[i].address_of_(), "pid_chain"
            ):
                if upid.ns == ns:
                    yield container_of(upid, "struct pid", f"numbers[{int(ns.level)}]")


def pid_task(pid, pid_type):
    """
    .. c:function:: struct task_struct *pid_task(struct pid *pid, enum pid_type pid_type)

    Return the ``struct task_struct *`` containing the given ``struct pid *``
    of the given type.
    """
    return _linux_helper_pid_task(pid, pid_type)


def find_task(prog_or_ns, pid):
    """
    .. c:function:: struct task_struct *find_task(struct pid_namespace *ns, int pid)

    Return the task with the given PID in the given namespace. If given a
    :class:`Program` instead, the initial PID namespace is used.
    """
    return _linux_helper_find_task(prog_or_ns, pid)


def for_each_task(prog_or_ns):
    """
    .. c:function:: for_each_task(struct pid_namespace *ns)

    Iterate over all of the tasks visible in the given namespace. If given a
    :class:`Program` instead, the initial PID namespace is used.

    :return: Iterator of ``struct task_struct *`` objects.
    """
    if isinstance(prog_or_ns, Program):
        prog = prog_or_ns
    else:
        prog = prog_or_ns.prog_
    PIDTYPE_PID = prog["PIDTYPE_PID"].value_()
    for pid in for_each_pid(prog_or_ns):
        task = pid_task(pid, PIDTYPE_PID)
        if task:
            yield task
