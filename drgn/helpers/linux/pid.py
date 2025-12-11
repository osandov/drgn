# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Process IDS
-----------

The ``drgn.helpers.linux.pid`` module provides helpers for looking up process
IDs and processes.
"""

from typing import Iterator, Optional

from _drgn import (
    _linux_helper_find_pid,
    _linux_helper_find_task,
    _linux_helper_pid_task as pid_task,
)
from drgn import IntegerLike, Object, Program, cast, container_of
from drgn.helpers.common.prog import takes_object_or_program_or_default
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.idr import idr_for_each
from drgn.helpers.linux.list import hlist_for_each_entry, list_for_each_entry
from drgn.helpers.linux.sched import idle_task

__all__ = (
    "find_pid",
    "find_task",
    "for_each_pid",
    "for_each_task",
    "for_each_task_in_group",
    "pid_task",
)


@takes_object_or_program_or_default
def find_pid(prog: Program, ns: Optional[Object], pid: IntegerLike) -> Object:
    """
    Return the ``struct pid *`` for the given PID number.

    :param ns: ``struct pid_namespace *``. Defaults to the initial PID
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :return: ``struct pid *``
    """
    if ns is None:
        ns = prog["init_pid_ns"].address_of_()
    return _linux_helper_find_pid(ns, pid)


@takes_object_or_program_or_default
def for_each_pid(prog: Program, ns: Optional[Object]) -> Iterator[Object]:
    """
    Iterate over all PIDs in a namespace.

    :param ns: ``struct pid_namespace *``. Defaults to the initial PID
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :return: Iterator of ``struct pid *`` objects.
    """
    if ns is None:
        ns = prog["init_pid_ns"].address_of_()
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


@takes_object_or_program_or_default
def find_task(prog: Program, ns: Optional[Object], pid: IntegerLike) -> Object:
    """
    Return the task with the given PID.

    :param ns: ``struct pid_namespace *``. Defaults to the initial PID
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :return: ``struct task_struct *``
    """
    if ns is None:
        ns = prog["init_pid_ns"].address_of_()
    return _linux_helper_find_task(ns, pid)


@takes_object_or_program_or_default
def for_each_task(
    prog: Program, ns: Optional[Object], *, idle: bool = False
) -> Iterator[Object]:
    """
    Iterate over all of the tasks visible in a namespace.

    :param ns: ``struct pid_namespace *``. Defaults to the initial PID
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :param idle: Whether to include the idle threads (PID 0, a.k.a swapper) for
        each CPU.
    :return: Iterator of ``struct task_struct *`` objects.
    """
    if idle:
        for cpu in for_each_online_cpu(prog):
            yield idle_task(prog, cpu)

    PIDTYPE_PID = prog["PIDTYPE_PID"].value_()
    for pid in for_each_pid(prog if ns is None else ns):
        task = pid_task(pid, PIDTYPE_PID)
        if task:
            yield task


def for_each_task_in_group(
    task: Object, include_self: bool = False
) -> Iterator[Object]:
    """
    Iterate over all tasks in the thread group

    Or, in the more common userspace terms, iterate over all threads of a
    process.

    :param task: a task whose group to iterate over
    :param include_self: should ``task`` itself be returned?
    :returns: an iterable of every thread in the thread group
    """
    for other in list_for_each_entry(
        "struct task_struct",
        task.signal.thread_head.address_of_(),
        "thread_node",
    ):
        if other != task or include_self:
            yield other
