# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Process IDS
-----------

The ``drgn.helpers.linux.pid`` module provides helpers for looking up process
IDs and processes.
"""

from typing import Iterator, Union

from _drgn import (
    _linux_helper_find_pid as find_pid,
    _linux_helper_find_task as find_task,
    _linux_helper_pid_task as pid_task,
)
from drgn import NULL, Object, Program, cast, container_of
from drgn.helpers.linux.idr import idr_find, idr_for_each
from drgn.helpers.linux.list import hlist_for_each_entry

__all__ = (
    "find_pid",
    "find_task",
    "for_each_pid",
    "for_each_task",
    "pid_task",
)


def for_each_pid(prog_or_ns: Union[Program, Object]) -> Iterator[Object]:
    """
    Iterate over all PIDs in a namespace.

    :param prog_or_ns: ``struct pid_namespace *`` to iterate over, or
        :class:`Program` to iterate over initial PID namespace.
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


def for_each_task(prog_or_ns: Union[Program, Object]) -> Iterator[Object]:
    """
    Iterate over all of the tasks visible in a namespace.

    :param prog_or_ns: ``struct pid_namespace *`` to iterate over, or
        :class:`Program` to iterate over initial PID namespace.
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
