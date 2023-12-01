# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Wait Queues
-----------

The ``drgn.helpers.linux.wait`` module provides helpers for working with wait
queues (``wait_queue_head_t`` and ``wait_queue_entry_t``) from
:linux:`include/linux/wait.h`.

.. note::

    Since Linux 4.13, entries in a wait queue have type ``wait_queue_entry_t``.
    Before that, the type was named ``wait_queue_t``.
"""

from typing import Iterator

from drgn import Object, cast
from drgn.helpers.linux.list import list_empty, list_for_each_entry

__all__ = (
    "waitqueue_active",
    "waitqueue_for_each_entry",
    "waitqueue_for_each_task",
)


def _get_wait_queue_head(wq: Object) -> Object:
    # Linux kernel commit 2055da97389a ("sched/wait: Disambiguate
    # wq_entry->task_list and wq_head->task_list naming") (in v4.13) renamed
    # the task_list member to head.
    try:
        return wq.head
    except AttributeError:
        return wq.task_list


def waitqueue_active(wq: Object) -> bool:
    """
    Return whether a wait queue has any waiters.

    :param wq: ``wait_queue_head_t *``
    """
    head = _get_wait_queue_head(wq)
    return not list_empty(head.address_of_())


def waitqueue_for_each_entry(wq: Object) -> Iterator[Object]:
    """
    Iterate over all entries in a wait queue.

    :param wq: ``wait_queue_head_t *``
    :return: Iterator of ``wait_queue_entry_t *`` or ``wait_queue_t *``
        objects depending on the kernel version.
    """
    head_addr = _get_wait_queue_head(wq).address_of_()
    prog = wq.prog_
    # Linux kernel commit ac6424b981bc ("sched/wait: Rename wait_queue_t =>
    # wait_queue_entry_t") (in v4.13) renamed the entry type and commit
    # 2055da97389a ("sched/wait: Disambiguate wq_entry->task_list and
    # wq_head->task_list naming") (in v4.13) renamed .task_list to .entry.
    try:
        wait_queue_entry_type, link = prog.type("wait_queue_entry_t"), "entry"
    except LookupError:
        wait_queue_entry_type, link = prog.type("wait_queue_t"), "task_list"

    return list_for_each_entry(wait_queue_entry_type, head_addr, link)


def waitqueue_for_each_task(wq: Object) -> Iterator[Object]:
    """
    Iterate over all tasks waiting on a wait queue.

    .. warning::

        This comes from ``wait_queue_entry_t::private``, which usually stores a
        task. However, some wait queue entries store a different pointer type,
        in which case this will return garbage.

    :param wq: ``wait_queue_head_t *``
    :return: Iterator of ``struct task_struct *`` objects.
    """
    task_structp_type = wq.prog_.type("struct task_struct *")
    for entry in waitqueue_for_each_entry(wq):
        yield cast(task_structp_type, entry.private)
