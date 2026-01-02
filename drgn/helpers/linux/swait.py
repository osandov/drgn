# Copyright (c) 2026, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Simple Wait Queues
------------------

The ``drgn.helpers.linux.swait`` module provides helpers for working with
simple wait queues (``swait_queue_head`` and ``swait_queue``) from
:linux:`include/linux/swait.h`.

"""

from typing import Iterator

from drgn import Object
from drgn.helpers.linux.list import list_empty, list_for_each_entry

__all__ = (
    "swait_active",
    "swait_for_each_task",
)


def swait_active(wq: Object) -> bool:
    """
    Return whether a simple wait queue has any waiters.

    :param wq: ``struct swait_queue_head *``
    """
    return not list_empty(wq.task_list.address_of_())


def swait_for_each_task(wq: Object) -> Iterator[Object]:
    """
    Iterate over all tasks waiting on a simple wait queue.

    :param wq: ``struct swait_queue_head *``
    :return: Iterator of ``struct task_struct *`` objects.
    """
    for entry in list_for_each_entry(
        "struct swait_queue", wq.task_list.address_of_(), "task_list"
    ):
        yield entry.task
