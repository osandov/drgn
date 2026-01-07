# Copyright (c) 2026, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Completion variables
------------------

The ``drgn.helpers.linux.completion`` module provides helpers for working with
completion variables (``struct completion``) from :linux:`include/linux/completion.h`.

"""

from typing import Iterator

from drgn import Object
from drgn.helpers.linux.swait import swait_for_each_task
from drgn.helpers.linux.wait import waitqueue_for_each_task

__all__ = (
    "completion_done",
    "completion_for_each_task",
)


def completion_done(completion: Object) -> bool:
    """
    Test if a completion has any waiters.

    :param completion: ``struct completion *``
    """
    return bool(completion.done)


def completion_for_each_task(completion: Object) -> Iterator[Object]:
    """
    Iterate over all tasks waiting on a completion variable.

    :param completion: ``struct completion *``
    :return: Iterator of ``struct task_struct *`` objects.
    """
    wait = completion.wait.address_of_()
    # completion->wait is a simple wait queue since Linux kernel commit
    # a5c6234e1028 ("completion: Use simple wait queues") (in v5.7).
    # Also Linux kernel commit 2055da97389a ("sched/wait: Disambiguate
    # wq_entry->task_list and wq_head->task_list naming") (in v4.13) renamed
    # the task_list member to head.
    # So completion->wait in kernels v5.7 and later and in kernels prior to v4.13,
    # have task_list member, but of different types. So use type of completion->wait
    # to differentiate between completion backends.
    if wait.type_.type_name() == "struct swait_queue_head *":
        return swait_for_each_task(wait)
    else:
        return waitqueue_for_each_task(wait)
