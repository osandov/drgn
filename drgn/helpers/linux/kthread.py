# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Kernel Threads
--------------

The ``drgn.helpers.linux.kthread`` module provides helpers for working with
Linux kernel threads, a.k.a. kthreads.
"""

from drgn import Object, cast, container_of

__all__ = (
    "kthread_data",
    "task_is_kthread",
    "to_kthread",
)


def to_kthread(task: Object) -> Object:
    """
    Get the kthread information for a task.

    >>> to_kthread(find_task(3))
    *(struct kthread *)0xffff8ef600191580 = {
            ...
            .threadfn = (int (*)(void *))kthread_worker_fn+0x0 = 0xffffffffba1e61b0,
            .full_name = (char *)0xffff8ef6003d4ac0 = "pool_workqueue_release",
    }

    :param task: ``struct task *``
    :return: ``struct kthread *``
    """
    try:
        # Since Linux kernel commit e32cf5dfbe22 ("kthread: Generalize
        # pf_io_worker so it can point to struct kthread") (in v5.17), the
        # struct kthread * is in task->worker_private.
        return cast("struct kthread *", task.worker_private)
    except AttributeError:
        if "free_kthread_struct" in task.prog_:
            # Between that and Linux kernel commit 1da5c46fa965 ("kthread: Make
            # struct kthread kmalloc'ed") (in v4.10), it is in
            # task->set_child_tid. Unfortunately we can only distinguish this
            # by looking for another function added in that commit.
            return cast("struct kthread *", task.set_child_tid)
        else:
            # Before that, task->vfork_done points to kthread->exited.
            return container_of(task.vfork_done, "struct kthread", "exited")


def kthread_data(task: Object) -> Object:
    """
    Get the data that was specified when a kthread was created.

    >>> kthread_data(find_task(3))
    (void *)0xffff8ef6001812c0

    :param task: ``struct task *``
    :return: ``void *``
    """
    return to_kthread(task).data.read_()


def task_is_kthread(task: Object) -> bool:
    """
    Return whether a task is a kernel thread.

    :param task: ``struct task_struct *``
    """
    # This hasn't changed since Linux kernel commit 246bb0b1deb2 ("kill
    # PF_BORROWED_MM in favour of PF_KTHREAD") (in v2.6.27).
    PF_KTHREAD = 0x200000
    return bool(task.flags.value_() & PF_KTHREAD)
