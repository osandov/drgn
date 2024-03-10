# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Locks
-----------

The ``drgn.helpers.linux.locks`` module provides helpers for working with
different kernel locking primitives like semaphore, mutex, read-write
semaphore etc.
"""
from typing import Iterator

from drgn import NULL, Object, cast
from drgn.helpers.linux.list import list_for_each_entry

######################################
# mutex
######################################

_MUTEX_FLAGS = 0x07


def mutex_owner(lock: Object) -> Object:
    """
    Get owner of a mutex.

    :param lock: ``struct mutex *``
    :return: ``struct task_struct *`` corresponding to owner, ``NULL``
             otherwise.
    """
    try:
        owner = lock.owner
        if owner.type_.type_name() == "struct task_struct *":
            return owner
        elif owner.value_():
            # Since Linux kernel commit 3ca0ff571b09 ("locking/mutex: Rework mutex::owner")
            # (in v4.10) count has been replaced with atomic_long_t owner that contains the
            # owner information (earlier available under task_struct *owner) and uses lower
            # bits for mutex state
            owner = cast("unsigned long", owner.counter.read_()) & ~_MUTEX_FLAGS
            return Object(lock.prog_, "struct task_struct", address=owner).address_of_()
        else:
            return NULL(lock.prog_, "struct task_struct *")
    except AttributeError:
        print("Mutex does not have owner information")
        return NULL(lock.prog_, "struct task_struct *")


def mutex_is_locked(lock: Object) -> bool:
    """
    Check if a given mutex is locked or not.

    :param lock: ``struct mutex *``
    :return: True if mutex is locked, False otherwise.
    """
    try:
        count = lock.count
        if count.counter.value_() != 1:
            return True
        else:
            return False
    except AttributeError:
        ret = True if mutex_owner(lock) else False
        return ret


def mutex_for_each_waiter(lock: Object) -> Iterator[Object]:
    """
    Iterate over all mutex_waiter objects for a mutex.

    :param lock: ``struct mutex *``
    :return: Iterator of ``struct mutex_waiter *`` objects.
    """
    for waiter in list_for_each_entry(
        "struct mutex_waiter", lock.wait_list.address_of_(), "list"
    ):
        yield waiter


def mutex_for_each_waiter_task(lock: Object) -> Iterator[Object]:
    """
    Iterate over all tasks blocked on a mutex.

    :param lock: ``struct mutex *``
    :return: Iterator of ``struct task_struct *`` objects.
    """
    for waiter in mutex_for_each_waiter(lock):
        yield waiter.task


######################################
# semaphore
######################################


def semaphore_is_locked(lock: Object) -> bool:
    """
    Check if a given semaphore is locked or not.

    :param lock: ``struct semaphore *``
    :return: True if semphore is locked (i.e count <= 0), False otherwise.
    """

    return lock.count.value_() <= 0


def semaphore_for_each_waiter(lock: Object) -> Iterator[Object]:
    """
    Iterate over all semaphore_waiter objects for a semaphore.

    :param lock: ``struct semaphore *``
    :return: Iterator of ``struct semaphore_waiter *`` objects.
    """
    for waiter in list_for_each_entry(
        "struct semaphore_waiter", lock.wait_list.address_of_(), "list"
    ):
        yield waiter


def semaphore_for_each_waiter_task(lock: Object) -> Iterator[Object]:
    """
    Iterate over all tasks blocked on a semaphore.

    :param lock: ``struct semaphore *``
    :return: Iterator of ``struct task_struct *`` objects.
    """
    for waiter in semaphore_for_each_waiter(lock):
        yield waiter.task
