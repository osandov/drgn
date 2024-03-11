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


######################################
# rwsem
######################################

# Masks for rwsem.count
_RWSEM_WRITER_LOCKED = 1 << 0
_RWSEM_FLAG_WAITERS = 1 << 1
_RWSEM_FLAG_HANDOFF = 1 << 2
# Bits 8-62(i.e. 55 bits of counter indicate number of current readers that hold the lock)
_RWSEM_READER_MASK = 0x7FFFFFFFFFFFFF00  # Bits 8-62 - 55-bit reader count
_RWSEM_WRITER_MASK = 1 << 0
_RWSEM_READER_SHIFT = 8

# Masks for rwsem.owner
_RWSEM_READER_OWNED = 1 << 0
_RWSEM_ANONYMOUSLY_OWNED = 1 << 0  # For old kernels
_RWSEM_RD_NONSPINNABLE = 1 << 1
_RWSEM_WR_NONSPINNABLE = 1 << 2

# Linux kernel commit 617f3ef95177840c77f59c2aec1029d27d5547d6 ("locking/rwsem:
# Remove reader optimistic spinning") (in v5.11) removed optimistic spinning for
# readers and hence left one bit to check for spinnable
_RWSEM_NONSPINNABLE = 1 << 1


def rwsem_for_each_waiter(rwsem: Object) -> Iterator[Object]:
    """
    Iterate over all rwsem_waiter objects for a given rwsem.

    :param rwsem: ``struct rw_semaphore *``
    :returns: Iterator of ``struct rwsem_waiter``
    """

    for waiter in list_for_each_entry(
        "struct rwsem_waiter", rwsem.wait_list.address_of_(), "list"
    ):
        yield waiter


def rwsem_for_each_waiter_task(rwsem: Object) -> Iterator[Object]:
    """
    Iterate over all tasks blocked on  a given rwsem.

    :param rwsem: ``struct rw_semaphore *``
    :returns: Iterator of ``struct task_struct *``
    """

    for waiter in rwsem_for_each_waiter(rwsem):
        yield waiter.task


def get_rwsem_owner(rwsem: Object) -> Object:
    """
    Find owner of  given rwsem

    :param rwsem: ``struct rw_semaphore *``
    :returns: ``struct task_struct *`` if owner can be found, NULL otherwise
    """
    prog = rwsem.prog_
    if not rwsem.count.counter.value_():
        print("rwsem is free.")
        return NULL(prog, "struct task_struct *")

    if is_rwsem_writer_owned(rwsem):
        if rwsem.owner.type_.type_name() != "atomic_long_t":
            if rwsem.owner.value_() & _RWSEM_ANONYMOUSLY_OWNED:
                print("rwsem is owned by anonymous writer")
                return NULL(prog, "struct task_struct *")
            else:
                return rwsem.owner
        else:
            owner = cast("struct task_struct *", rwsem.owner.counter)
            return owner
    else:
        # If rwsem is owned by one or more readers or other cases
        # when owner field is not reliable
        print("Could not reliably determine rwsem owner")
        return NULL(prog, "struct task_struct *")


def get_rwsem_waiter_type(rwsem_waiter: Object) -> str:
    """
    Find type of an rwsem waiter

    :param rwsem_waiter: ``struct rwsem_waiter``
    :returns: str indicating type of rwsem waiter
    """

    prog = rwsem_waiter.prog_
    if rwsem_waiter.type.value_() == prog["RWSEM_WAITING_FOR_WRITE"].value_():
        waiter_type = "down_write"
    elif rwsem_waiter.type.value_() == prog["RWSEM_WAITING_FOR_READ"].value_():
        waiter_type = "down_read"
    else:
        waiter_type = "waiter type unknown"

    return waiter_type


def is_rwsem_reader_owned(rwsem: Object) -> bool:
    """
    Check if rwsem is reader owned or not

    :param rwsem: ``struct rw_semaphore *``
    :returns: True if rwsem is reader owned, False otherwise (including the
              case when type of owner could not be determined or when rwsem
              is free.)
    """
    if not rwsem.count.counter.value_():  # rwsem is free
        return False
    if rwsem.owner.type_.type_name() == "atomic_long_t":
        # If LSB of rwsem.count is set, rwsem is owned by a writer
        owner_is_writer = rwsem.count.counter.value_() & _RWSEM_WRITER_LOCKED
        # To confirm that rwsem is owned by a reader, 3 conditions
        # should be true
        #  1. Reader count i.e bits 8-62 of rwsem.count should have some
        #     non-zero value
        #  2. LSB of rwsem.owner should be set
        #  3. LSB of rwsem.count should not be set i.e rwsem is not owned
        #     by a writer
        owner_is_reader = (
            (rwsem.count.counter.value_() & _RWSEM_READER_MASK)
            and (rwsem.owner.counter.value_() & _RWSEM_READER_OWNED)
            and (owner_is_writer == 0)
        )

        return bool(owner_is_reader)
    else:
        if not rwsem.owner.value_():
            print("rwsem is being acquired but owner info has not yet been set.")
            return False
        owner_is_reader = rwsem.owner.value_() == _RWSEM_READER_OWNED
        return owner_is_reader


def is_rwsem_writer_owned(rwsem: Object) -> bool:
    """
    Check if rwsem is writer owned or not

    :param rwsem: ``struct rw_semaphore *``
    :returns: True if rwsem is writer owned, False otherwise (including the
              case when type of owner could not be determined or when rwsem
              was free.)
    """
    if not rwsem.count.counter.value_():  # rwsem is free
        return False

    if rwsem.owner.type_.type_name() == "atomic_long_t":
        # If LSB of rwsem.count is set, rwsem is owned by a writer
        owner_is_writer = rwsem.count.counter.value_() & _RWSEM_WRITER_LOCKED
        return bool(owner_is_writer)
    else:
        if not rwsem.owner.value_():
            print("rwsem is being acquired but owner info has not yet been set.")
            return False

        owner_is_reader = rwsem.owner.value_() == _RWSEM_READER_OWNED
        return not owner_is_reader
