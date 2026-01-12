# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Locking
-------

The ``drgn.helpers.linux.locking`` module provides helpers for inspecting
locks, including mutexes and read-write semaphores.
"""


import enum

from drgn import Object, Program, TypeKind, cast

__all__ = (
    "mutex_owner",
    "rwsem_locked",
    "rwsem_owner",
)


# Before Linux kernel commit e274795ea7b7 ("locking/mutex: Fix mutex handoff")
# (in v4.11), this was 0x3, but task_struct was sufficiently aligned that it
# doesn't matter.
_MUTEX_FLAGS = 0x7


def mutex_owner(lock: Object) -> Object:
    """
    Get the task that currently owns a mutex.

    Before `Linux 4.10
    <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3ca0ff571b092ee4d807f1168caa428d95b0173b>`_,
    this is only supported when ``CONFIG_DEBUG_MUTEXES`` or
    ``CONFIG_MUTEX_SPIN_ON_OWNER`` are enabled.

    :param lock: ``struct mutex *``
    :return: ``struct task_struct *``
    """
    owner = lock.owner
    try:
        # Since Linux kernel commit 3ca0ff571b09 ("locking/mutex: Rework
        # mutex::owner") (in v4.10), struct mutex::owner is a tagged pointer in
        # an atomic_long_t.
        return cast("struct task_struct *", owner.counter & ~_MUTEX_FLAGS)
    except AttributeError:
        # Before that, it was a direct struct task_struct * pointer.
        return owner.read_()


# Linux kernel commit 64489e78004c ("locking/rwsem: Implement a new locking
# scheme") (in v5.3) changed how ownership is tracked. We can't easily detect
# that commit directly, but we can detect a later commit in the same series,
# 94a9717b3c40 ("locking/rwsem: Make rwsem->owner an atomic_long_t").
def _rwsem_new_scheme(prog: Program) -> bool:
    try:
        return prog.cache["rwsem_new_scheme"]
    except KeyError:
        pass
    ret = prog.type("struct rw_semaphore").member("owner").type.kind != TypeKind.POINTER
    prog.cache["rwsem_new_scheme"] = ret
    return ret


def rwsem_locked(sem: Object) -> "RwsemLocked":
    """
    Return whether a read-write semaphore is unlocked, read-locked, or
    write-locked.

    Before `Linux 5.3
    <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c71fd893f614f205dbc050d60299cc5496491c19>`_,
    this is only supported when ``CONFIG_RWSEM_SPIN_ON_OWNER`` is enabled.

    :param sem: ``struct rw_semaphore *``
    """
    count = sem.count.counter.value_()
    if not count:
        return RwsemLocked.UNLOCKED
    # Since Linux kernel commit 64489e78004c ("locking/rwsem: Implement a new
    # locking scheme") (in v5.3), we can use the RWSEM_WRITER_LOCKED flag (1)
    # to determine whether a semaphore is write-locked.
    #
    # Before that, count values are ambiguous, so we have to use the owner to
    # disambiguate. Between that and Linux kernel commit 925b9cd1b89a
    # ("locking/rwsem: Make owner store task pointer of last owning reader"),
    # we have to check whether the RWSEM_READER_OWNED flag (1) is set on the
    # owner. Before that, we have to check whether the owner is exactly
    # RWSEM_READER_OWNED (1). Annoyingly, the only way to detect this commit is
    # by the presence of a function.
    if _rwsem_new_scheme(sem.prog_):
        return RwsemLocked.WRITE_LOCKED if (count & 1) else RwsemLocked.READ_LOCKED
    elif "__rwsem_set_reader_owned" in sem.prog_:
        return (
            RwsemLocked.READ_LOCKED
            if sem.owner.value_() & 1
            else RwsemLocked.WRITE_LOCKED
        )
    else:
        return (
            RwsemLocked.READ_LOCKED
            if sem.owner.value_() == 1
            else RwsemLocked.WRITE_LOCKED
        )


class RwsemLocked(enum.Enum):
    """Locked status of a read-write semaphore."""

    UNLOCKED = enum.auto()
    ""
    READ_LOCKED = enum.auto()
    ""
    WRITE_LOCKED = enum.auto()
    ""

    # Make `if rwsem_locked(sem)` work as expected.
    def __bool__(self) -> bool:
        return self != RwsemLocked.UNLOCKED


# Since Linux kernel commit 617f3ef95177 ("locking/rwsem: Remove reader
# optimistic spinning") (in v5.11), this is actually 0x3. Between that and
# 7d43f1ce9dd0 ("locking/rwsem: Enable time-based spinning on reader-owned
# rwsem") (in v5.3), it was 0x7. Between that and 02f1082b003a ("locking/rwsem:
# Clarify usage of owner's nonspinaable bit") (in v5.3), it was also 0x3.
# Between that and 925b9cd1b89a ("locking/rwsem: Make owner store task pointer
# of last owning reader") (in v4.20), the macro name didn't exist, but the mask
# was (RWSEM_READER_OWNED|RWSEM_ANONYMOUSLY_OWNED), which was also 0x3. Before
# that, there was only RWSEM_ANONYMOUSLY_OWNED (0x1). task_struct is
# sufficiently aligned that none of this matters and we can just use 0x7.
_RWSEM_OWNER_FLAGS_MASK = 0x7


def rwsem_owner(sem: Object) -> Object:
    """
    Get the task that currently owns a read-write semaphore.

    .. warning::

        Due to the kernel implementation, unless the semaphore is currently
        write-locked, then this is not totally reliable.

        It may return ``NULL`` when the semaphore is read-locked (specifically,
        when the last task to read-lock the semaphore unlocks it and
        ``CONFIG_DEBUG_RWSEMS`` or ``CONFIG_DETECT_HUNG_TASK_BLOCKER`` are
        enabled, or before `Linux 4.20
        <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=925b9cd1b89a94b7124d128c80dfc48f78a63098>`_).

        It may also return a previous reader that no longer owns the semaphore
        when it is read-locked or unlocked (although an effort is made to avoid
        this when ``CONFIG_DEBUG_RWSEMS`` or
        ``CONFIG_DETECT_HUNG_TASK_BLOCKER`` are enabled unless
        ``up_read_non_owner()`` is used).

    Before `Linux 5.3
    <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c71fd893f614f205dbc050d60299cc5496491c19>`_,
    this is only supported when ``CONFIG_RWSEM_SPIN_ON_OWNER`` is enabled.

    :param sem: ``struct rw_semaphore *``
    :return: ``struct task_struct *``
    """
    # Since Linux kernel commit 94a9717b3c40 ("locking/rwsem: Make rwsem->owner
    # an atomic_long_t") (in v5.3), struct rw_semaphore::owner is an
    # atomic_long_t. Before that, it was a struct task_struct *. On all
    # kernels, it's actually a tagged pointer.
    if _rwsem_new_scheme(sem.prog_):
        counter = sem.owner.counter.value_()
    else:
        counter = sem.owner.value_()
    return Object(sem.prog_, "struct task_struct *", counter & ~_RWSEM_OWNER_FLAGS_MASK)
