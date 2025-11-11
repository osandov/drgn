# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Interprocess Communication
--------------------------

The ``drgn.helpers.linux.ipc`` module provides helpers for working with System
V interprocess communication mechanisms.
"""

import operator
from typing import Iterator, Optional

from drgn import NULL, IntegerLike, Object, ObjectNotFoundError, Program, container_of
from drgn.helpers.common.format import decode_flags
from drgn.helpers.common.prog import (
    takes_object_or_program_or_default,
    takes_program_or_default,
)
from drgn.helpers.linux.idr import idr_find, idr_for_each

__all__ = (
    "decode_sysv_shm_flags",
    "decode_sysv_shm_mode_flags",
    "find_sysv_msg_queue",
    "find_sysv_sem_array",
    "find_sysv_shm",
    "for_each_sysv_msg_queue",
    "for_each_sysv_sem_array",
    "for_each_sysv_shm",
)

_IPC_SEM_IDS = 0
_IPC_MSG_IDS = 1
_IPC_SHM_IDS = 2


def _for_each_sysv_ipc(
    prog: Program, ns: Optional[Object], kind: int, type_name: str, member: str
) -> Iterator[Object]:
    if ns is None:
        ns = prog["init_ipc_ns"]
    for _, entry in idr_for_each(ns.ids[kind].ipcs_idr.address_of_()):
        yield container_of(entry, type_name, member)


def _find_sysv_ipc(
    prog: Program,
    ns: Optional[Object],
    id: IntegerLike,
    kind: int,
    type_name: str,
    member: str,
) -> Object:
    if ns is None:
        ns = prog["init_ipc_ns"]
    try:
        ipcmni_seq_shift = prog["ipc_mni_shift"].value_()
    except ObjectNotFoundError:
        ipcmni_seq_shift = 15
    id = operator.index(id)

    entry = idr_find(
        ns.ids[kind].ipcs_idr.address_of_(), id & ((1 << ipcmni_seq_shift) - 1)
    )
    if not entry:
        return NULL(prog, prog.pointer_type(prog.type(type_name)))
    entry = container_of(entry, type_name, member)
    if entry.member_(member).seq.value_() != (id >> ipcmni_seq_shift):
        return NULL(prog, entry.type_)
    return entry


@takes_object_or_program_or_default
def for_each_sysv_msg_queue(prog: Program, ns: Optional[Object]) -> Iterator[Object]:
    """
    Iterate over all System V message queues in a namespace.

    :param ns: ``struct ipc_namespace *``. Defaults to the initial IPC
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :return: Iterator of ``struct msg_queue *`` objects.
    """
    return _for_each_sysv_ipc(prog, ns, _IPC_MSG_IDS, "struct msg_queue", "q_perm")


@takes_object_or_program_or_default
def find_sysv_msg_queue(prog: Program, ns: Optional[Object], id: IntegerLike) -> Object:
    """
    Find a System V message queue by ID.

    :param ns: ``struct ipc_namespace *``. Defaults to the initial IPC
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :param id: Message queue identifier.
    :return: ``struct msg_queue *`` (``NULL`` if not found)
    """
    return _find_sysv_ipc(prog, ns, id, _IPC_MSG_IDS, "struct msg_queue", "q_perm")


@takes_object_or_program_or_default
def for_each_sysv_shm(prog: Program, ns: Optional[Object]) -> Iterator[Object]:
    """
    Iterate over all System V shared memory segments in a namespace.

    :param ns: ``struct ipc_namespace *``. Defaults to the initial IPC
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :return: Iterator of ``struct shmid_kernel *`` objects.
    """
    return _for_each_sysv_ipc(prog, ns, _IPC_SHM_IDS, "struct shmid_kernel", "shm_perm")


@takes_object_or_program_or_default
def find_sysv_shm(prog: Program, ns: Optional[Object], id: IntegerLike) -> Object:
    """
    Find a System V shared memory segment by ID.

    :param ns: ``struct ipc_namespace *``. Defaults to the initial IPC
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :param id: Shared memory segment identifier.
    :return: ``struct shmid_kernel *`` (``NULL`` if not found)
    """
    return _find_sysv_ipc(prog, ns, id, _IPC_SHM_IDS, "struct shmid_kernel", "shm_perm")


def decode_sysv_shm_flags(shm: Object) -> str:
    """
    Get a human-readable representation of the flags set on a System V shared
    memory segment.

    >>> decode_sysv_shm_flags(shm)
    'SHM_LOCKED'

    :param shm: ``struct shmid_kernel *``
    """
    return decode_sysv_shm_mode_flags(shm.shm_perm.mode)


@takes_program_or_default
def decode_sysv_shm_mode_flags(prog: Program, value: IntegerLike) -> str:
    """
    Get a human-readable representation of the flags in the ``mode`` value of a
    System V shared memory segment.

    >>> decode_sysv_shm_mode_flags(0o2777)
    'SHM_LOCKED'

    :param mode: ``umode_t``
    """
    return decode_flags(
        operator.index(value) & ~0o777,
        # These are ABI, so we don't have to worry about them changing.
        (("SHM_DEST", 0o1000), ("SHM_LOCKED", 0o2000)),
        bit_numbers=False,
    )


@takes_object_or_program_or_default
def for_each_sysv_sem_array(prog: Program, ns: Optional[Object]) -> Iterator[Object]:
    """
    Iterate over all System V semaphore arrays in a namespace.

    :param ns: ``struct ipc_namespace *``. Defaults to the initial IPC
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :return: Iterator of ``struct sem_array *`` objects.
    """
    return _for_each_sysv_ipc(prog, ns, _IPC_SEM_IDS, "struct sem_array", "sem_perm")


@takes_object_or_program_or_default
def find_sysv_sem_array(prog: Program, ns: Optional[Object], id: IntegerLike) -> Object:
    """
    Find a System V semaphore array by ID.

    :param ns: ``struct ipc_namespace *``. Defaults to the initial IPC
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :param id: Semaphore array identifier.
    :return: ``struct sem_array *`` (``NULL`` if not found)
    """
    return _find_sysv_ipc(prog, ns, id, _IPC_SEM_IDS, "struct sem_array", "sem_perm")
