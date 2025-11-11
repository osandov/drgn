# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
from pathlib import Path
import tempfile
import types

from drgn import NULL
from drgn.helpers.linux.ipc import (
    decode_sysv_shm_flags,
    find_sysv_msg_queue,
    find_sysv_sem_array,
    find_sysv_shm,
    for_each_sysv_msg_queue,
    for_each_sysv_sem_array,
    for_each_sysv_shm,
)
from tests.linux_kernel import (
    IPC_PRIVATE,
    IPC_RMID,
    SHM_LOCK,
    LinuxKernelTestCase,
    ftok,
    msgctl,
    msgget,
    semctl,
    semget,
    shmctl,
    shmget,
)

_PROC_SYSVIPC_PATH = Path("/proc/sysvipc")


@contextlib.contextmanager
def tmp_sysv_ipc():
    try:
        msg = []
        sem = []
        shm = []

        with tempfile.NamedTemporaryFile() as tmp_file:
            key = ftok(tmp_file.name, ord("m"))
            msg.append((key, msgget(key)))

            key = ftok(tmp_file.name, ord("e"))
            sem.append((key, semget(key, nsems=4)))

            key = ftok(tmp_file.name, ord("h"))
            shm.append((key, shmget(key, size=64 * 1024)))

        msg.append((IPC_PRIVATE, msgget(IPC_PRIVATE)))
        sem.append((IPC_PRIVATE, semget(IPC_PRIVATE, nsems=4)))
        shm.append((IPC_PRIVATE, shmget(IPC_PRIVATE, size=64 * 1024)))

        shmctl(shm[0][1], SHM_LOCK)

        yield types.SimpleNamespace(msg=msg, sem=sem, shm=shm)
    finally:
        for _, msqid in msg:
            msgctl(msqid, IPC_RMID)
        for _, semid in sem:
            semctl(semid, 0, IPC_RMID)
        for _, shmid in shm:
            shmctl(shmid, IPC_RMID)


def parse_proc_sysvipc_key_and_id(name):
    result = []
    with (_PROC_SYSVIPC_PATH / name).open("r") as f:
        f.readline()  # Skip the header.
        for line in f:
            tokens = line.split()
            result.append((int(tokens[0]), int(tokens[1])))
    assert result
    return result


class TestIpc(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ipcs = cls.enterClassContext(tmp_sysv_ipc())

    def test_for_each_sysv_msg_queue(self):
        self.assertCountEqual(
            [
                (msg_queue.q_perm.key.value_(), msg_queue.q_perm.id.value_())
                for msg_queue in for_each_sysv_msg_queue(self.prog)
            ],
            parse_proc_sysvipc_key_and_id("msg"),
        )

    def test_find_sysv_msg_queue(self):
        key, id = self.ipcs.msg[0]
        self.assertEqual(find_sysv_msg_queue(self.prog, id).q_perm.key, key)
        self.assertIdentical(
            find_sysv_msg_queue(self.prog, id ^ 0x40000000),
            NULL(self.prog, "struct msg_queue *"),
        )

    def test_for_each_sysv_shm(self):
        self.assertCountEqual(
            [
                (shm.shm_perm.key.value_(), shm.shm_perm.id.value_())
                for shm in for_each_sysv_shm(self.prog)
            ],
            parse_proc_sysvipc_key_and_id("shm"),
        )

    def test_find_sysv_shm(self):
        key, id = self.ipcs.shm[0]
        self.assertEqual(find_sysv_shm(self.prog, id).shm_perm.key, key)
        self.assertIdentical(
            find_sysv_shm(self.prog, id ^ 0x40000000),
            NULL(self.prog, "struct shmid_kernel *"),
        )

    def test_decode_sysv_shm_flags(self):
        id = self.ipcs.shm[0][1]
        self.assertEqual(
            decode_sysv_shm_flags(find_sysv_shm(self.prog, id)), "SHM_LOCKED"
        )

    def test_for_each_sysv_sem_array(self):
        self.assertCountEqual(
            [
                (sem_array.sem_perm.key.value_(), sem_array.sem_perm.id.value_())
                for sem_array in for_each_sysv_sem_array(self.prog)
            ],
            parse_proc_sysvipc_key_and_id("sem"),
        )

    def test_find_sysv_sem_array(self):
        key, id = self.ipcs.sem[0]
        self.assertEqual(find_sysv_sem_array(self.prog, id).sem_perm.key, key)
        self.assertIdentical(
            find_sysv_sem_array(self.prog, id ^ 0x40000000),
            NULL(self.prog, "struct sem_array *"),
        )
