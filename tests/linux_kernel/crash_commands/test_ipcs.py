# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import re

from drgn import Object
from drgn.helpers.linux.ipc import find_sysv_msg_queue, find_sysv_shm
from tests.linux_kernel.crash_commands import CrashCommandTestCase
from tests.linux_kernel.helpers.test_ipc import tmp_sysv_ipc


class TestIpcs(CrashCommandTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.run_crash_command("set -p")
        cls.ipcs = cls.enterClassContext(tmp_sysv_ipc())

    def test_ipcs(self):
        cmd = self.check_crash_command("ipcs")
        found_shm = {}
        found_sem = {}
        found_msg = {}
        for line in cmd.stdout.splitlines():
            if line.startswith("SHMID_KERNEL"):
                found = found_shm
            elif line.startswith("SEM_ARRAY"):
                found = found_sem
            elif line.startswith("MSG_QUEUE"):
                found = found_msg
            elif match := re.match(r"[0-9a-f]+\s+([0-9a-f]+)\s+([0-9]+)", line):
                found[(int(match.group(1), 16), int(match.group(2)))] = line

        for key, id in self.ipcs.shm:
            self.assertIn((key, id), found_shm)
        self.assertIn("SHM_LOCKED", found_shm[self.ipcs.shm[0]])

        for key, id in self.ipcs.sem:
            self.assertIn((key, id), found_sem)

        for key, id in self.ipcs.msg:
            self.assertIn((key, id), found_msg)

        self.assertEqual(
            cmd.drgn_option.globals["shm"].type_.type_name(), "struct shmid_kernel *"
        )
        self.assertEqual(
            cmd.drgn_option.globals["sem_array"].type_.type_name(), "struct sem_array *"
        )
        self.assertEqual(
            cmd.drgn_option.globals["msg_queue"].type_.type_name(), "struct msg_queue *"
        )

        for variable in (
            "key",
            "id",
            "perms",
            "bytes",
            "nattch",
            "nsems",
            "used_bytes",
            "messages",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

        self.assertIsInstance(cmd.drgn_option.globals["uid"], int)
        self.assertIsInstance(cmd.drgn_option.globals["status"], str)

    def test_s(self):
        cmd = self.check_crash_command("ipcs -s")
        self.assertIn("SEM_ARRAY", cmd.stdout)
        self.assertNotIn("SHMID_KERNEL", cmd.stdout)
        self.assertNotIn("MSG_QUEUE", cmd.stdout)

        self.assertEqual(
            cmd.drgn_option.globals["sem_array"].type_.type_name(), "struct sem_array *"
        )
        self.assertNotIn("shm", cmd.drgn_option.globals)
        self.assertNotIn("msg_queue", cmd.drgn_option.globals)

        for variable in (
            "key",
            "id",
            "perms",
            "nsems",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

        self.assertIsInstance(cmd.drgn_option.globals["uid"], int)

        self.assertNotIn("bytes", cmd.drgn_option.globals)
        self.assertNotIn("nattch", cmd.drgn_option.globals)
        self.assertNotIn("used_bytes", cmd.drgn_option.globals)
        self.assertNotIn("messages", cmd.drgn_option.globals)
        self.assertNotIn("status", cmd.drgn_option.globals)

    def test_m(self):
        cmd = self.check_crash_command("ipcs -m")
        self.assertIn("SHMID_KERNEL", cmd.stdout)
        self.assertNotIn("SEM_ARRAY", cmd.stdout)
        self.assertNotIn("MSG_QUEUE", cmd.stdout)

        self.assertEqual(
            cmd.drgn_option.globals["shm"].type_.type_name(), "struct shmid_kernel *"
        )
        self.assertNotIn("sem_array", cmd.drgn_option.globals)
        self.assertNotIn("msg_queue", cmd.drgn_option.globals)

        for variable in (
            "key",
            "id",
            "perms",
            "bytes",
            "nattch",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

        self.assertIsInstance(cmd.drgn_option.globals["uid"], int)
        self.assertIsInstance(cmd.drgn_option.globals["status"], str)

        self.assertNotIn("nsems", cmd.drgn_option.globals)
        self.assertNotIn("used_bytes", cmd.drgn_option.globals)
        self.assertNotIn("messages", cmd.drgn_option.globals)

    def test_q(self):
        cmd = self.check_crash_command("ipcs -q")
        self.assertIn("MSG_QUEUE", cmd.stdout)
        self.assertNotIn("SHMID_KERNEL", cmd.stdout)
        self.assertNotIn("SEM_ARRAY", cmd.stdout)

        self.assertEqual(
            cmd.drgn_option.globals["msg_queue"].type_.type_name(), "struct msg_queue *"
        )
        self.assertNotIn("shm", cmd.drgn_option.globals)
        self.assertNotIn("sem_array", cmd.drgn_option.globals)

        for variable in (
            "key",
            "id",
            "perms",
            "used_bytes",
            "messages",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

        self.assertIsInstance(cmd.drgn_option.globals["uid"], int)

        self.assertNotIn("bytes", cmd.drgn_option.globals)
        self.assertNotIn("nattch", cmd.drgn_option.globals)
        self.assertNotIn("status", cmd.drgn_option.globals)
        self.assertNotIn("nsems", cmd.drgn_option.globals)

    def test_id(self):
        shm_key, shm_id = self.ipcs.shm[0]

        cmd = self.check_crash_command(f"ipcs {shm_id}")
        found_shm = {}
        found_sem = {}
        found_msg = {}
        for line in cmd.stdout.splitlines():
            if line.startswith("SHMID_KERNEL"):
                found = found_shm
            elif line.startswith("SEM_ARRAY"):
                found = found_sem
            elif line.startswith("MSG_QUEUE"):
                found = found_msg
            elif match := re.match(r"[0-9a-f]+\s+([0-9a-f]+)\s+([0-9]+)", line):
                found[(int(match.group(1), 16), int(match.group(2)))] = line

        for key, id in self.ipcs.shm:
            if (key, id) == (shm_key, shm_id):
                self.assertIn((key, id), found_shm)
            else:
                self.assertNotIn((key, id), found_shm)
        self.assertIn("SHM_LOCKED", found_shm[self.ipcs.shm[0]])

        self.assertEqual(
            cmd.drgn_option.globals["shm"], find_sysv_shm(self.prog, shm_id)
        )

        for variable in (
            "key",
            "id",
            "perms",
            "bytes",
            "nattch",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

        self.assertIsInstance(cmd.drgn_option.globals["uid"], int)
        self.assertIsInstance(cmd.drgn_option.globals["status"], str)

    def test_addr(self):
        msg_key, msg_id = self.ipcs.msg[0]
        msg_queue = find_sysv_msg_queue(self.prog, msg_id)

        cmd = self.check_crash_command(f"ipcs {hex(msg_queue)}")
        found_shm = {}
        found_sem = {}
        found_msg = {}
        for line in cmd.stdout.splitlines():
            if line.startswith("SHMID_KERNEL"):
                found = found_shm
            elif line.startswith("SEM_ARRAY"):
                found = found_sem
            elif line.startswith("MSG_QUEUE"):
                found = found_msg
            elif match := re.match(r"[0-9a-f]+\s+([0-9a-f]+)\s+([0-9]+)", line):
                found[(int(match.group(1), 16), int(match.group(2)))] = line

        for key, id in self.ipcs.msg:
            if (key, id) == (msg_key, msg_id):
                self.assertIn((key, id), found_msg)
            else:
                self.assertNotIn((key, id), found_msg)

        self.assertFalse(found_shm)
        self.assertFalse(found_sem)

        self.assertEqual(
            cmd.drgn_option.globals["msg_queue"].type_.type_name(), "struct msg_queue *"
        )

        for variable in (
            "key",
            "id",
            "perms",
            "used_bytes",
            "messages",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

        self.assertIsInstance(cmd.drgn_option.globals["uid"], int)

        self.assertNotIn("bytes", cmd.drgn_option.globals)
        self.assertNotIn("nattch", cmd.drgn_option.globals)
        self.assertNotIn("status", cmd.drgn_option.globals)
        self.assertNotIn("nsems", cmd.drgn_option.globals)

    def test_n_pid(self):
        cmd = self.check_crash_command("ipcs -n 1")
        self.assertIn("SHM_LOCKED", cmd.stdout)
        self.assertIn("for_each_sysv_shm(ipc_ns)", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["ipc_ns"], self.prog["init_ipc_ns"].address_of_()
        )

    def test_n_task(self):
        task = self.prog["init_task"].address_of_()
        cmd = self.check_crash_command(f"ipcs -n {hex(task)}")
        self.assertIn("SHM_LOCKED", cmd.stdout)
        self.assertIn("for_each_sysv_shm(ipc_ns)", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["ipc_ns"], self.prog["init_ipc_ns"].address_of_()
        )

    def test_n_and_id(self):
        shm_key, shm_id = self.ipcs.shm[0]
        cmd = self.check_crash_command(f"ipcs -n 1 {shm_id}")
        self.assertIn("SHM_LOCKED", cmd.stdout)
        self.assertIn("find_sysv_shm(ipc_ns,", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["ipc_ns"], self.prog["init_ipc_ns"].address_of_()
        )

    def test_n_and_addr(self):
        msg_key, msg_id = self.ipcs.msg[0]
        msg_queue = find_sysv_msg_queue(self.prog, msg_id)

        cmd = self.check_crash_command(f"ipcs -n 1 {hex(msg_queue)}")
        self.assertIn("for_each_sysv_msg_queue(ipc_ns)", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["ipc_ns"], self.prog["init_ipc_ns"].address_of_()
        )
