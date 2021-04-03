# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os

from drgn.helpers.linux.pid import find_pid, find_task, for_each_pid, for_each_task
from tests.helpers.linux import LinuxHelperTestCase


class TestPid(LinuxHelperTestCase):
    def test_find_pid(self):
        pid = os.getpid()
        self.assertEqual(find_pid(self.prog, pid).numbers[0].nr, pid)

    def test_for_each_pid(self):
        pid = os.getpid()
        self.assertTrue(
            any(
                pid_struct.numbers[0].nr == pid
                for pid_struct in for_each_pid(self.prog)
            )
        )

    def test_find_task(self):
        pid = os.getpid()
        with open("/proc/self/comm", "rb") as f:
            comm = f.read()[:-1]
        task = find_task(self.prog, os.getpid())
        self.assertEqual(task.pid, pid)
        self.assertEqual(task.comm.string_(), comm)

    def test_for_each_task(self):
        pid = os.getpid()
        self.assertTrue(any(task.pid == pid for task in for_each_task(self.prog)))
