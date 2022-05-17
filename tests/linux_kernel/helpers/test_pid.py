# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from multiprocessing import Barrier, Process
import os

from drgn.helpers.linux.pid import find_pid, find_task, for_each_pid, for_each_task
from tests.linux_kernel import LinuxKernelTestCase


class TestPid(LinuxKernelTestCase):
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
        NUM_PROCS = 12
        barrier = Barrier(NUM_PROCS + 1)

        def proc_func():
            barrier.wait()

        try:
            procs = [Process(target=proc_func) for _ in range(NUM_PROCS)]
            for proc in procs:
                proc.start()
            pids = {task.pid.value_() for task in for_each_task(self.prog)}
            for proc in procs:
                self.assertIn(proc.pid, pids)
            self.assertIn(os.getpid(), pids)
            barrier.wait()
        except BaseException:
            barrier.abort()
            for proc in procs:
                proc.terminate()
            raise
