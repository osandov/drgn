# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from multiprocessing import Barrier, Process
import os

from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import LinuxKernelTestCase


class TestThreads(LinuxKernelTestCase):
    def test_threads(self):
        NUM_PROCS = 12
        barrier = Barrier(NUM_PROCS + 1)

        def proc_func():
            barrier.wait()

        try:
            procs = [Process(target=proc_func) for _ in range(NUM_PROCS)]
            for proc in procs:
                proc.start()
            pids = {thread.tid for thread in self.prog.threads()}
            for proc in procs:
                self.assertIn(proc.pid, pids)
            self.assertIn(os.getpid(), pids)
            barrier.wait()
        except BaseException:
            barrier.abort()
            for proc in procs:
                proc.terminate()
            raise

    def test_thread(self):
        pid = os.getpid()
        thread = self.prog.thread(pid)
        self.assertEqual(thread.tid, pid)
        self.assertEqual(thread.object, find_task(self.prog, pid))

    def test_main_thread(self):
        self.assertRaisesRegex(
            ValueError,
            "main thread is not defined for the Linux kernel",
            self.prog.main_thread,
        )

    def test_crashed_thread(self):
        self.assertRaisesRegex(
            ValueError,
            "crashed thread is only defined for core dumps",
            self.prog.crashed_thread,
        )
