# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from multiprocessing import Barrier, Process
import os
from threading import Condition, Thread

from drgn.helpers.linux.pid import (
    find_pid,
    find_task,
    for_each_pid,
    for_each_task,
    for_each_task_in_group,
)
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

        try:
            procs = [Process(target=barrier.wait) for _ in range(NUM_PROCS)]
            for proc in procs:
                proc.start()
            pids = {task.pid.value_() for task in for_each_task(self.prog)}
            for proc in procs:
                self.assertIn(proc.pid, pids)
            self.assertIn(os.getpid(), pids)
            self.assertNotIn(0, pids)
            barrier.wait()
        except BaseException:
            barrier.abort()
            for proc in procs:
                proc.terminate()
            raise

    def test_for_each_task_idle(self):
        self.assertTrue(
            any(task.pid.value_() == 0 for task in for_each_task(self.prog, idle=True))
        )

    def test_for_each_task_in_group(self):
        NUM_THREADS = 12
        condition = Condition()
        this_task = find_task(self.prog, os.getpid())

        def thread_func():
            with condition:
                condition.wait()

        try:
            threads = [Thread(target=thread_func) for _ in range(NUM_THREADS)]
            for thread in threads:
                thread.start()

            actual = {
                t.pid.value_()
                for t in for_each_task_in_group(this_task, include_self=False)
            }
            for thread in threads:
                self.assertIn(thread.native_id, actual)
            self.assertNotIn(os.getpid(), actual)
        finally:
            with condition:
                condition.notify_all()
            for thread in threads:
                thread.join()
