# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import signal
from threading import Condition, Thread
import time

from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import (
    cpu_curr,
    get_task_state,
    idle_task,
    loadavg,
    task_cpu,
    task_on_cpu,
    task_since_last_arrival_ns,
    task_state_to_char,
    task_thread_info,
    thread_group_leader,
)
from tests.linux_kernel import (
    LinuxKernelTestCase,
    fork_and_stop,
    proc_state,
    skip_unless_have_test_kmod,
    wait_until,
)


class TestSched(LinuxKernelTestCase):
    @skip_unless_have_test_kmod
    def test_task_thread_info(self):
        self.assertEqual(
            task_thread_info(self.prog["drgn_test_kthread"]),
            self.prog["drgn_test_kthread_info"],
        )

    def test_task_cpu(self):
        cpu = os.cpu_count() - 1
        with fork_and_stop(os.sched_setaffinity, 0, (cpu,)) as (pid, _):
            self.assertEqual(task_cpu(find_task(self.prog, pid)), cpu)

    def test_task_state_to_char(self):
        task = find_task(self.prog, os.getpid())
        self.assertEqual(task_state_to_char(task), "R")
        self.assertEqual(get_task_state(task), "R (running)")

        pid = os.fork()
        try:
            if pid == 0:
                try:
                    while True:
                        signal.pause()
                finally:
                    os._exit(1)

            task = find_task(self.prog, pid)

            wait_until(lambda: proc_state(pid) == "S")
            self.assertEqual(task_state_to_char(task), "S")
            self.assertEqual(get_task_state(task), "S (sleeping)")

            os.kill(pid, signal.SIGSTOP)
            wait_until(lambda: proc_state(pid) == "T")
            self.assertEqual(task_state_to_char(task), "T")

            os.kill(pid, signal.SIGKILL)
            wait_until(lambda: proc_state(pid) == "Z")
            self.assertEqual(task_state_to_char(task), "Z")
        finally:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)

    def test_task_on_cpu(self):
        task = find_task(self.prog, os.getpid())
        self.assertTrue(task_on_cpu(task))

        with fork_and_stop() as pid:
            task = find_task(self.prog, pid)
            self.assertFalse(task_on_cpu(task))

    def test_cpu_curr(self):
        task = find_task(self.prog, os.getpid())
        cpu = os.cpu_count() - 1
        old_affinity = os.sched_getaffinity(0)
        os.sched_setaffinity(0, (cpu,))
        try:
            self.assertEqual(cpu_curr(self.prog, cpu), task)
        finally:
            os.sched_setaffinity(0, old_affinity)

    def test_idle_task(self):
        for cpu in for_each_possible_cpu(self.prog):
            task = idle_task(self.prog, cpu)
            if cpu == 0:
                self.assertEqual(task, self.prog["init_task"].address_of_())
            else:
                self.assertEqual(task.comm.string_(), f"swapper/{cpu}".encode())

    def test_loadavg(self):
        values = loadavg(self.prog)
        self.assertEqual(len(values), 3)
        self.assertTrue(all(v >= 0.0 for v in values))

    def test_task_since_last_arrival_ns(self):
        with fork_and_stop() as pid:
            time.sleep(0.01)
            # Forcing the process to migrate also forces the rq clock to update
            # so we can get a reliable reading.
            affinity = os.sched_getaffinity(pid)
            if len(affinity) > 1:
                other_affinity = {affinity.pop()}
                os.sched_setaffinity(pid, affinity)
                os.sched_setaffinity(pid, other_affinity)
            task = find_task(self.prog, pid)
            self.assertGreaterEqual(task_since_last_arrival_ns(task), 10000000)

    def test_thread_group_leader(self):
        condition = Condition()

        def thread_func():
            with condition:
                condition.wait()

        thread = Thread(target=thread_func)
        try:
            thread.start()

            self.assertTrue(thread_group_leader(find_task(self.prog, os.getpid())))
            self.assertFalse(
                thread_group_leader(find_task(self.prog, thread.native_id))
            )
        finally:
            with condition:
                condition.notify_all()
            thread.join()
