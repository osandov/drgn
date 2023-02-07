# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import signal

from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import idle_task, loadavg, task_cpu, task_state_to_char
from tests.linux_kernel import (
    LinuxKernelTestCase,
    fork_and_sigwait,
    proc_state,
    smp_enabled,
    wait_until,
)


class TestSched(LinuxKernelTestCase):
    def test_task_cpu(self):
        cpu = os.cpu_count() - 1
        with fork_and_sigwait(lambda: os.sched_setaffinity(0, (cpu,))) as pid:
            self.assertEqual(task_cpu(find_task(self.prog, pid)), cpu)

    def test_task_state_to_char(self):
        task = find_task(self.prog, os.getpid())
        self.assertEqual(task_state_to_char(task), "R")

        with fork_and_sigwait() as pid:
            task = find_task(self.prog, pid)

            wait_until(lambda: proc_state(pid) == "S")
            self.assertEqual(task_state_to_char(task), "S")

            os.kill(pid, signal.SIGSTOP)
            wait_until(lambda: proc_state(pid) == "T")
            self.assertEqual(task_state_to_char(task), "T")

            os.kill(pid, signal.SIGKILL)
            wait_until(lambda: proc_state(pid) == "Z")
            self.assertEqual(task_state_to_char(task), "Z")

    def test_idle_task(self):
        if smp_enabled():
            for cpu in for_each_possible_cpu(self.prog):
                self.assertEqual(
                    idle_task(self.prog, cpu).comm.string_(), f"swapper/{cpu}".encode()
                )
        else:
            self.assertEqual(idle_task(self.prog, 0).comm.string_(), b"swapper")

    def test_loadavg(self):
        values = loadavg(self.prog)
        self.assertEqual(len(values), 3)
        self.assertTrue(all(v >= 0.0 for v in values))
