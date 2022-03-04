# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import signal

from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import idle_task, task_state_to_char
from tests.linux_kernel import (
    LinuxKernelTestCase,
    fork_and_pause,
    proc_state,
    smp_enabled,
    wait_until,
)


class TestSched(LinuxKernelTestCase):
    def test_task_state_to_char(self):
        task = find_task(self.prog, os.getpid())
        self.assertEqual(task_state_to_char(task), "R")

        pid = fork_and_pause()
        task = find_task(self.prog, pid)

        wait_until(lambda: proc_state(pid) == "S")
        self.assertEqual(task_state_to_char(task), "S")

        os.kill(pid, signal.SIGSTOP)
        wait_until(lambda: proc_state(pid) == "T")
        self.assertEqual(task_state_to_char(task), "T")

        os.kill(pid, signal.SIGKILL)
        wait_until(lambda: proc_state(pid) == "Z")
        self.assertEqual(task_state_to_char(task), "Z")

        os.waitpid(pid, 0)

    def test_idle_task(self):
        if smp_enabled():
            for cpu in for_each_possible_cpu(self.prog):
                self.assertEqual(
                    idle_task(self.prog, cpu).comm.string_(), f"swapper/{cpu}".encode()
                )
        else:
            self.assertEqual(idle_task(self.prog, 0).comm.string_(), b"swapper")
