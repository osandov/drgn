# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import signal

from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import task_state_to_char
from tests.helpers.linux import (
    LinuxHelperTestCase,
    fork_and_pause,
    proc_state,
    wait_until,
)


class TestSched(LinuxHelperTestCase):
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
