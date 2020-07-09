# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import os
import re
import signal
import unittest

from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import task_state_to_char
from tests.helpers.linux import (
    LinuxHelperTestCase,
    fork_and_pause,
    proc_state,
    wait_until,
)


def is_power_of_two(n):
    return n != 0 and (n & (n - 1)) == 0


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

    @unittest.skip("GCC 10 breaks THREAD_SIZE object finder")
    def test_thread_size(self):
        # As far as I can tell, there's no way to query this value from
        # userspace, so at least sanity check that it's a power-of-two multiple
        # of the page size and that we can read the entire stack.
        thread_size = self.prog["THREAD_SIZE"].value_()
        page_size = self.prog["PAGE_SIZE"].value_()
        self.assertEqual(thread_size % page_size, 0)
        self.assertTrue(is_power_of_two(thread_size // page_size))

        task = find_task(self.prog, os.getpid())
        self.prog.read(task.stack, thread_size)
