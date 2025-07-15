# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
import time

from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.runq import task_lastrun2now
from tests.linux_kernel import LinuxKernelTestCase, fork_and_stop


class TestRunq(LinuxKernelTestCase):
    def sleep_10ms():
        time.sleep(0.01)

    def test_task_lastrun2now(self):
        with fork_and_stop(self.sleep_10ms) as pid:
            task = find_task(self.prog, pid)
            assert task_lastrun2now(task) >= 0.01 * 1e9
