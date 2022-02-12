# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from drgn import ProgramFlags
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel.vmcore import LinuxVMCoreTestCase


class TestVMCore(LinuxVMCoreTestCase):
    def test_program_flags(self):
        self.assertFalse(self.prog.flags & ProgramFlags.IS_LIVE)
        self.assertTrue(self.prog.flags & ProgramFlags.IS_LINUX_KERNEL)

    def test_threads(self):
        tids = [thread.tid for thread in self.prog.threads()]
        self.assertIn(1, tids)
        self.assertIn(self.prog.crashed_thread().tid, tids)

    def test_thread(self):
        thread = self.prog.thread(1)
        self.assertEqual(thread.tid, 1)
        self.assertEqual(thread.object, find_task(self.prog, 1))

        crashed_thread_tid = self.prog.crashed_thread().tid
        self.assertEqual(self.prog.thread(crashed_thread_tid).tid, crashed_thread_tid)

    def test_thread_not_found(self):
        tids = {thread.tid for thread in self.prog.threads()}
        tid = 1
        while tid in tids:
            tid += 1
        self.assertRaises(LookupError, self.prog.thread, tid)

    def test_main_thread(self):
        self.assertRaisesRegex(
            ValueError,
            "main thread is not defined for the Linux kernel",
            self.prog.main_thread,
        )

    def test_crashed_thread(self):
        crashed_thread = self.prog.crashed_thread()
        self.assertGreater(crashed_thread.tid, 0)
