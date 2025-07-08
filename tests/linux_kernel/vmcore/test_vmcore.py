# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import unittest

from _drgn_util.platform import NORMALIZED_MACHINE_NAME
from drgn import Object, Program, ProgramFlags
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.timekeeping import ktime_get_real_seconds
from tests import TestCase
from tests.linux_kernel.vmcore import VMCORE_PATH, LinuxVMCoreTestCase


class TestVMCore(LinuxVMCoreTestCase):
    # When CPU 0 panics on s390x, the kernel switches to a different stack that
    # we don't know how to unwind through. This is a bug. For now,
    # vmtest.enter_kdump tries to avoid this so we can get some test coverage,
    # and we skip the tests otherwise.
    def _skip_if_cpu0_on_s390x(self):
        if NORMALIZED_MACHINE_NAME == "s390x" and self.prog["panic_cpu"].counter == 0:
            self.skipTest("drgn can't unwind s390x panic stack on CPU 0")

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
        # This assumes that we crashed from vmtest.enter_kdump. I don't know
        # why anyone would run these tests from kdump otherwise.
        self.assertEqual(crashed_thread.object.comm.string_(), b"selfdestruct")

    def _test_crashed_thread_stack_trace(self, trace):
        # This assumes that we crashed using the drgn_test kmod. Note that on
        # supported architectures, drgn_test_crash_func() is called from an IRQ
        # handler that interrupts drgn_test_crash_store().
        trace_iter = iter(trace)
        for frame in trace_iter:
            if frame.name == "drgn_test_crash_func":
                break
        else:
            self.fail("drgn_test_crash_func frame not found")

        for frame in trace_iter:
            if frame.name == "drgn_test_crash_store":
                break
        else:
            self.fail(
                "drgn_test_crash_store frame not found below drgn_test_crash_func"
            )

    def test_crashed_thread_stack_trace(self):
        self._skip_if_cpu0_on_s390x()
        self._test_crashed_thread_stack_trace(self.prog.crashed_thread().stack_trace())

    def test_crashed_thread_stack_trace_by_tid(self):
        self._skip_if_cpu0_on_s390x()
        self._test_crashed_thread_stack_trace(
            self.prog.stack_trace(self.prog.crashed_thread().tid)
        )

    def test_crashed_thread_stack_trace_by_task_struct(self):
        self._skip_if_cpu0_on_s390x()
        self._test_crashed_thread_stack_trace(
            self.prog.stack_trace(self.prog.crashed_thread().object)
        )


@unittest.skipUnless(VMCORE_PATH.exists(), "not running in kdump")
class TestVMCoreNoDebugInfo(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.prog = Program()
        cls.prog.set_core_dump(VMCORE_PATH)

    @classmethod
    def tearDownClass(cls):
        del cls.prog

    def test_ktime_get_real_seconds(self):
        self.assertIsInstance(ktime_get_real_seconds(self.prog), Object)
