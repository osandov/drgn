# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import unittest

from drgn import Object, Program, cast
from drgn.helpers.linux.pid import find_task
from tests import assertReprPrettyEqualsStr
from tests.linux_kernel import (
    LinuxKernelTestCase,
    fork_and_sigwait,
    setenv,
    skip_unless_have_test_kmod,
)
from util import NORMALIZED_MACHINE_NAME


class TestStackTrace(LinuxKernelTestCase):
    def _test_drgn_test_kthread_trace(self, trace):
        for i, frame in enumerate(trace):
            if frame.name == "drgn_test_kthread_fn3":
                break
        else:
            self.fail("Couldn't find drgn_test_kthread_fn3 frame")
        self.assertEqual(trace[i + 1].name, "drgn_test_kthread_fn2")
        self.assertEqual(trace[i + 2].name, "drgn_test_kthread_fn")

    @skip_unless_have_test_kmod
    def test_by_task_struct(self):
        self._test_drgn_test_kthread_trace(
            self.prog.stack_trace(self.prog["drgn_test_kthread"])
        )

    def _test_by_pid(self, orc):
        old_orc = int(os.environ.get("DRGN_PREFER_ORC_UNWINDER", "0")) != 0
        with setenv("DRGN_PREFER_ORC_UNWINDER", "1" if orc else "0"):
            if orc == old_orc:
                prog = self.prog
            else:
                prog = Program()
                prog.set_kernel()
                self._load_debug_info(prog)
            self._test_drgn_test_kthread_trace(
                self.prog.stack_trace(self.prog["drgn_test_kthread"].pid)
            )

    @skip_unless_have_test_kmod
    def test_by_pid_dwarf(self):
        self._test_by_pid(False)

    @unittest.skipUnless(
        NORMALIZED_MACHINE_NAME == "x86_64",
        f"{NORMALIZED_MACHINE_NAME} does not use ORC",
    )
    @skip_unless_have_test_kmod
    def test_by_pid_orc(self):
        self._test_by_pid(True)

    @skip_unless_have_test_kmod
    def test_local_variable(self):
        for frame in self.prog.stack_trace(self.prog["drgn_test_kthread"]):
            if frame.name == "drgn_test_kthread_fn3":
                break
        else:
            self.fail("Couldn't find drgn_test_kthread_fn3 frame")
        self.assertEqual(frame["a"], 1)
        self.assertEqual(frame["b"], 2)
        self.assertEqual(frame["c"], 3)

    @skip_unless_have_test_kmod
    def test_locals(self):
        task = self.prog["drgn_test_kthread"]
        stack_trace = self.prog.stack_trace(task)
        for frame in stack_trace:
            if frame.name == "drgn_test_kthread_fn3":
                self.assertSetEqual(set(frame.locals()), {"a", "b", "c"})
                break
        else:
            self.fail("Couldn't find drgn_test_kthread_fn3 frame")

    def test_pt_regs(self):
        # This won't unwind anything useful, but at least make sure it accepts
        # a struct pt_regs.
        self.prog.stack_trace(Object(self.prog, "struct pt_regs", value={}))

        # Likewise, this is nonsense, but we should also accept a struct
        # pt_regs *.
        task = find_task(self.prog, os.getpid())
        self.prog.stack_trace(cast("struct pt_regs *", task.stack))

    def test_registers(self):
        # Smoke test that we get at least one register and that
        # StackFrame.registers() agrees with StackFrame.register().
        with fork_and_sigwait() as pid:
            trace = self.prog.stack_trace(pid)
            have_registers = False
            for frame in trace:
                for name, value in frame.registers().items():
                    self.assertEqual(frame.register(name), value)
                    have_registers = True
            self.assertTrue(have_registers)

    def test_prog(self):
        self.assertEqual(
            self.prog.stack_trace(Object(self.prog, "struct pt_regs", value={})).prog,
            self.prog,
        )

    def test_stack__repr_pretty_(self):
        with fork_and_sigwait() as pid:
            trace = self.prog.stack_trace(pid)
            assertReprPrettyEqualsStr(trace)
            for frame in trace:
                assertReprPrettyEqualsStr(frame)
