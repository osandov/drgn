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
    def _assert_trace_in_sigwait(self, trace):
        for frame in trace:
            if frame.name and "sigtimedwait" in frame.name:
                return
        self.fail(f"sigwait frame not found in {str(trace)!r}")

    def test_by_task_struct(self):
        with fork_and_sigwait() as pid:
            self._assert_trace_in_sigwait(
                self.prog.stack_trace(find_task(self.prog, pid))
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
            with fork_and_sigwait() as pid:
                self._assert_trace_in_sigwait(prog.stack_trace(pid))

    def test_by_pid_dwarf(self):
        self._test_by_pid(False)

    @unittest.skipUnless(
        NORMALIZED_MACHINE_NAME == "x86_64",
        f"{NORMALIZED_MACHINE_NAME} does not use ORC",
    )
    def test_by_pid_orc(self):
        self._test_by_pid(True)

    def test_local_variable(self):
        with fork_and_sigwait() as pid:
            for frame in self.prog.stack_trace(pid):
                if frame.name in ("context_switch", "__schedule"):
                    try:
                        prev = frame["prev"]
                    except KeyError:
                        continue
                    if not prev.absent_:
                        self.assertEqual(prev.pid, pid)
                        break
            else:
                self.skipTest("prev not found in context_switch or __schedule")

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

    @skip_unless_have_test_kmod
    def test_stack_locals(self):
        task = self.prog["drgn_kthread"]
        stack_trace = self.prog.stack_trace(task)
        for frame in stack_trace:
            if frame.symbol().name == "drgn_kthread_fn":
                self.assertSetEqual(
                    {"arg", "a", "b", "c"},
                    set(frame.locals()),
                )
                break
        else:
            self.fail("Couldn't find drgn_kthread_fn frame")
