# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import unittest

from drgn import Object, Program, reinterpret
from tests import assertReprPrettyEqualsStr, modifyenv
from tests.linux_kernel import (
    LinuxKernelTestCase,
    fork_and_stop,
    skip_unless_have_stack_tracing,
    skip_unless_have_test_kmod,
)
from util import NORMALIZED_MACHINE_NAME


@skip_unless_have_stack_tracing
class LinuxKernelStackTraceTestCase(LinuxKernelTestCase):
    def _test_drgn_test_kthread_trace(self, trace):
        for i, frame in enumerate(trace):
            if frame.name == "drgn_test_kthread_fn3":
                break
        else:
            self.fail("Couldn't find drgn_test_kthread_fn3 frame")
        self.assertEqual(trace[i + 1].name, "drgn_test_kthread_fn2")
        self.assertEqual(trace[i + 2].name, "drgn_test_kthread_fn")


class TestStackTrace(LinuxKernelStackTraceTestCase):
    @skip_unless_have_test_kmod
    def test_by_task_struct(self):
        self._test_drgn_test_kthread_trace(
            self.prog.stack_trace(self.prog["drgn_test_kthread"])
        )

    def _test_by_pid(self, orc):
        old_orc = int(os.environ.get("DRGN_PREFER_ORC_UNWINDER", "0")) != 0
        with modifyenv({"DRGN_PREFER_ORC_UNWINDER": "1" if orc else "0"}):
            if orc == old_orc:
                prog = self.prog
            else:
                prog = Program()
                prog.set_kernel()
                self._load_debug_info(prog)
            self._test_drgn_test_kthread_trace(
                prog.stack_trace(prog["drgn_test_kthread"].pid)
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
    def test_by_pt_regs(self):
        pt_regs = self.prog["drgn_test_kthread_pt_regs"]
        self._test_drgn_test_kthread_trace(self.prog.stack_trace(pt_regs))
        self._test_drgn_test_kthread_trace(self.prog.stack_trace(pt_regs.address_of_()))

    @skip_unless_have_test_kmod
    def test_stack_trace_from_pcs(self):
        if not self.prog["drgn_test_have_stacktrace"]:
            self.skipTest("kernel was not built with CONFIG_STACKTRACE")
        entries = self.prog["drgn_test_stack_entries"]
        self._test_drgn_test_kthread_trace(
            self.prog.stack_trace_from_pcs(
                reinterpret(
                    self.prog.array_type(
                        entries.type_.type,
                        self.prog["drgn_test_num_stack_entries"].value_(),
                    ),
                    entries,
                ).value_()
            )
        )

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

    def test_registers(self):
        # Smoke test that we get at least one register and that
        # StackFrame.registers() agrees with StackFrame.register().
        with fork_and_stop() as pid:
            trace = self.prog.stack_trace(pid)
            have_registers = False
            for frame in trace:
                for name, value in frame.registers().items():
                    self.assertEqual(frame.register(name), value)
                    have_registers = True
            self.assertTrue(have_registers)

    def test_sp(self):
        # Smoke test that the stack pointer register shows up in
        # StackFrame.registers().
        with fork_and_stop() as pid:
            trace = self.prog.stack_trace(pid)
            self.assertIn(trace[0].sp, trace[0].registers().values())

    def test_prog(self):
        self.assertEqual(
            self.prog.stack_trace(Object(self.prog, "struct pt_regs", value={})).prog,
            self.prog,
        )

    def test_stack__repr_pretty_(self):
        with fork_and_stop() as pid:
            trace = self.prog.stack_trace(pid)
            assertReprPrettyEqualsStr(trace)
            for frame in trace:
                assertReprPrettyEqualsStr(frame)
