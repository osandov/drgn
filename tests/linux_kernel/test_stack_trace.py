# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import signal

from drgn import Object, Program, cast
from drgn.helpers.linux.pid import find_task
from tests import assertReprPrettyEqualsStr
from tests.linux_kernel import (
    LinuxKernelTestCase,
    fork_and_pause,
    proc_blocked,
    setenv,
    wait_until,
)


class TestStackTrace(LinuxKernelTestCase):
    def _assert_trace_paused(self, trace):
        for frame in trace:
            if "pause" in frame.name or "poll" in frame.name:
                return
        self.fail(f"pause frame not found in {str(trace)!r}")

    def test_by_task_struct(self):
        pid = fork_and_pause()
        wait_until(proc_blocked, pid)
        self._assert_trace_paused(self.prog.stack_trace(find_task(self.prog, pid)))
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)

    def _test_by_pid(self, orc):
        old_orc = int(os.environ.get("DRGN_PREFER_ORC_UNWINDER", "0")) != 0
        with setenv("DRGN_PREFER_ORC_UNWINDER", "1" if orc else "0"):
            if orc == old_orc:
                prog = self.prog
            else:
                prog = Program()
                prog.set_kernel()
                self._load_debug_info(prog)
            pid = fork_and_pause()
            wait_until(proc_blocked, pid)
            self._assert_trace_paused(prog.stack_trace(pid))
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)

    def test_by_pid_dwarf(self):
        self._test_by_pid(False)

    def test_by_pid_orc(self):
        self._test_by_pid(True)

    def test_local_variable(self):
        pid = fork_and_pause()
        wait_until(proc_blocked, pid)
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
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)

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
        pid = fork_and_pause()
        wait_until(proc_blocked, pid)
        trace = self.prog.stack_trace(pid)
        have_registers = False
        for frame in trace:
            for name, value in frame.registers().items():
                self.assertEqual(frame.register(name), value)
                have_registers = True
        self.assertTrue(have_registers)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)

    def test_prog(self):
        self.assertEqual(
            self.prog.stack_trace(Object(self.prog, "struct pt_regs", value={})).prog,
            self.prog,
        )

    def test_stack__repr_pretty_(self):
        pid = fork_and_pause()
        wait_until(proc_blocked, pid)
        trace = self.prog.stack_trace(pid)
        assertReprPrettyEqualsStr(trace)
        for frame in trace:
            assertReprPrettyEqualsStr(frame)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
