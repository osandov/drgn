# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import signal

from drgn import Object, Program, cast
from drgn.helpers.linux.pid import find_task
from tests.helpers.linux import (
    LinuxHelperTestCase,
    fork_and_pause,
    proc_state,
    setenv,
    wait_until,
)


class TestStackTrace(LinuxHelperTestCase):
    def test_by_task_struct(self):
        pid = fork_and_pause()
        wait_until(lambda: proc_state(pid) == "S")
        self.assertIn("pause", str(self.prog.stack_trace(find_task(self.prog, pid))))
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
                prog.load_default_debug_info()
            pid = fork_and_pause()
            wait_until(lambda: proc_state(pid) == "S")
            self.assertIn("pause", str(prog.stack_trace(pid)))
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)

    def test_by_pid_dwarf(self):
        self._test_by_pid(False)

    def test_by_pid_orc(self):
        self._test_by_pid(True)

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
        wait_until(lambda: proc_state(pid) == "S")
        trace = self.prog.stack_trace(pid)
        have_registers = False
        for frame in trace:
            for name, value in frame.registers().items():
                self.assertEqual(frame.register(name), value)
                have_registers = True
        self.assertTrue(have_registers)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
