# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

from tests.linux_kernel import (
    fork_and_stop,
    skip_unless_have_stack_tracing,
    skip_unless_have_test_kmod,
)
from tests.linux_kernel.crash_commands import CrashCommandTestCase


@skip_unless_have_stack_tracing
class TestBt(CrashCommandTestCase):
    def test_no_options(self):
        with fork_and_stop() as pid:
            self.run_crash_command(f"set {pid}")
            cmd = self.check_crash_command("bt")
            self.assertIn(f"PID: {pid}", cmd.stdout)
            self.assertRegex(
                cmd.stdout, r"(?m).*^ *#\d+ \[[0-9a-f]+\] \w+ at [0-9a-f]+$"
            )

    def test_pid(self):
        with fork_and_stop() as pid:
            cmd = self.check_crash_command(f"bt {pid}")
            self.assertIn(f"PID: {pid}", cmd.stdout)
            self.assertRegex(
                cmd.stdout, r"(?m).*^ *#\d+ \[[0-9a-f]+\] \w+ at [0-9a-f]+$"
            )

    def test_multiple_pids(self):
        with fork_and_stop() as pid1, fork_and_stop() as pid2:
            cmd = self.check_crash_command(f"bt {pid1} {pid2}")
            self.assertIn(f"PID: {pid1}", cmd.stdout)
            self.assertIn(f"PID: {pid2}", cmd.stdout)

    @skip_unless_have_test_kmod
    def test_task_struct(self):
        task = self.prog["drgn_test_kthread"]
        cmd = self.check_crash_command(f"bt 0x{task.value_():x}")
        self.assertIn(f"PID: {task.pid.value_()}", cmd.stdout)
        self.assertIn(f"TASK: {task.value_():x}", cmd.stdout)
        self.assertIn("drgn_test_kthread_fn", cmd.stdout)
        self.assertIn("drgn_test_kthread_fn2", cmd.stdout)
        self.assertIn("drgn_test_kthread_fn3", cmd.stdout)
        self.assertIn("[drgn_test]", cmd.stdout)

    @skip_unless_have_test_kmod
    def test_frame_data(self):
        task = self.prog["drgn_test_kthread"]
        cmd = self.check_crash_command(f"bt -f 0x{task.value_():x}")
        self.assertRegex(cmd.stdout, "(?m)^    [0-9a-f]+:  [0-9a-f]+")

    @skip_unless_have_test_kmod
    def test_frame_data_slab(self):
        task = self.prog["drgn_test_kthread"]
        cmd = self.check_crash_command(f"bt -F 0x{task.value_():x}")
        # We know we will find return address symbols on the stack:
        self.assertIn("drgn_test_kthread_fn+", cmd.stdout)
        self.assertIn("drgn_test_kthread_fn2+", cmd.stdout)
        self.assertIn("drgn_test_kthread_fn3+", cmd.stdout)
        # We also know we will find the drgn small slab object, but whether it
        # can be identified depends on kernel configuration (non-SLOB)
        if self.prog["drgn_test_slob"]:
            self.assertIn("[unknown slab object]", cmd.stdout)
        else:
            self.assertIn("[drgn_test_small]", cmd.stdout)

    @skip_unless_have_test_kmod
    def test_frame_data_verbose(self):
        task = self.prog["drgn_test_kthread"]
        cmd = self.check_crash_command(f"bt -FF 0x{task.value_():x}")
        # We know we will find return address symbols on the stack:
        self.assertIn("drgn_test_kthread_fn+", cmd.stdout)
        self.assertIn("drgn_test_kthread_fn2+", cmd.stdout)
        self.assertIn("drgn_test_kthread_fn3+", cmd.stdout)
        # We also know we will find the drgn small slab object, but whether it
        # can be identified depends on kernel configuration (non-SLOB)
        if self.prog["drgn_test_slob"]:
            self.assertRegex(cmd.stdout, r"\[[0-9a-f]+:unknown slab object\]")
        else:
            self.assertRegex(cmd.stdout, r"\[[0-9a-f]+:drgn_test_small\]")

    @skip_unless_have_test_kmod
    def test_line_numbers(self):
        task = self.prog["drgn_test_kthread"]
        cmd = self.check_crash_command(f"bt -l 0x{task.value_():x}")
        self.assertIn("drgn_test.c", cmd.stdout)

    @skip_unless_have_test_kmod
    def test_variables(self):
        task = self.prog["drgn_test_kthread"]
        cmd = self.check_crash_command(f"bt -V 0x{task.value_():x}")
        self.assertIn("a = (volatile int)1", cmd.stdout)
