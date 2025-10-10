# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
from drgn.commands import CommandArgumentError
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestVm(CrashCommandTestCase):
    def test_no_args(self):
        """Test case: no arguments"""
        cmd = self.check_crash_command("vm")

        # Verify 'tasks' list exists in globals
        self.assertIn("tasks", cmd.drgn_option.globals)

        # Verify 'tasks' is not empty
        tasks = cmd.drgn_option.globals["tasks"]
        self.assertGreater(len(tasks), 0, "Tasks list should not be empty")

        # Verify each task has expected attributes
        for task in tasks:
            self.assertTrue(hasattr(task, "mm"), "Task should have 'mm' attribute")
            self.assertTrue(hasattr(task, "pid"), "Task should have 'pid' attribute")
            self.assertTrue(hasattr(task, "comm"), "Task should have 'comm' attribute")

    def test_with_pid(self):
        """Test case: with PID argument"""
        init_pid = 1
        cmd = self.check_crash_command(f"vm {init_pid}")

        # Should display info for specified PID
        self.assertRegex(
            cmd.stdout,
            rf"PID:\s+{init_pid}\s+TASK:\s+[0-9a-fx]+\s+CPU:\s+\d+\s+COMMAND:",
        )

        # Verify drgn code generation
        # Check that the generated code uses 'find_task' with the correct PID
        self.assertIn("task = find_task(pid)", cmd.drgn_option.stdout)
        self.assertIn(f"pid = {init_pid}", cmd.drgn_option.stdout)

    def test_with_task_pointer(self):
        """Test case: with task pointer argument"""
        # Get address of init task
        init_task = self.prog["init_task"]
        task_addr = init_task.address_

        cmd = self.check_crash_command(f"vm {task_addr:#x}")

        # Should display info for specified task
        self.assertRegex(
            cmd.stdout,
            rf"PID:\s+\d+\s+TASK:\s+{task_addr:x}\s+CPU:\s+\d+\s+COMMAND:",
        )

        # Verify drgn code generation
        self.assertIn(
            f"address = {task_addr:#x}",
            cmd.drgn_option.stdout,
        )
        self.assertIn(
            'Object(prog, "struct task_struct *", address)',
            cmd.drgn_option.stdout,
        )

    def test_multiple_tasks(self):
        """Test case: multiple task arguments"""
        init_pid = 1
        init_task = self.prog["init_task"]
        task_addr = init_task.address_

        cmd = self.check_crash_command(f"vm {init_pid} {task_addr:#x}")

        # Should display info for both tasks
        self.assertIn(f"PID: {init_pid}", cmd.stdout)
        self.assertRegex(
            cmd.stdout,
            rf"TASK:\s+{task_addr:x}|TASK:\s+0x{task_addr:x}",
            "Expected task address not found in output",
        )

        # Verify drgn code generation includes both tasks
        self.assertIn(f"pid = {init_pid}", cmd.drgn_option.stdout)
        self.assertIn("task = find_task(pid)", cmd.drgn_option.stdout)
        self.assertIn(
            f"address = {task_addr:#x}",
            cmd.drgn_option.stdout,
        )
        self.assertIn(
            'Object(prog, "struct task_struct *", address)',
            cmd.drgn_option.stdout,
        )

    def test_kernel_thread(self):
        """Test case: kernel thread (no mm struct)"""
        cmd = self.check_crash_command("vm 2")

        # Kernel thread should show no memory mapping
        self.assertRegex(
            cmd.stdout, r"PID:\s+2\s+TASK:\s+[0-9a-fx]+\s+CPU:\s+\d+\s+COMMAND:"
        )
        self.assertIn("MM", cmd.stdout)
        self.assertIn("PGD", cmd.stdout)
        self.assertIn("0", cmd.stdout)  # Placeholder when no mm

    def test_vma_display(self):
        """Test case: VMA info display"""
        cmd = self.check_crash_command("vm 1")  # init process

        # Check VMA info format
        vma_pattern = r"[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+"
        self.assertRegex(cmd.stdout, vma_pattern, "VMA info format does not match")

        # Check common VMA types
        vma_types = ["\\[heap\\]", "\\[stack\\]", "\\[vdso\\]", "\\[anon\\]", "/"]
        vma_type_pattern = "|".join(vma_types)
        self.assertRegex(cmd.stdout, vma_type_pattern, "Common VMA types not found")

    def test_invalid_pid(self):
        """Test case: invalid PID argument"""
        with self.assertRaisesRegex(
            CommandArgumentError,
            r"argument pid\|task: invalid 'pid_or_task' value: 'invalid_pid'",
        ):
            self.check_crash_command("vm invalid_pid")

    def test_rss_and_total_vm_format(self):
        """Test case: RSS and TOTAL_VM format"""
        cmd = self.check_crash_command("vm 1")

        # Check memory usage format (should be number followed by 'k')
        rss_pattern = r"\d+k"
        total_vm_pattern = r"\d+k"

        self.assertRegex(cmd.stdout, rss_pattern)
        self.assertRegex(cmd.stdout, total_vm_pattern)

    def test_vm_flags_display(self):
        """Test case: VM flags display"""
        cmd = self.check_crash_command("vm 1")

        # VM flags should be in hexadecimal format
        flags_pattern = r"\b[0-9a-f]+\b"
        self.assertRegex(
            cmd.stdout, flags_pattern, "VM flags are not in hexadecimal format"
        )
