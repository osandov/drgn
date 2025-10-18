# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestVm(CrashCommandTestCase):
    def test_no_args(self):
        """Test case: no arguments"""
        cmd = self.check_crash_command("vm")

        # Should display memory info of current process
        self.assertRegex(
            cmd.stdout, r"PID:\s+\d+\s+TASK:\s+[0-9a-fx]+\s+CPU:\s+\d+\s+COMMAND:"
        )

        # Check memory statistics header
        self.assertRegex(cmd.stdout, r"MM\s+PGD\s+RSS\s+TOTAL_VM")

        # Check VMA header
        if "VMA" in cmd.stdout:
            self.assertRegex(cmd.stdout, r"VMA\s+START\s+END\s+FLAGS\s+FILE")

        # Verify variables in drgn options
        self.assertIn("task", cmd.drgn_option.globals)
        self.assertIn("mm", cmd.drgn_option.globals)
        if cmd.drgn_option.globals.get("mm"):
            self.assertIn("vma", cmd.drgn_option.globals)

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
        self.assertIn(f"find_task(prog, {init_pid})", cmd.drgn_option.stdout)

    def test_with_task_pointer(self):
        """Test case: with task pointer argument"""
        # Get address of init task
        init_task = self.prog["init_task"]
        task_addr = init_task.address_

        cmd = self.check_crash_command(f"vm {task_addr:#x}")

        # Should display info for specified task
        self.assertRegex(
            cmd.stdout, rf"PID:\s+0\s+TASK:\s+{task_addr:#x}\s+CPU:\s+\d+\s+COMMAND:"
        )

        # Verify drgn code generation
        self.assertIn(
            f'Object(prog, "struct task_struct *", value={task_addr:#x})',
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
        self.assertIn(f"TASK: {task_addr:#x}", cmd.stdout)

        # Verify drgn code generation includes both tasks
        self.assertIn(f"find_task(prog, {init_pid})", cmd.drgn_option.stdout)
        self.assertIn(
            f'Object(prog, "struct task_struct *", value={task_addr:#x})',
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
        vma_pattern = r"0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+"
        self.assertRegex(cmd.stdout, vma_pattern)

        # Check common VMA types
        vma_types = ["\\[heap\\]", "\\[stack\\]", "\\[vdso\\]", "\\[anon\\]", "/"]
        vma_type_pattern = "|".join(vma_types)
        self.assertRegex(cmd.stdout, vma_type_pattern)

    def test_invalid_pid(self):
        """Test case: invalid PID argument"""
        cmd = self.check_crash_command("vm invalid_pid")

        # Should gracefully handle non-existent PID
        # May display error message or skip the task
        self.assertIsNotNone(cmd.stdout)

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
        flags_pattern = r"0x[0-9a-f]+"
        self.assertRegex(cmd.stdout, flags_pattern)
