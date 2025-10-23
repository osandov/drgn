# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestWhatis(CrashCommandTestCase):
    def test_struct_explicit(self):
        cmd = self.run_crash_command("whatis 'struct list_head'")
        self.assertIn("struct list_head {", cmd.stdout)
        self.assertRegex(cmd.stdout, r"(?m)^SIZE: [0-9]+$")

    def test_struct_implicit(self):
        cmd = self.run_crash_command("whatis list_head")
        self.assertIn("struct list_head {", cmd.stdout)
        self.assertRegex(cmd.stdout, r"(?m)^SIZE: [0-9]+$")

    def test_typedef(self):
        cmd = self.run_crash_command("whatis atomic_t")
        self.assertIn("atomic_t", cmd.stdout)
        self.assertRegex(cmd.stdout, r"(?m)^SIZE: [0-9]+$")

    def test_enum(self):
        cmd = self.run_crash_command("whatis pid_type")
        self.assertIn("enum pid_type", cmd.stdout)
        self.assertRegex(cmd.stdout, r"(?m)^SIZE: [0-9]+$")

    def test_function_symbol(self):
        cmd = self.run_crash_command("whatis schedule")
        self.assertRegex(cmd.stdout, r"(?m)\bschedule\s*\(.*\);")

    def test_data_symbol(self):
        cmd = self.run_crash_command("whatis init_task")
        self.assertIn("init_task;", cmd.stdout)
        self.assertIn("struct task_struct", cmd.stdout)
