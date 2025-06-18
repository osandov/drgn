# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestMount(CrashCommandTestCase):
    def test_no_options(self):
        cmd = self.run_crash_command("mount")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+.*proc")

    def test_drgn(self):
        cmd = self.run_crash_command("mount --drgn")
        self.assertIn("for_each_mount", cmd.stdout)

    def test_n_pid(self):
        cmd = self.run_crash_command("mount -n 1")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+.*proc")

    def test_drgn_n_pid(self):
        cmd = self.run_crash_command("mount -n 1 --drgn")
        self.assertIn("find_task", cmd.stdout)

    def test_n_task(self):
        task = self.prog["init_task"].address_of_()
        cmd = self.run_crash_command(f"mount -n {hex(task)}")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+.*proc")

    def test_drgn_n_task(self):
        cmd = self.run_crash_command("mount -n 0x0 --drgn")
        self.assertIn("Object", cmd.stdout)
