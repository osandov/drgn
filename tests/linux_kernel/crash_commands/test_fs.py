# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import CLONE_NEWNS, fork_and_stop, unshare
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestMount(CrashCommandTestCase):
    def test_no_options(self):
        self.run_crash_command("set 1")
        cmd = self.check_crash_command("mount")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+.*proc")
        self.assertIn("for_each_mount()", cmd.drgn_option.stdout)
        self.assertNotIn("mnt_ns", cmd.drgn_option.globals)

    def test_no_options_in_namespace(self):
        with fork_and_stop(unshare, CLONE_NEWNS) as (pid, _):
            self.run_crash_command(f"set {pid}")
            cmd = self.check_crash_command("mount")
            self.assertIn("for_each_mount(mnt_ns)", cmd.drgn_option.stdout)
            self.assertEqual(
                cmd.drgn_option.globals["mnt_ns"],
                find_task(self.prog, pid).nsproxy.mnt_ns,
            )

    def test_n_pid(self):
        cmd = self.check_crash_command("mount -n 1")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+.*proc")
        self.assertIn("for_each_mount(mnt_ns)", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["mnt_ns"], find_task(self.prog, 1).nsproxy.mnt_ns
        )

    def test_n_task(self):
        task = self.prog["init_task"].address_of_()
        cmd = self.check_crash_command(f"mount -n {hex(task)}")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+.*proc")
        self.assertIn("for_each_mount(mnt_ns)", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["mnt_ns"], self.prog["init_task"].nsproxy.mnt_ns
        )
