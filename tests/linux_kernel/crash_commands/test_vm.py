# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os

from drgn import Object
from drgn.helpers.linux.mm import TaskRss
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestVm(CrashCommandTestCase):
    def _test_common(self, cmd):
        self.assertRegex(
            cmd.stdout,
            r"\bMM\s+PGD\s+RSS\s+TOTAL_VM(?:\s+[0-9a-f]+){2}(?:\s+[0-9]+k){2}\b",
        )
        self.assertRegex(
            cmd.stdout, r"\bVMA\s+START\s+END\s+FLAGS\s+FILE(?:\s+[0-9a-f]+){4}"
        )
        self.assertRegex(cmd.stdout, r"\bVMA(?s:.)*/")  # Check for any file path.

    def _test_drgn_option_common(self, cmd):
        for variable in (
            "pid",
            "task",
            "command",
            "mm",
            "pgd",
            "vma",
            "start",
            "end",
            "flags",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIsInstance(cmd.drgn_option.globals["cpu"], int)
        self.assertIsInstance(cmd.drgn_option.globals["rss"], TaskRss)
        self.assertIsInstance(cmd.drgn_option.globals["file"], str)

    def test_no_args(self):
        self.run_crash_command("set -p")

        cmd = self.check_crash_command("vm")
        self.assertIn(f"PID: {os.getpid()}", cmd.stdout)
        self._test_common(cmd)

        self._test_drgn_option_common(cmd)

    def test_tasks(self):
        cmd = self.check_crash_command(f"vm 1 {os.getpid()}")
        foreach_cmd = self.check_crash_command(
            f"foreach 1 {os.getpid()} vm", mode="capture"
        )

        for c in (cmd, foreach_cmd):
            self.assertIn("PID: 1", c.stdout)
            self.assertIn(f"PID: {os.getpid()}", c.stdout)
            self._test_common(c)

        self._test_drgn_option_common(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_kernel_thread(self):
        cmd = self.check_crash_command("vm 2")

        self.assertRegex(cmd.stdout, r"\bMM\s+PGD\s+RSS\s+TOTAL_VM\s+0\s+0\s+0k\s+0k\b")
        self.assertNotIn("VMA", cmd.stdout)

        self.assertFalse(cmd.drgn_option.globals["mm"])
