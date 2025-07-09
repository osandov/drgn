# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import gzip

from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestSys(CrashCommandTestCase):
    def test_sys(self):
        cmd = self.check_crash_command("sys")
        for field in (
            "KERNEL",
            "DUMPFILE",
            "CPUS",
            "DATE",
            "UPTIME",
            "LOAD AVERAGE",
            "TASKS",
            "NODENAME",
            "RELEASE",
            "VERSION",
            "MACHINE",
            "MEMORY",
        ):
            self.assertRegex(cmd.stdout, rf"(?m)^\s*{field}:")

        for variable in (
            "kernel",
            "dumpfile",
            "cpus",
            "offline_cpus",
            "timestamp",
            "uptime_",
            "load_average",
            "num_tasks",
            "nodename",
            "release",
            "version",
            "machine",
            "memory",
        ):
            self.assertIn(variable, cmd.drgn_option.globals)

    def test_sys_config(self):
        try:
            with gzip.open("/proc/config.gz", "rt") as f:
                expected = f.read()
        except FileNotFoundError:
            self.skipTest("kernel not built with CONFIG_IKCONFIG_PROC")

        cmd = self.check_crash_command("sys config")
        self.assertEqual(cmd.stdout, expected)
        self.assertIn("kconfig", cmd.drgn_option.globals)
