# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestRunq(CrashCommandTestCase):
    def test_no_options(self):
        cmd = self.run_crash_command("runq")
        self.assertIn("RT PRIO_ARRAY", cmd.stdout)

    def test_show_timestamps(self):
        cmd = self.run_crash_command("runq -t")
        self.assertIn("RQ_TIMESTAMP", cmd.stdout)

    def test_show_lag(self):
        cmd = self.run_crash_command("runq -T")
        self.assertIn("secs", cmd.stdout)

    def test_pretty_runtime(self):
        cmd = self.run_crash_command("runq -m")
        self.assertIn("RUNTIME", cmd.stdout)

    def test_group(self):
        cmd = self.run_crash_command("runq -g")
        self.assertIn("ROOT_TASK_GROUP", cmd.stdout)

    def test_cpus(self):
        cmd = self.run_crash_command("runq -c 0")
        self.assertIn("CPU 0", cmd.stdout)
