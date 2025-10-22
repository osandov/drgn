# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

from tests.linux_kernel import fork_and_stop
from tests.linux_kernel.crash_commands import CrashCommandTestCase


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

    def test_cpu(self):
        with self.assertRaises(ValueError) as exc:
            self.check_crash_command("bt -c 0")
        self.assertIn("cannot unwind stack of running task", str(exc.exception))
