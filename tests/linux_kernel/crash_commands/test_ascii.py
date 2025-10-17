# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.commands import CommandArgumentError
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestAscii(CrashCommandTestCase):
    def test_ascii(self):
        cmd = self.check_crash_command("ascii 62696c2f7273752f")
        self.assertRegex(cmd.stdout, r"(?m)^62696c2f7273752f: /usr/lib$")
        self.assertEqual(cmd.drgn_option.globals["bytestring"], b"/usr/lib")

    def test_too_large(self):
        command = "ascii fedcba9876543210f"
        self.assertRaisesRegex(
            CommandArgumentError, "too large", self.run_crash_command, command
        )
        self.assertRaisesRegex(
            ValueError, "too large", self.run_crash_command_drgn_option, command
        )
