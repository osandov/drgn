# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestAscii(CrashCommandTestCase):
    def test_ascii(self):
        cmd = self.check_crash_command("ascii 62696c2f7273752f")
        self.assertRegex(cmd.stdout, r"(?m)^62696c2f7273752f: /usr/lib$")
        self.assertEqual(cmd.drgn_option.globals["bytestring"], b"/usr/lib")
