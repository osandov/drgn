# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import shlex

from tests.linux_kernel import skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase


@skip_unless_have_test_kmod
class TestMod(CrashCommandTestCase):
    def test_no_options(self):
        cmd = self.check_crash_command("mod")
        self.assertIn("drgn_test", cmd.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["struct_module"].type_.type_name(),
            "struct module *",
        )

    def test_taints(self):
        cmd = self.check_crash_command("mod -t")
        self.assertRegex(cmd.stdout, "drgn_test.*O")
        self.assertIsInstance(cmd.drgn_option.globals["taints"], str)

    def test_load(self):
        cmd = self.check_crash_command("mod -s drgn_test")
        self.assertIn("drgn_test", cmd.stdout)
        self.assertIn("prog.load_module_debug_info", cmd.drgn_option.stdout)

    def test_load_path(self):
        cmd = self.check_crash_command(
            f"mod -s drgn_test {shlex.quote(os.getenv('DRGN_TEST_KMOD'))}"
        )
        self.assertIn("drgn_test", cmd.stdout)
        self.assertIn("module.try_file", cmd.drgn_option.stdout)

    def test_load_all(self):
        cmd = self.check_crash_command("mod -S")
        self.assertIn("drgn_test", cmd.stdout)
        self.assertIn("prog.load_default_debug_info", cmd.drgn_option.stdout)

    def test_load_all_directory(self):
        cmd = self.check_crash_command("mod -S /dev/null")
        self.assertIn("drgn_test", cmd.stdout)
        self.assertIn(
            "prog.debug_info_options.kernel_directories", cmd.drgn_option.stdout
        )
        self.assertIn("prog.load_default_debug_info", cmd.drgn_option.stdout)
