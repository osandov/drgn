# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import re

from drgn import Symbol
from tests import slow_test
from tests.linux_kernel import skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase


@skip_unless_have_test_kmod
class TestSym(CrashCommandTestCase):
    @slow_test
    def test_all(self):
        cmd = self.check_crash_command("sym -l")
        self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+ init_task$")
        self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+ schedule$")
        self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+ drgn_test_function$")
        self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+ drgn_test_data$")
        self.assertNotRegex(cmd.stdout, r"(?m) \.L.*$")

        self.assertIn("prog.symbols()", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["sym"], Symbol)

    @slow_test
    def test_substring(self):
        cmd = self.check_crash_command("sym -q drgn_test")
        self.assertNotRegex(cmd.stdout, r"(?m)^[0-9a-f]+ init_task$")
        self.assertNotRegex(cmd.stdout, r"(?m)^[0-9a-f]+ schedule$")
        self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+ drgn_test_function$")
        self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+ drgn_test_data$")

        self.assertIn('"drgn_test" in sym.name', cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["sym"], Symbol)

    @slow_test
    def test_substring_multiple(self):
        cmd = self.check_crash_command("sym -q drgn_test -q init")
        self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+ init_task$")
        self.assertNotRegex(cmd.stdout, r"(?m)^[0-9a-f]+ schedule$")
        self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+ drgn_test_function$")
        self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+ drgn_test_data$")

        self.assertIn("any(substring in sym.name", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["sym"], Symbol)

    def test_name(self):
        cmd = self.check_crash_command("sym drgn_test_function")
        self.assertRegex(
            cmd.stdout, r"^[0-9a-f]+ drgn_test_function .*drgn_test\.c: [0-9]+$"
        )

        self.assertIn('prog.symbol("drgn_test_function")', cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["sym"], Symbol)
        self.assertEqual(cmd.drgn_option.globals["sym"].name, "drgn_test_function")

    def test_address(self):
        address = self.prog.symbol("drgn_test_function").address

        cmd = self.check_crash_command(f"sym {hex(address)}")
        self.assertRegex(
            cmd.stdout, r"^[0-9a-f]+ drgn_test_function .*drgn_test\.c: [0-9]+$"
        )

        self.assertIn("prog.symbol(0x", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["sym"], Symbol)
        self.assertEqual(cmd.drgn_option.globals["sym"].name, "drgn_test_function")

    def test_multiple_names(self):
        cmd = self.check_crash_command("sym init_task drgn_test_function")
        self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+ init_task$")
        self.assertRegex(
            cmd.stdout, r"(?m)^[0-9a-f]+ drgn_test_function .*drgn_test\.c: [0-9]+$"
        )

        self.assertIn('prog.symbol("drgn_test_function")', cmd.drgn_option.stdout)
        self.assertIn('prog.symbol("init_task")', cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["sym"], Symbol)
        self.assertEqual(cmd.drgn_option.globals["sym"].name, "drgn_test_function")

    @slow_test
    def test_fallback_query(self):
        # The generated --drgn output doesn't do the fallback, so it would fail
        # with a LookupError. Just compile it.
        cmd = self.check_crash_command("sym drgn_test_", mode="compile")
        self.assertNotRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+ init_task$")
        self.assertNotRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+ schedule$")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+ drgn_test_function$")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+ drgn_test_data$")

        self.assertIn('prog.symbol("drgn_test_")', cmd.drgn_option.stdout)

    @slow_test
    def test_next_prev(self):
        cmd = self.check_crash_command("sym -np drgn_test_function")

        lines = cmd.stdout.splitlines()
        self.assertRegex(lines[1], r"^[0-9a-f]+ drgn_test_function")

        addresses = [int(re.match(r"[0-9a-f]+", line).group(), 16) for line in lines]
        self.assertEqual(addresses, sorted(addresses))

        self.assertIsInstance(cmd.drgn_option.globals["sym"], Symbol)
        self.assertIsInstance(cmd.drgn_option.globals["prev_sym"], Symbol)
        self.assertIsInstance(cmd.drgn_option.globals["next_sym"], Symbol)

        self.assertEqual(cmd.drgn_option.globals["sym"].name, "drgn_test_function")
        self.assertLess(
            cmd.drgn_option.globals["prev_sym"].address,
            cmd.drgn_option.globals["sym"].address,
        )
        self.assertGreater(
            cmd.drgn_option.globals["next_sym"].address,
            cmd.drgn_option.globals["sym"].address,
        )
