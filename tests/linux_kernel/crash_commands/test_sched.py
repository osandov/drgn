# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


from drgn import Object
from drgn.commands import CommandArgumentError
from tests.linux_kernel import skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestWaitq(CrashCommandTestCase):
    @skip_unless_have_test_kmod
    def test_empty(self):
        cmd = self.check_crash_command("waitq drgn_test_empty_waitq")
        self.assertIn("is empty", cmd.stdout)
        self.assertIn("waitqueue_for_each_task(", cmd.drgn_option.stdout)

    @skip_unless_have_test_kmod
    def test_non_empty(self):
        cmd = self.check_crash_command("waitq drgn_test_waitq")
        self.assertIn('COMMAND: "drgn_test_', cmd.stdout)
        self.assertIn("waitqueue_for_each_task(", cmd.drgn_option.stdout)
        for variable in (
            "task",
            "pid",
            "command",
        ):
            self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIsInstance(cmd.drgn_option.globals["cpu"], int)

    @skip_unless_have_test_kmod
    def test_empty_symbol(self):
        address = self.prog.symbol("drgn_test_empty_waitq").address
        cmd = self.check_crash_command(f"waitq {address:x}")
        self.assertIn("is empty", cmd.stdout)
        self.assertIn("waitqueue_for_each_task(", cmd.drgn_option.stdout)

    @skip_unless_have_test_kmod
    def test_struct(self):
        address = self.prog.symbol("drgn_test_waitq_container").address
        cmd = self.check_crash_command(
            f"waitq drgn_test_waitq_container_struct.waitq {address:x}"
        )
        self.assertIn("is empty", cmd.stdout)
        self.assertIn("waitqueue_for_each_task(", cmd.drgn_option.stdout)

    def test_no_arguments(self):
        self.assertRaisesRegex(
            CommandArgumentError,
            "is required",
            self.run_crash_command,
            "waitq",
        )

    def test_too_many_arguments(self):
        self.assertRaisesRegex(
            CommandArgumentError,
            "unrecognized",
            self.run_crash_command,
            "waitq foo.bar abcd1234 baz",
        )
