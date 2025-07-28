# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import re

from tests.linux_kernel import possible_cpus, skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestP(CrashCommandTestCase):
    def test_object(self):
        cmd = self.check_crash_command("p jiffies")
        self.assertRegex(cmd.stdout, r"jiffies = \([^)]+\)[0-9]+")
        self.assertIdentical(cmd.drgn_option.globals["object"], self.prog["jiffies"])

    @skip_unless_have_test_kmod
    def test_cpuspec(self):
        cmd = self.check_crash_command("p drgn_test_percpu_structs:a")
        matches = re.findall(
            r"^per_cpu\(drgn_test_percpu_structs, ([0-9]+)\) = \(struct drgn_test_percpu_struct\)\{",
            cmd.stdout,
            flags=re.MULTILINE,
        )
        cpus = sorted(possible_cpus())
        self.assertEqual([int(match) for match in matches], cpus)
        self.assertIn("per_cpu(", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["object"].cpu, max(cpus))

    def test_member(self):
        cmd = self.check_crash_command("p init_task.pid")
        self.assertRegex(cmd.stdout, r"init_task\.pid = \([^)]*\)0")
        self.assertIn(".pid", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["init_task"].pid
        )

    @skip_unless_have_test_kmod
    def test_radix(self):
        self.addCleanup(self.prog.config.pop, "crash_radix", None)

        self.run_crash_command("set radix 16")
        cmd = self.run_crash_command("p drgn_test_singular_list_entry")
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0x0")

        cmd = self.run_crash_command("p -d drgn_test_singular_list_entry")
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0\b")

        self.run_crash_command("set radix 10")
        cmd = self.run_crash_command("p drgn_test_singular_list_entry")
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0\b")

        cmd = self.run_crash_command("p -x drgn_test_singular_list_entry")
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0x0")
