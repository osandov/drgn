# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import re

from drgn import Object
from tests.linux_kernel import online_cpus, skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase


@skip_unless_have_test_kmod
class TestTimer(CrashCommandTestCase):
    def test_timer(self):
        cmd = self.check_crash_command("timer")
        self.assertIn("<drgn_test_timer_fn", cmd.stdout)
        self.assertIn("timer_base_for_each(", cmd.drgn_option.stdout)
        self.assertTrue(cmd.drgn_option.globals["name"], "BASE_")
        for variable in (
            "jiffies",
            "base",
            "timer",
            "expires",
            "tte",
            "function",
        ):
            self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

    def test_timer_cpu(self):
        cpu = min(online_cpus())
        cmd = self.check_crash_command(f"timer -C {cpu}")
        self.assertEqual(
            set(re.findall(r"TIMER_BASES\[([0-9]+)\]", cmd.stdout)), {str(cpu)}
        )
        self.assertEqual(cmd.drgn_option.globals["base"].cpu, cpu)

    def test_hrtimer(self):
        cmd = self.check_crash_command("timer -r")
        self.assertIn("<drgn_test_hrtimer_fn>", cmd.stdout)
        self.assertIn("hrtimer_clock_base_for_each(", cmd.drgn_option.stdout)
        for variable in (
            "cpu_base",
            "clock_base",
            "clock",
            "current",
            "hrtimer",
            "softexpires",
            "expires",
            "tte",
            "function",
        ):
            self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

    def test_hrtimer_cpu(self):
        cpu = min(online_cpus())
        cmd = self.check_crash_command(f"timer -r -C {cpu}")
        self.assertEqual(set(re.findall(r"CPU: ([0-9]+)", cmd.stdout)), {str(cpu)})
        self.assertEqual(cmd.drgn_option.globals["clock_base"].cpu_base.cpu, cpu)
