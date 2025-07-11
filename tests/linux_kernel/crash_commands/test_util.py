# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


from pathlib import Path
import unittest.mock

from drgn.commands.crash import parse_cpuspec
from drgn.helpers.linux.sched import idle_task
from tests.linux_kernel import parse_range_list
from tests.linux_kernel.crash_commands import CrashCommandTestCase

POSSIBLE_CPUS_PATH = Path("/sys/devices/system/cpu/possible")


class TestParseCpuspec(CrashCommandTestCase):
    # TODO: rework tests to use _parse_cpuspec instead.
    def setUp(self):
        patcher = unittest.mock.patch(
            "drgn.commands.crash.for_each_possible_cpu",
            side_effect=lambda prog: (0, 1, 2, 4, 5),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_current(self):
        cpu = max(parse_range_list(POSSIBLE_CPUS_PATH.read_text()))
        task = idle_task(self.prog, cpu)
        self.run_crash_command(f"set {hex(task)}")
        self.assertEqual(parse_cpuspec(self.prog, ""), [cpu])
        self.assertEqual(parse_cpuspec(self.prog, " "), [cpu])

    def test_all(self):
        self.assertEqual(parse_cpuspec(self.prog, "a"), [0, 1, 2, 4, 5])
        self.assertEqual(parse_cpuspec(self.prog, "all"), [0, 1, 2, 4, 5])

    def test_all_extra_whitespace(self):
        self.assertEqual(parse_cpuspec(self.prog, " a "), [0, 1, 2, 4, 5])

    def test_single(self):
        self.assertEqual(parse_cpuspec(self.prog, "0"), [0])
        self.assertEqual(parse_cpuspec(self.prog, "5"), [5])

    def test_single_extra_whitespace(self):
        self.assertEqual(parse_cpuspec(self.prog, " 1 "), [1])

    def test_multiple(self):
        self.assertEqual(parse_cpuspec(self.prog, "0,1,5"), [0, 1, 5])

    def test_multiple_extra_whitespace(self):
        self.assertEqual(parse_cpuspec(self.prog, " 0, 1 ,5 "), [0, 1, 5])

    def test_multiple_sort(self):
        self.assertEqual(parse_cpuspec(self.prog, "2,1,5"), [1, 2, 5])

    def test_multiple_repeat(self):
        self.assertEqual(parse_cpuspec(self.prog, "1,0,1"), [0, 1])

    def test_extra_commas(self):
        self.assertEqual(parse_cpuspec(self.prog, ",0,1,,5, ,"), [0, 1, 5])

    def test_range(self):
        self.assertEqual(parse_cpuspec(self.prog, "0-2"), [0, 1, 2])

    def test_range_extra_whitespace(self):
        self.assertEqual(parse_cpuspec(self.prog, " 0 - 2 "), [0, 1, 2])

    def test_range_single(self):
        self.assertEqual(parse_cpuspec(self.prog, "4-4"), [4])

    def test_range_backwards(self):
        self.assertEqual(parse_cpuspec(self.prog, "4-3"), [])

    def test_extra_hyphens(self):
        self.assertEqual(parse_cpuspec(self.prog, "0-"), [0])
        self.assertEqual(parse_cpuspec(self.prog, "-1"), [1])
        self.assertEqual(parse_cpuspec(self.prog, "0-1-2"), [0, 1, 2])
        self.assertEqual(parse_cpuspec(self.prog, "0- -2"), [0, 1, 2])
        self.assertEqual(parse_cpuspec(self.prog, "-1--2-"), [1, 2])

    def test_bad_syntax(self):
        self.assertRaisesRegex(
            ValueError, "invalid cpuspec", parse_cpuspec, self.prog, "0 0"
        )
        self.assertRaisesRegex(
            ValueError, "invalid cpuspec", parse_cpuspec, self.prog, "+"
        )

    def test_bad_cpus(self):
        self.assertRaisesRegex(
            ValueError, "invalid cpuspec", parse_cpuspec, self.prog, "0-9"
        )


# TODO: test add_cpuspec
