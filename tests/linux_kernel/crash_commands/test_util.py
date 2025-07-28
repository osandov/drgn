# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


import unittest.mock

from drgn.commands.crash import Cpuspec, parse_cpuspec
from drgn.helpers.linux.sched import idle_task
from tests import TestCase
from tests.linux_kernel import possible_cpus
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestParseCpuspec(TestCase):
    def test_current(self):
        self.assertEqual(parse_cpuspec(""), Cpuspec(current=True))

    def test_all(self):
        self.assertEqual(parse_cpuspec("a"), Cpuspec(all=True))
        self.assertEqual(parse_cpuspec("all"), Cpuspec(all=True))

    def test_single(self):
        self.assertEqual(parse_cpuspec("0"), Cpuspec(explicit_cpus={0}))
        self.assertEqual(parse_cpuspec("13"), Cpuspec(explicit_cpus={13}))

    def test_multiple(self):
        self.assertEqual(parse_cpuspec("0,1,5"), Cpuspec(explicit_cpus={0, 1, 5}))

    def test_multiple_repeat(self):
        self.assertEqual(parse_cpuspec("1,0,1"), Cpuspec(explicit_cpus={0, 1}))

    def test_range(self):
        self.assertEqual(parse_cpuspec("0-2"), Cpuspec(explicit_cpus={0, 1, 2}))
        self.assertEqual(parse_cpuspec("10-12"), Cpuspec(explicit_cpus={10, 11, 12}))

    def test_range_single(self):
        self.assertEqual(parse_cpuspec("4-4"), Cpuspec(explicit_cpus={4}))

    def test_range_backwards(self):
        self.assertEqual(parse_cpuspec("4-3"), Cpuspec(explicit_cpus=set()))

    def test_bad_syntax(self):
        for spec in (
            ",",
            "0,",
            "0,,1",
            ",0",
            "0 0",
            "0-",
            "-1",
            "0,",
            "-",
            "+",
        ):
            with self.subTest(spec=spec):
                self.assertRaisesRegex(
                    ValueError, "invalid cpuspec", parse_cpuspec, spec
                )


class TestCpuspecCpus(CrashCommandTestCase):
    def setUp(self):
        patcher = unittest.mock.patch(
            "drgn.commands.crash.for_each_possible_cpu",
            side_effect=lambda prog: (0, 1, 2, 4, 5),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_current(self):
        cpu = max(possible_cpus())
        task = idle_task(self.prog, cpu)
        self.run_crash_command(f"set {hex(task)}")
        self.assertEqual(Cpuspec(current=True).cpus(self.prog), [cpu])

    def test_all(self):
        self.assertEqual(Cpuspec(all=True).cpus(self.prog), [0, 1, 2, 4, 5])

    def test_explicit(self):
        self.assertEqual(Cpuspec(explicit_cpus={0, 1, 4}).cpus(self.prog), [0, 1, 4])

    def test_invalid_cpu(self):
        self.assertRaisesRegex(
            ValueError,
            "invalid CPU",
            Cpuspec(explicit_cpus={3}).cpus,
            self.prog,
        )
