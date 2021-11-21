# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from drgn.helpers.linux.cpumask import (
    for_each_online_cpu,
    for_each_possible_cpu,
    for_each_present_cpu,
)
from tests.helpers.linux import LinuxHelperTestCase, parse_range_list

CPU_PATH = Path("/sys/devices/system/cpu")


class TestCpuMask(LinuxHelperTestCase):
    def _test_for_each_cpu(self, func, name):
        self.assertEqual(
            list(func(self.prog)),
            sorted(parse_range_list((CPU_PATH / name).read_text())),
        )

    def test_for_each_online_cpu(self):
        self._test_for_each_cpu(for_each_online_cpu, "online")

    def test_for_each_possible_cpu(self):
        self._test_for_each_cpu(for_each_possible_cpu, "possible")

    def test_for_each_present_cpu(self):
        self._test_for_each_cpu(for_each_present_cpu, "present")
