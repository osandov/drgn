# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

import drgn.helpers.linux.cpumask
from drgn.helpers.linux.cpumask import cpumask_to_cpulist
from tests.linux_kernel import LinuxKernelTestCase, parse_range_list

CPU_PATH = Path("/sys/devices/system/cpu")


class TestCpuMask(LinuxKernelTestCase):
    _MASKS = ("online", "possible", "present")

    def test_for_each_cpu(self):
        for name in self._MASKS:
            with self.subTest(name=name):
                self.assertEqual(
                    list(
                        getattr(drgn.helpers.linux.cpumask, f"for_each_{name}_cpu")(
                            self.prog
                        )
                    ),
                    sorted(parse_range_list((CPU_PATH / name).read_text())),
                )

    def test_cpumask_to_cpulist(self):
        for name in self._MASKS:
            with self.subTest(name=name):
                self.assertEqual(
                    cpumask_to_cpulist(
                        getattr(drgn.helpers.linux.cpumask, f"cpu_{name}_mask")(
                            self.prog
                        )
                    ),
                    (CPU_PATH / name).read_text().strip(),
                )
