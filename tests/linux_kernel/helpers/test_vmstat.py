# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import re

from drgn.helpers.linux.vmstat import (
    global_numa_event_state,
    global_vm_event_state,
    nr_free_pages,
)
from tests.linux_kernel import LinuxKernelTestCase, meminfo_field_in_pages


class TestVmstat(LinuxKernelTestCase):
    def test_nr_free_pages(self):
        self.assertAlmostEqual(
            nr_free_pages(self.prog),
            meminfo_field_in_pages("MemFree"),
            delta=1024 * 1024 * 1024,
        )

    def test_global_numa_event_state(self):
        with open("/proc/vmstat", "r") as f:
            for line in f:
                match = re.match(r"numa_hit\s+([0-9]+)", line)
                if match:
                    expected = int(match.group(1))
                    break
            else:
                self.skipTest("kernel does not support NUMA statistics")
        self.assertAlmostEqual(
            global_numa_event_state(self.prog["NUMA_HIT"]), expected, delta=1024 * 1024
        )

    def test_global_vm_event_state(self):
        with open("/proc/vmstat", "r") as f:
            for line in f:
                match = re.match(r"pgmajfault\s+([0-9]+)", line)
                if match:
                    expected = int(match.group(1))
                    break
            else:
                self.skipTest("kernel does not support VM event statistics")
        self.assertAlmostEqual(
            global_vm_event_state(self.prog["PGMAJFAULT"]), expected, delta=1024 * 1024
        )
