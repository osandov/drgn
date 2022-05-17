# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import platform
import re
import unittest

from drgn.helpers.linux.boot import pgtable_l5_enabled
from tests.linux_kernel import LinuxKernelTestCase


class TestBoot(LinuxKernelTestCase):
    @unittest.skipUnless(platform.machine() == "x86_64", "machine is not x86_64")
    def test_pgtable_l5_enabled(self):
        with open("/proc/cpuinfo", "r") as f:
            self.assertEqual(
                pgtable_l5_enabled(self.prog),
                bool(re.search(r"flags\s*:.*\bla57\b", f.read())),
            )
