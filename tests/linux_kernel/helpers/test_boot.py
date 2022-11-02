# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import re
import unittest

from drgn.helpers.linux.boot import pgtable_l5_enabled
from tests.linux_kernel import LinuxKernelTestCase
from util import NORMALIZED_MACHINE_NAME


class TestBoot(LinuxKernelTestCase):
    @unittest.skipUnless(NORMALIZED_MACHINE_NAME == "x86_64", "machine is not x86_64")
    def test_pgtable_l5_enabled(self):
        with open("/proc/cpuinfo", "r") as f:
            self.assertEqual(
                pgtable_l5_enabled(self.prog),
                bool(re.search(r"flags\s*:.*\bla57\b", f.read())),
            )
