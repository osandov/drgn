# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import gzip
import re

from drgn.helpers.linux.kconfig import get_kconfig
from tests.linux_kernel import LinuxKernelTestCase


class TestKconfig(LinuxKernelTestCase):
    def test_get_kconfig(self):
        expected = {}
        try:
            with gzip.open("/proc/config.gz", "rt") as f:
                for line in f:
                    match = re.match(r"(\w+)=(.*)", line)
                    if match:
                        expected[match.group(1)] = match.group(2)
        except FileNotFoundError:
            self.skipTest("kernel not built with CONFIG_IKCONFIG_PROC")
        self.assertEqual(get_kconfig(self.prog), expected)
