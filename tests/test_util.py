# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from functools import cmp_to_key
import unittest

from util import KernelVersion, verrevcmp


class TestUtil(unittest.TestCase):
    def assertVersionSort(self, sorted_list):
        self.assertEqual(sorted(sorted_list, key=cmp_to_key(verrevcmp)), sorted_list)

    def test_verrevcmp(self):
        self.assertVersionSort(
            ["0~", "0", "1", "1.0", "1.1~rc1", "1.1~rc2", "1.1", "1.2", "1.12"]
        )
        self.assertVersionSort(["a", "."])
        self.assertVersionSort(["", "1"])
        self.assertVersionSort(["~", "~1"])
        self.assertVersionSort(["~~", "~~a", "~", "", "a"])

    def test_kernel_version(self):
        self.assertLess(KernelVersion("1.0"), KernelVersion("2.0"))
        self.assertLess(KernelVersion("5.6.0-rc6"), KernelVersion("5.6.0-rc7"))
        self.assertLess(KernelVersion("5.6.0-rc7"), KernelVersion("5.6.0"))
        self.assertLess(
            KernelVersion("5.6.0-rc7-vmtest2"), KernelVersion("5.6.0-vmtest1")
        )
        self.assertLess(KernelVersion("5.6.0-vmtest1"), KernelVersion("5.6.0-vmtest2"))
