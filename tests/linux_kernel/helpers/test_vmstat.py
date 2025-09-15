# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.vmstat import nr_free_pages
from tests.linux_kernel import LinuxKernelTestCase, meminfo_field_in_pages


class TestVmstat(LinuxKernelTestCase):
    def test_nr_free_pages(self):
        self.assertAlmostEqual(
            nr_free_pages(self.prog),
            meminfo_field_in_pages("MemFree"),
            delta=1024 * 1024 * 1024,
        )
