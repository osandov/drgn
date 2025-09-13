# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import mmap
import os
from pathlib import Path

from drgn.helpers.linux.hugetlb import (
    for_each_hstate,
    huge_page_size,
    hugetlb_total_pages,
    hugetlb_total_usage,
)
from tests.linux_kernel import LinuxKernelTestCase


class TestHugetlb(LinuxKernelTestCase):
    def test_for_each_hstate(self):
        try:
            expected = os.listdir(b"/sys/kernel/mm/hugepages")
        except FileNotFoundError:
            expected = []
        self.assertCountEqual(
            [h.name.string_() for h in for_each_hstate(self.prog)],
            expected,
        )

    def test_huge_page_size(self):
        for hstate in for_each_hstate(self.prog):
            self.assertEqual(
                f"hugepages-{huge_page_size(hstate).value_() // 1024}kB".encode(),
                hstate.name.string_(),
            )
            break
        else:
            self.skipTest("no HugeTLB sizes")

    # Also tests hugetlb_total_pages().
    def test_hugetlb_total_usage(self):
        nr_hugepages_path = Path("/proc/sys/vm/nr_hugepages")
        try:
            old_nr_hugepages = int(nr_hugepages_path.read_text())
        except FileNotFoundError:
            old_nr_hugepages = None
        try:
            if old_nr_hugepages == 0:
                nr_hugepages_path.write_text("1")

            expected_total = 0
            expected_free = 0
            for path in Path("/sys/kernel/mm/hugepages").glob("hugepages-*kB"):
                pages = (
                    int(path.name[len("hugepages-") : -len("kB")])
                    * 1024
                    // mmap.PAGESIZE
                )
                expected_total += int((path / "nr_hugepages").read_text()) * pages
                expected_free += int((path / "free_hugepages").read_text()) * pages

            usage = hugetlb_total_usage(self.prog)
            self.assertEqual(usage.pages, expected_total)
            self.assertAlmostEqual(usage.free_pages, expected_free, delta=1024)

            self.assertEqual(hugetlb_total_pages(self.prog), expected_total)
        finally:
            if old_nr_hugepages == 0:
                nr_hugepages_path.write_text("0")
