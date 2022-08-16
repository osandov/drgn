# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from drgn.helpers.common import identify_address
from drgn.helpers.linux.mm import pfn_to_virt
from tests.linux_kernel import (
    LinuxKernelTestCase,
    skip_unless_have_full_mm_support,
    skip_unless_have_test_kmod,
)


class TestIdentifyAddress(LinuxKernelTestCase):
    def test_identify_symbol(self):
        symbol = self.prog.symbol("__schedule")

        self.assertIn(
            identify_address(self.prog, symbol.address),
            ("symbol: __sched_text_start+0x0", "function symbol: __schedule+0x0"),
        )

        self.assertEqual(
            identify_address(self.prog, symbol.address + 1),
            "function symbol: __schedule+0x1",
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_slab_cache(self):
        for size in ("small", "big"):
            with self.subTest(size=size):
                objects = self.prog[f"drgn_test_{size}_slab_objects"]

                if self.prog["drgn_test_slob"]:
                    for obj in objects:
                        self.assertIsNone(identify_address(obj))
                else:
                    for obj in objects:
                        self.assertEqual(
                            identify_address(obj),
                            f"slab object: drgn_test_{size}",
                        )

    def test_identify_unrecognized(self):
        start_addr = (pfn_to_virt(self.prog["min_low_pfn"])).value_()
        end_addr = (pfn_to_virt(self.prog["max_pfn"]) + self.prog["PAGE_SIZE"]).value_()

        self.assertIsNone(identify_address(self.prog, start_addr - 1))
        self.assertIsNone(identify_address(self.prog, end_addr))
        self.assertIsNone(identify_address(self.prog, self.prog["drgn_test_va"]))
