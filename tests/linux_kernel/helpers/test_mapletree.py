# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import unittest

from drgn import NULL, Object, sizeof
from drgn.helpers.linux.mapletree import mt_for_each, mtree_load
from drgn.helpers.linux.xarray import xa_is_zero
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestMapleTree(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not cls.prog["drgn_test_have_maple_tree"]:
            raise unittest.SkipTest("kernel does not have maple tree")

    def maple_trees(self, name):
        yield self.prog["drgn_test_maple_tree_" + name].address_of_(), False
        yield self.prog["drgn_test_maple_tree_arange_" + name].address_of_(), True

    def test_mtree_load_empty(self):
        for mt, _ in self.maple_trees("empty"):
            self.assertIdentical(mtree_load(mt, 0), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 666), NULL(self.prog, "void *"))

    def test_mt_for_each_empty(self):
        for mt, _ in self.maple_trees("empty"):
            self.assertIdentical(list(mt_for_each(mt)), [])

    def test_mtree_load_one(self):
        for mt, _ in self.maple_trees("one"):
            self.assertIdentical(mtree_load(mt, 0), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 665), NULL(self.prog, "void *"))
            self.assertIdentical(
                mtree_load(mt, 666), Object(self.prog, "void *", 0xDEADB00)
            )
            self.assertIdentical(mtree_load(mt, 667), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**32 - 1), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**64 - 1), NULL(self.prog, "void *"))

    def test_mt_for_each_one(self):
        for mt, _ in self.maple_trees("one"):
            self.assertIdentical(
                list(mt_for_each(mt)),
                [(666, 666, Object(self.prog, "void *", 0xDEADB00))],
            )

    def test_mtree_load_one_range(self):
        for mt, _ in self.maple_trees("one_range"):
            self.assertIdentical(mtree_load(mt, 0), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 615), NULL(self.prog, "void *"))
            self.assertIdentical(
                mtree_load(mt, 616), Object(self.prog, "void *", 0xDEADB000)
            )
            self.assertIdentical(
                mtree_load(mt, 660), Object(self.prog, "void *", 0xDEADB000)
            )
            self.assertIdentical(
                mtree_load(mt, 666), Object(self.prog, "void *", 0xDEADB000)
            )
            self.assertIdentical(mtree_load(mt, 667), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**32 - 1), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**64 - 1), NULL(self.prog, "void *"))

    def test_mt_for_each_one_range(self):
        for mt, _ in self.maple_trees("one_range"):
            self.assertIdentical(
                list(mt_for_each(mt)),
                [(616, 666, Object(self.prog, "void *", 0xDEADB000))],
            )

    def test_mtree_load_one_at_zero(self):
        for mt, _ in self.maple_trees("one_at_zero"):
            self.assertIdentical(mtree_load(mt, 0), Object(self.prog, "void *", 0x1234))
            self.assertIdentical(mtree_load(mt, 1), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**32 - 1), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**64 - 1), NULL(self.prog, "void *"))

    def test_mt_for_each_one_at_zero(self):
        for mt, _ in self.maple_trees("one_at_zero"):
            self.assertIdentical(
                list(mt_for_each(mt)), [(0, 0, Object(self.prog, "void *", 0x1234))]
            )

    def test_mtree_load_one_range_at_zero(self):
        for mt, _ in self.maple_trees("one_range_at_zero"):
            self.assertIdentical(mtree_load(mt, 0), Object(self.prog, "void *", 0x5678))
            self.assertIdentical(mtree_load(mt, 1), Object(self.prog, "void *", 0x5678))
            self.assertIdentical(
                mtree_load(mt, 0x1336), Object(self.prog, "void *", 0x5678)
            )
            self.assertIdentical(
                mtree_load(mt, 0x1337), Object(self.prog, "void *", 0x5678)
            )
            self.assertIdentical(mtree_load(mt, 0x1338), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**32 - 1), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**64 - 1), NULL(self.prog, "void *"))

    def test_mt_for_each_one_range_at_zero(self):
        for mt, _ in self.maple_trees("one_range_at_zero"):
            self.assertIdentical(
                list(mt_for_each(mt)),
                [(0, 0x1337, Object(self.prog, "void *", 0x5678))],
            )

    def test_mtree_load_zero_entry(self):
        for mt, _ in self.maple_trees("zero_entry"):
            self.assertIdentical(mtree_load(mt, 666), NULL(self.prog, "void *"))
            self.assertTrue(xa_is_zero(mtree_load(mt, 666, advanced=True)))

    def test_mtree_for_each_zero_entry(self):
        for mt, _ in self.maple_trees("zero_entry"):
            self.assertIdentical(list(mt_for_each(mt)), [])
            entries = list(mt_for_each(mt, advanced=True))
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0][:2], (666, 666))
            self.assertTrue(xa_is_zero(entries[0][2]))

    def test_mtree_load_zero_entry_at_zero(self):
        for mt, _ in self.maple_trees("zero_entry_at_zero"):
            self.assertIdentical(mtree_load(mt, 0), NULL(self.prog, "void *"))
            self.assertTrue(xa_is_zero(mtree_load(mt, 0, advanced=True)))

    def test_mtree_for_each_zero_entry_at_zero(self):
        for mt, _ in self.maple_trees("zero_entry_at_zero"):
            self.assertIdentical(list(mt_for_each(mt)), [])
            entries = list(mt_for_each(mt, advanced=True))
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0][:2], (0, 0))
            self.assertTrue(xa_is_zero(entries[0][2]))

    def test_mtree_load_dense(self):
        for mt, _ in self.maple_trees("dense"):
            for i in range(5):
                with self.subTest(i=i):
                    self.assertIdentical(
                        mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA000 | i)
                    )
            self.assertIdentical(mtree_load(mt, 5), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**32 - 1), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**64 - 1), NULL(self.prog, "void *"))

    def test_mt_for_each_dense(self):
        for mt, _ in self.maple_trees("dense"):
            self.assertIdentical(
                list(mt_for_each(mt)),
                [(i, i, Object(self.prog, "void *", 0xB0BA000 | i)) for i in range(5)],
            )

    def test_mtree_load_dense_ranges(self):
        for mt, _ in self.maple_trees("dense_ranges"):
            self.assertIdentical(
                mtree_load(mt, 0), Object(self.prog, "void *", 0xB0BA000)
            )
            for i in range(1, 4):
                self.assertIdentical(
                    mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA001)
                )
            for i in range(4, 9):
                self.assertIdentical(
                    mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA002)
                )
            for i in range(9, 16):
                self.assertIdentical(
                    mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA003)
                )
            for i in range(16, 25):
                self.assertIdentical(
                    mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA004)
                )
            self.assertIdentical(mtree_load(mt, 25), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**32 - 1), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**64 - 1), NULL(self.prog, "void *"))

    def test_mt_for_each_dense_ranges(self):
        for mt, _ in self.maple_trees("dense_ranges"):
            self.assertIdentical(
                list(mt_for_each(mt)),
                [
                    (
                        i**2,
                        (i + 1) ** 2 - 1,
                        Object(self.prog, "void *", 0xB0BA000 | i),
                    )
                    for i in range(5)
                ],
            )

    def test_mtree_load_sparse(self):
        for mt, _ in self.maple_trees("sparse"):
            self.assertIdentical(mtree_load(mt, 0), NULL(self.prog, "void *"))
            self.assertIdentical(
                mtree_load(mt, 1), Object(self.prog, "void *", 0xB0BA000)
            )
            for i in range(2, 4):
                self.assertIdentical(mtree_load(mt, i), NULL(self.prog, "void *"))
            self.assertIdentical(
                mtree_load(mt, 4), Object(self.prog, "void *", 0xB0BA001)
            )
            for i in range(5, 9):
                self.assertIdentical(mtree_load(mt, i), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 26), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**32 - 1), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**64 - 1), NULL(self.prog, "void *"))

    def test_mt_for_each_sparse(self):
        for mt, _ in self.maple_trees("sparse"):
            self.assertIdentical(
                list(mt_for_each(mt)),
                [
                    (
                        (i + 1) ** 2,
                        (i + 1) ** 2,
                        Object(self.prog, "void *", 0xB0BA000 | i),
                    )
                    for i in range(5)
                ],
            )

    def test_mtree_load_sparse_ranges(self):
        for mt, _ in self.maple_trees("sparse_ranges"):
            self.assertIdentical(mtree_load(mt, 0), NULL(self.prog, "void *"))
            for i in range(1, 5):
                self.assertIdentical(
                    mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA000)
                )
            for i in range(5, 9):
                self.assertIdentical(mtree_load(mt, i), NULL(self.prog, "void *"))
            for i in range(9, 17):
                self.assertIdentical(
                    mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA001)
                )
            for i in range(17, 25):
                self.assertIdentical(mtree_load(mt, i), NULL(self.prog, "void *"))
            for i in range(25, 37):
                self.assertIdentical(
                    mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA002)
                )
            for i in range(37, 49):
                self.assertIdentical(mtree_load(mt, i), NULL(self.prog, "void *"))
            for i in range(49, 65):
                self.assertIdentical(
                    mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA003)
                )
            for i in range(65, 81):
                self.assertIdentical(mtree_load(mt, i), NULL(self.prog, "void *"))
            for i in range(81, 101):
                self.assertIdentical(
                    mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA004)
                )
            self.assertIdentical(mtree_load(mt, 101), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**32 - 1), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, 2**64 - 1), NULL(self.prog, "void *"))

    def test_mt_for_each_sparse_ranges(self):
        for mt, _ in self.maple_trees("sparse_ranges"):
            self.assertIdentical(
                list(mt_for_each(mt)),
                [
                    (
                        (2 * i + 1) ** 2,
                        (2 * i + 2) ** 2,
                        Object(self.prog, "void *", 0xB0BA000 | i),
                    )
                    for i in range(5)
                ],
            )

    def test_mtree_load_three_levels_dense_1(self):
        maple_range64_slots = self.prog["drgn_test_maple_range64_slots"].value_()
        ulong_max = (1 << (sizeof(self.prog.type("unsigned long")) * 8)) - 1
        for mt, arange in self.maple_trees("three_levels_dense_1"):
            node_slots = self.prog[
                "drgn_test_maple_arange64_slots"
                if arange
                else "drgn_test_maple_range64_slots"
            ].value_()
            n = 2 * (node_slots - 1) * (maple_range64_slots - 1) + (
                maple_range64_slots - 1
            )
            for i in range(n):
                with self.subTest(i=i):
                    self.assertIdentical(
                        mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA000 | i)
                    )
            self.assertIdentical(mtree_load(mt, n), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, n + 1), NULL(self.prog, "void *"))
            self.assertIdentical(
                mtree_load(mt, ulong_max - 1), NULL(self.prog, "void *")
            )
            self.assertIdentical(mtree_load(mt, ulong_max), NULL(self.prog, "void *"))

    def test_mt_for_each_three_levels_dense_1(self):
        maple_range64_slots = self.prog["drgn_test_maple_range64_slots"].value_()
        for mt, arange in self.maple_trees("three_levels_dense_1"):
            node_slots = self.prog[
                "drgn_test_maple_arange64_slots"
                if arange
                else "drgn_test_maple_range64_slots"
            ].value_()
            n = 2 * (node_slots - 1) * (maple_range64_slots - 1) + (
                maple_range64_slots - 1
            )
            self.assertIdentical(
                list(mt_for_each(mt)),
                [(i, i, Object(self.prog, "void *", 0xB0BA000 | i)) for i in range(n)],
            )

    def test_mtree_load_three_levels_dense_2(self):
        maple_range64_slots = self.prog["drgn_test_maple_range64_slots"].value_()
        ulong_max = (1 << (sizeof(self.prog.type("unsigned long")) * 8)) - 1
        for mt, arange in self.maple_trees("three_levels_dense_2"):
            node_slots = self.prog[
                "drgn_test_maple_arange64_slots"
                if arange
                else "drgn_test_maple_range64_slots"
            ].value_()
            n = 2 * node_slots * maple_range64_slots
            for i in range(n):
                with self.subTest(i=i):
                    self.assertIdentical(
                        mtree_load(mt, i), Object(self.prog, "void *", 0xB0BA000 | i)
                    )
            self.assertIdentical(mtree_load(mt, n), NULL(self.prog, "void *"))
            self.assertIdentical(mtree_load(mt, n + 1), NULL(self.prog, "void *"))
            self.assertIdentical(
                mtree_load(mt, ulong_max - 1), NULL(self.prog, "void *")
            )
            self.assertIdentical(mtree_load(mt, ulong_max), NULL(self.prog, "void *"))

    def test_mt_for_each_three_levels_dense_2(self):
        maple_range64_slots = self.prog["drgn_test_maple_range64_slots"].value_()
        for mt, arange in self.maple_trees("three_levels_dense_2"):
            node_slots = self.prog[
                "drgn_test_maple_arange64_slots"
                if arange
                else "drgn_test_maple_range64_slots"
            ].value_()
            n = 2 * node_slots * maple_range64_slots
            self.assertIdentical(
                list(mt_for_each(mt)),
                [(i, i, Object(self.prog, "void *", 0xB0BA000 | i)) for i in range(n)],
            )

    def test_mtree_load_three_levels_ranges_1(self):
        maple_range64_slots = self.prog["drgn_test_maple_range64_slots"].value_()
        ulong_max = (1 << (sizeof(self.prog.type("unsigned long")) * 8)) - 1
        for mt, arange in self.maple_trees("three_levels_ranges_1"):
            node_slots = self.prog[
                "drgn_test_maple_arange64_slots"
                if arange
                else "drgn_test_maple_range64_slots"
            ].value_()
            n = 2 * (node_slots - 1) * (maple_range64_slots - 1) + (
                maple_range64_slots - 1
            )
            for i in range(n):
                with self.subTest(i=i):
                    self.assertIdentical(
                        mtree_load(mt, 2 * i),
                        Object(self.prog, "void *", 0xB0BA000 | i),
                    )
                    self.assertIdentical(
                        mtree_load(mt, 2 * i + 1),
                        Object(self.prog, "void *", 0xB0BA000 | i),
                    )
            self.assertIdentical(
                mtree_load(mt, 2 * n), Object(self.prog, "void *", 0xB0BA000 | n)
            )
            self.assertIdentical(
                mtree_load(mt, 2 * n + 1), Object(self.prog, "void *", 0xB0BA000 | n)
            )
            self.assertIdentical(
                mtree_load(mt, ulong_max - 1),
                Object(self.prog, "void *", 0xB0BA000 | n),
            )
            self.assertIdentical(
                mtree_load(mt, ulong_max), Object(self.prog, "void *", 0xB0BA000 | n)
            )

    def test_mt_for_each_three_levels_ranges_1(self):
        maple_range64_slots = self.prog["drgn_test_maple_range64_slots"].value_()
        ulong_max = (1 << (sizeof(self.prog.type("unsigned long")) * 8)) - 1
        for mt, arange in self.maple_trees("three_levels_ranges_1"):
            node_slots = self.prog[
                "drgn_test_maple_arange64_slots"
                if arange
                else "drgn_test_maple_range64_slots"
            ].value_()
            n = 2 * (node_slots - 1) * (maple_range64_slots - 1) + (
                maple_range64_slots - 1
            )
            self.assertIdentical(
                list(mt_for_each(mt)),
                [
                    (2 * i, 2 * i + 1, Object(self.prog, "void *", 0xB0BA000 | i))
                    for i in range(n)
                ]
                + [(2 * n, ulong_max, Object(self.prog, "void *", 0xB0BA000 | n))],
            )

    def test_mtree_load_three_levels_ranges_2(self):
        maple_range64_slots = self.prog["drgn_test_maple_range64_slots"].value_()
        ulong_max = (1 << (sizeof(self.prog.type("unsigned long")) * 8)) - 1
        for mt, arange in self.maple_trees("three_levels_ranges_2"):
            node_slots = self.prog[
                "drgn_test_maple_arange64_slots"
                if arange
                else "drgn_test_maple_range64_slots"
            ].value_()
            n = 2 * node_slots * maple_range64_slots
            for i in range(n):
                with self.subTest(i=i):
                    self.assertIdentical(
                        mtree_load(mt, 2 * i),
                        Object(self.prog, "void *", 0xB0BA000 | i),
                    )
                    self.assertIdentical(
                        mtree_load(mt, 2 * i + 1),
                        Object(self.prog, "void *", 0xB0BA000 | i),
                    )
            self.assertIdentical(
                mtree_load(mt, 2 * n), Object(self.prog, "void *", 0xB0BA000 | n)
            )
            self.assertIdentical(
                mtree_load(mt, 2 * n + 1), Object(self.prog, "void *", 0xB0BA000 | n)
            )
            self.assertIdentical(
                mtree_load(mt, ulong_max - 1),
                Object(self.prog, "void *", 0xB0BA000 | n),
            )
            self.assertIdentical(
                mtree_load(mt, ulong_max), Object(self.prog, "void *", 0xB0BA000 | n)
            )

    def test_mt_for_each_three_levels_ranges_2(self):
        maple_range64_slots = self.prog["drgn_test_maple_range64_slots"].value_()
        ulong_max = (1 << (sizeof(self.prog.type("unsigned long")) * 8)) - 1
        for mt, arange in self.maple_trees("three_levels_ranges_2"):
            node_slots = self.prog[
                "drgn_test_maple_arange64_slots"
                if arange
                else "drgn_test_maple_range64_slots"
            ].value_()
            n = 2 * node_slots * maple_range64_slots
            self.assertIdentical(
                list(mt_for_each(mt)),
                [
                    (2 * i, 2 * i + 1, Object(self.prog, "void *", 0xB0BA000 | i))
                    for i in range(n)
                ]
                + [(2 * n, ulong_max, Object(self.prog, "void *", 0xB0BA000 | n))],
            )
