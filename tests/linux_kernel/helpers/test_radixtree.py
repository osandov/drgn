# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import NULL, Object
from drgn.helpers.linux.radixtree import radix_tree_for_each, radix_tree_lookup
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestRadixTree(LinuxKernelTestCase):
    def test_radix_tree_lookup_empty(self):
        root = self.prog["drgn_test_radix_tree_empty"].address_of_()
        self.assertIdentical(radix_tree_lookup(root, 0), NULL(self.prog, "void *"))
        self.assertIdentical(radix_tree_lookup(root, 100000), NULL(self.prog, "void *"))

    def test_radix_tree_for_each_empty(self):
        root = self.prog["drgn_test_radix_tree_empty"].address_of_()
        self.assertIdentical(list(radix_tree_for_each(root)), [])

    def test_radix_tree_lookup_one(self):
        root = self.prog["drgn_test_radix_tree_one"].address_of_()
        self.assertIdentical(radix_tree_lookup(root, 0), NULL(self.prog, "void *"))
        self.assertIdentical(radix_tree_lookup(root, 665), NULL(self.prog, "void *"))
        self.assertIdentical(
            radix_tree_lookup(root, 666), Object(self.prog, "void *", 0xDEADB00)
        )
        self.assertIdentical(radix_tree_lookup(root, 667), NULL(self.prog, "void *"))
        self.assertIdentical(radix_tree_lookup(root, 100000), NULL(self.prog, "void *"))

    def test_radix_tree_for_each_one(self):
        root = self.prog["drgn_test_radix_tree_one"].address_of_()
        self.assertIdentical(
            list(radix_tree_for_each(root)),
            [(666, Object(self.prog, "void *", 0xDEADB00))],
        )

    def test_radix_tree_lookup_one_at_zero(self):
        root = self.prog["drgn_test_radix_tree_one_at_zero"].address_of_()
        self.assertIdentical(
            radix_tree_lookup(root, 0), Object(self.prog, "void *", 0x1234)
        )
        self.assertIdentical(radix_tree_lookup(root, 1), NULL(self.prog, "void *"))
        self.assertIdentical(radix_tree_lookup(root, 100000), NULL(self.prog, "void *"))

    def test_radix_tree_for_each_one_at_zero(self):
        root = self.prog["drgn_test_radix_tree_one_at_zero"].address_of_()
        self.assertIdentical(
            list(radix_tree_for_each(root)), [(0, Object(self.prog, "void *", 0x1234))]
        )

    def test_radix_tree_lookup_sparse(self):
        root = self.prog["drgn_test_radix_tree_sparse"].address_of_()
        self.assertIdentical(radix_tree_lookup(root, 0), NULL(self.prog, "void *"))
        self.assertIdentical(
            radix_tree_lookup(root, 1), Object(self.prog, "void *", 0x1234)
        )
        self.assertIdentical(radix_tree_lookup(root, 2), NULL(self.prog, "void *"))
        self.assertIdentical(
            radix_tree_lookup(root, 0x40000000), NULL(self.prog, "void *")
        )
        self.assertIdentical(
            radix_tree_lookup(root, 0x80000000), NULL(self.prog, "void *")
        )
        self.assertIdentical(
            radix_tree_lookup(root, 0x80800000), NULL(self.prog, "void *")
        )
        self.assertIdentical(
            radix_tree_lookup(root, 0x80808000), NULL(self.prog, "void *")
        )
        self.assertIdentical(
            radix_tree_lookup(root, 0x80808080), Object(self.prog, "void *", 0x5678)
        )
        self.assertIdentical(
            radix_tree_lookup(root, 0xFFFFFFFE), NULL(self.prog, "void *")
        )
        self.assertIdentical(
            radix_tree_lookup(root, 0xFFFFFFFF), Object(self.prog, "void *", 0x9ABC)
        )

    def test_radix_tree_for_each_sparse(self):
        root = self.prog["drgn_test_radix_tree_sparse"].address_of_()
        self.assertIdentical(
            list(radix_tree_for_each(root)),
            [
                (1, Object(self.prog, "void *", 0x1234)),
                (0x80808080, Object(self.prog, "void *", 0x5678)),
                (0xFFFFFFFF, Object(self.prog, "void *", 0x9ABC)),
            ],
        )

    def test_radix_tree_lookup_multi_index(self):
        try:
            root = self.prog["drgn_test_radix_tree_multi_order"].address_of_()
        except KeyError:
            # Radix tree multi-order support only exists between Linux kernel
            # commits e61452365372 ("radix_tree: add support for multi-order
            # entries") (in v4.6) and 3a08cd52c37c ("radix tree: Remove
            # multiorder support") (in v4.20), and only if
            # CONFIG_RADIX_TREE_MULTIORDER=y.
            self.skipTest("kernel does not have multi-order radix trees")
        self.assertIdentical(
            radix_tree_lookup(root, 0x80807FFF), NULL(self.prog, "void *")
        )
        for index in range(0x80808000, 0x80808200):
            with self.subTest(index=index):
                self.assertIdentical(
                    radix_tree_lookup(root, index), Object(self.prog, "void *", 0x1234)
                )
        self.assertIdentical(
            radix_tree_lookup(root, 0x80808200), NULL(self.prog, "void *")
        )

    def test_radix_tree_for_each_multi_index(self):
        try:
            root = self.prog["drgn_test_radix_tree_multi_order"].address_of_()
        except KeyError:
            # See test_radix_tree_lookup_multi_index().
            self.skipTest("kernel does not have multi-order radix trees")
        self.assertIdentical(
            list(radix_tree_for_each(root)),
            [(0x80808000, Object(self.prog, "void *", 0x1234))],
        )
