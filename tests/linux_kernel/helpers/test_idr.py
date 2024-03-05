# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import NULL, Object
from drgn.helpers.linux.idr import idr_find, idr_for_each, idr_for_each_entry
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestIDR(LinuxKernelTestCase):
    def test_idr_find_empty(self):
        root = self.prog["drgn_test_idr_empty"].address_of_()
        self.assertIdentical(idr_find(root, 0), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 100), NULL(self.prog, "void *"))

    def test_idr_for_each_empty(self):
        root = self.prog["drgn_test_idr_empty"].address_of_()
        self.assertIdentical(list(idr_for_each(root)), [])

    def test_idr_find_one(self):
        root = self.prog["drgn_test_idr_one"].address_of_()
        self.assertIdentical(idr_find(root, 0), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 65), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 66), Object(self.prog, "void *", 0xDEADB00))
        self.assertIdentical(idr_find(root, 67), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 100), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 256 + 66), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 2**24 + 66), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 2**56 + 66), NULL(self.prog, "void *"))

    def test_idr_for_each_one(self):
        root = self.prog["drgn_test_idr_one"].address_of_()
        self.assertIdentical(
            list(idr_for_each(root)),
            [(66, Object(self.prog, "void *", 0xDEADB00))],
        )

    def test_idr_lookup_one_at_zero(self):
        root = self.prog["drgn_test_idr_one_at_zero"].address_of_()
        self.assertIdentical(idr_find(root, 0), Object(self.prog, "void *", 0x1234))
        self.assertIdentical(idr_find(root, 1), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 100), NULL(self.prog, "void *"))

    def test_idr_for_each_one_at_zero(self):
        root = self.prog["drgn_test_idr_one_at_zero"].address_of_()
        self.assertIdentical(
            list(idr_for_each(root)), [(0, Object(self.prog, "void *", 0x1234))]
        )

    def test_idr_find_sparse(self):
        root = self.prog["drgn_test_idr_sparse"].address_of_()
        self.assertIdentical(idr_find(root, 0), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 1), Object(self.prog, "void *", 0x1234))
        self.assertIdentical(idr_find(root, 2), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 0x40), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 0x70), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 0x7F), NULL(self.prog, "void *"))
        self.assertIdentical(idr_find(root, 0x80), Object(self.prog, "void *", 0x5678))
        self.assertIdentical(idr_find(root, 0xEE), Object(self.prog, "void *", 0x9ABC))
        self.assertIdentical(idr_find(root, 0xEF), NULL(self.prog, "void *"))

    def test_idr_for_each_sparse(self):
        root = self.prog["drgn_test_idr_sparse"].address_of_()
        self.assertIdentical(
            list(idr_for_each(root)),
            [
                (1, Object(self.prog, "void *", 0x1234)),
                (0x80, Object(self.prog, "void *", 0x5678)),
                (0xEE, Object(self.prog, "void *", 0x9ABC)),
            ],
        )

    def test_idr_for_each_entry(self):
        root = self.prog["drgn_test_idr_sparse"].address_of_()
        self.assertIdentical(
            list(idr_for_each_entry(root, "int")),
            [
                (1, Object(self.prog, "int *", 0x1234)),
                (0x80, Object(self.prog, "int *", 0x5678)),
                (0xEE, Object(self.prog, "int *", 0x9ABC)),
            ],
        )
