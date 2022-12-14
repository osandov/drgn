# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import unittest

from drgn import NULL, Object
from drgn.helpers.linux.xarray import (
    xa_for_each,
    xa_is_value,
    xa_is_zero,
    xa_load,
    xa_to_value,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestXArray(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not cls.prog["drgn_test_have_xarray"]:
            raise unittest.SkipTest("kernel does not have XArray")

    def test_xa_is_zero(self):
        self.assertTrue(xa_is_zero(self.prog["drgn_test_xa_zero_entry"]))
        self.assertFalse(xa_is_zero(NULL(self.prog, "void *")))

    def test_xa_load_empty(self):
        xa = self.prog["drgn_test_xarray_empty"].address_of_()
        self.assertIdentical(xa_load(xa, 0), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 100000), NULL(self.prog, "void *"))

    def test_xa_for_each_empty(self):
        xa = self.prog["drgn_test_xarray_empty"].address_of_()
        self.assertIdentical(list(xa_for_each(xa)), [])

    def test_xa_load_one(self):
        xa = self.prog["drgn_test_xarray_one"].address_of_()
        self.assertIdentical(xa_load(xa, 0), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 665), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 666), Object(self.prog, "void *", 0xDEADB00))
        self.assertIdentical(xa_load(xa, 667), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 100000), NULL(self.prog, "void *"))

    def test_xa_for_each_one(self):
        xa = self.prog["drgn_test_xarray_one"].address_of_()
        self.assertIdentical(
            list(xa_for_each(xa)), [(666, Object(self.prog, "void *", 0xDEADB00))]
        )

    def test_xa_load_one_at_zero(self):
        xa = self.prog["drgn_test_xarray_one_at_zero"].address_of_()
        self.assertIdentical(xa_load(xa, 0), Object(self.prog, "void *", 0x1234))
        self.assertIdentical(xa_load(xa, 1), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 100000), NULL(self.prog, "void *"))

    def test_xa_for_each_one_at_zero(self):
        xa = self.prog["drgn_test_xarray_one_at_zero"].address_of_()
        self.assertIdentical(
            list(xa_for_each(xa)), [(0, Object(self.prog, "void *", 0x1234))]
        )

    def test_xa_load_sparse(self):
        xa = self.prog["drgn_test_xarray_sparse"].address_of_()
        self.assertIdentical(xa_load(xa, 0), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 1), Object(self.prog, "void *", 0x1234))
        self.assertIdentical(xa_load(xa, 2), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 0x40000000), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 0x80000000), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 0x80800000), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 0x80808000), NULL(self.prog, "void *"))
        self.assertIdentical(
            xa_load(xa, 0x80808080), Object(self.prog, "void *", 0x5678)
        )
        self.assertIdentical(xa_load(xa, 0xFFFFFFFE), NULL(self.prog, "void *"))
        self.assertIdentical(
            xa_load(xa, 0xFFFFFFFF), Object(self.prog, "void *", 0x9ABC)
        )

    def test_xa_for_each_sparse(self):
        xa = self.prog["drgn_test_xarray_sparse"].address_of_()
        self.assertIdentical(
            list(xa_for_each(xa)),
            [
                (1, Object(self.prog, "void *", 0x1234)),
                (0x80808080, Object(self.prog, "void *", 0x5678)),
                (0xFFFFFFFF, Object(self.prog, "void *", 0x9ABC)),
            ],
        )

    def test_xa_load_multi_index(self):
        xa = self.prog["drgn_test_xarray_multi_index"].address_of_()
        self.assertIdentical(xa_load(xa, 0x80807FFF), NULL(self.prog, "void *"))
        for index in range(0x80808000, 0x80808200):
            with self.subTest(index=index):
                self.assertIdentical(
                    xa_load(xa, index), Object(self.prog, "void *", 0x1234)
                )
        self.assertIdentical(xa_load(xa, 0x80808200), NULL(self.prog, "void *"))

    def test_xa_for_each_multi_index(self):
        xa = self.prog["drgn_test_xarray_multi_index"].address_of_()
        self.assertIdentical(
            list(xa_for_each(xa)), [(0x80808000, Object(self.prog, "void *", 0x1234))]
        )

    def test_xa_load_zero_entry(self):
        xa = self.prog["drgn_test_xarray_zero_entry"].address_of_()
        self.assertIdentical(xa_load(xa, 0), NULL(self.prog, "void *"))
        self.assertIdentical(xa_load(xa, 666), NULL(self.prog, "void *"))
        self.assertTrue(xa_is_zero(xa_load(xa, 666, advanced=True)))
        self.assertIdentical(xa_load(xa, 2), NULL(self.prog, "void *"))

    def test_xa_for_each_zero_entry(self):
        xa = self.prog["drgn_test_xarray_zero_entry"].address_of_()
        self.assertIdentical(list(xa_for_each(xa)), [])

        entries = list(xa_for_each(xa, advanced=True))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], 666)
        self.assertTrue(xa_is_zero(entries[0][1]))

    def test_xa_load_zero_entry_at_zero(self):
        xa = self.prog["drgn_test_xarray_zero_entry_at_zero"].address_of_()
        self.assertIdentical(xa_load(xa, 0), NULL(self.prog, "void *"))
        self.assertTrue(xa_is_zero(xa_load(xa, 0, advanced=True)))
        self.assertIdentical(xa_load(xa, 1), NULL(self.prog, "void *"))

    def test_xa_for_each_zero_entry_at_zero(self):
        xa = self.prog["drgn_test_xarray_zero_entry_at_zero"].address_of_()
        self.assertIdentical(list(xa_for_each(xa)), [])

        entries = list(xa_for_each(xa, advanced=True))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], 0)
        self.assertTrue(xa_is_zero(entries[0][1]))

    def test_xa_is_value(self):
        self.assertTrue(
            xa_is_value(xa_load(self.prog["drgn_test_xarray_value"].address_of_(), 0))
        )
        self.assertFalse(
            xa_is_value(
                xa_load(self.prog["drgn_test_xarray_one_at_zero"].address_of_(), 0)
            )
        )

    def test_xa_to_value(self):
        self.assertIdentical(
            xa_to_value(xa_load(self.prog["drgn_test_xarray_value"].address_of_(), 0)),
            Object(self.prog, "unsigned long", 1337),
        )
