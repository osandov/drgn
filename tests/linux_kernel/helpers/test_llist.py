# Copyright (c) 2022, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import NULL
from drgn.helpers.linux.llist import (
    llist_empty,
    llist_first_entry,
    llist_first_entry_or_null,
    llist_for_each,
    llist_for_each_entry,
    llist_is_singular,
    llist_next_entry,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestLlist(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        cls.empty = cls.prog["drgn_test_empty_llist"].address_of_()
        cls.full = cls.prog["drgn_test_full_llist"].address_of_()
        cls.entries = cls.prog["drgn_test_llist_entries"]
        cls.num_entries = 3
        cls.singular = cls.prog["drgn_test_singular_llist"].address_of_()
        cls.singular_entry = cls.prog["drgn_test_singular_llist_entry"].address_of_()
        cls.singular_node = cls.singular_entry.node.address_of_()

    def node(self, n):
        return self.entries[n].node.address_of_()

    def entry(self, n):
        return self.entries[n].address_of_()

    def test_llist_empty(self):
        self.assertTrue(llist_empty(self.empty))
        self.assertFalse(llist_empty(self.full))
        self.assertFalse(llist_empty(self.singular))

    def test_llist_is_singular(self):
        self.assertFalse(llist_is_singular(self.empty))
        self.assertFalse(llist_is_singular(self.full))
        self.assertTrue(llist_is_singular(self.singular))

    def test_llist_first_entry(self):
        self.assertEqual(
            llist_first_entry(self.full, "struct drgn_test_llist_entry", "node"),
            self.entry(2),
        )
        self.assertEqual(
            llist_first_entry(self.singular, "struct drgn_test_llist_entry", "node"),
            self.singular_entry,
        )

    def test_llist_first_entry_or_null(self):
        self.assertEqual(
            llist_first_entry_or_null(
                self.empty, "struct drgn_test_llist_entry", "node"
            ),
            NULL(self.prog, "struct drgn_test_llist_entry *"),
        )
        self.assertEqual(
            llist_first_entry_or_null(
                self.full, "struct drgn_test_llist_entry", "node"
            ),
            self.entry(2),
        )
        self.assertEqual(
            llist_first_entry_or_null(
                self.singular, "struct drgn_test_llist_entry", "node"
            ),
            self.singular_entry,
        )

    def test_llist_next_entry(self):
        for i in reversed(range(1, self.num_entries)):
            self.assertEqual(llist_next_entry(self.entry(i), "node"), self.entry(i - 1))

    def test_llist_for_each(self):
        self.assertEqual(list(llist_for_each(self.empty.first)), [])
        self.assertEqual(
            list(llist_for_each(self.full.first)),
            [self.node(i) for i in reversed(range(self.num_entries))],
        )
        self.assertEqual(
            list(llist_for_each(self.singular.first)), [self.singular_node]
        )

    def test_llist_for_each_entry(self):
        self.assertEqual(
            list(
                llist_for_each_entry(
                    "struct drgn_test_llist_entry", self.empty.first, "node"
                )
            ),
            [],
        )
        self.assertEqual(
            list(
                llist_for_each_entry(
                    "struct drgn_test_llist_entry", self.full.first, "node"
                )
            ),
            [self.entry(i) for i in reversed(range(self.num_entries))],
        )
        self.assertEqual(
            list(
                llist_for_each_entry(
                    "struct drgn_test_llist_entry", self.singular.first, "node"
                )
            ),
            [self.singular_entry],
        )
