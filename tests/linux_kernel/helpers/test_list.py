# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import collections

from drgn import NULL
from drgn.helpers import ValidationError
from drgn.helpers.linux.list import (
    hlist_empty,
    hlist_for_each,
    hlist_for_each_entry,
    list_empty,
    list_first_entry,
    list_first_entry_or_null,
    list_for_each,
    list_for_each_entry,
    list_for_each_entry_reverse,
    list_for_each_reverse,
    list_is_singular,
    list_last_entry,
    list_next_entry,
    list_prev_entry,
    validate_list,
    validate_list_for_each,
    validate_list_for_each_entry,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestList(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        cls.empty = cls.prog["drgn_test_empty_list"].address_of_()
        cls.full = cls.prog["drgn_test_full_list"].address_of_()
        cls.entries = cls.prog["drgn_test_list_entries"]
        cls.num_entries = 3
        cls.singular = cls.prog["drgn_test_singular_list"].address_of_()
        cls.singular_entry = cls.prog["drgn_test_singular_list_entry"].address_of_()
        cls.singular_node = cls.singular_entry.node.address_of_()
        cls.corrupted = cls.prog["drgn_test_corrupted_list"].address_of_()

    def node(self, n):
        return self.entries[n].node.address_of_()

    def entry(self, n):
        return self.entries[n].address_of_()

    def test_list_empty(self):
        self.assertTrue(list_empty(self.empty))
        self.assertFalse(list_empty(self.full))
        self.assertFalse(list_empty(self.singular))

    def test_list_is_singular(self):
        self.assertFalse(list_is_singular(self.empty))
        self.assertFalse(list_is_singular(self.full))
        self.assertTrue(list_is_singular(self.singular))

    def test_list_first_entry(self):
        self.assertEqual(
            list_first_entry(self.full, "struct drgn_test_list_entry", "node"),
            self.entry(0),
        )
        self.assertEqual(
            list_first_entry(self.singular, "struct drgn_test_list_entry", "node"),
            self.singular_entry,
        )

    def test_list_first_entry_or_null(self):
        self.assertEqual(
            list_first_entry_or_null(self.empty, "struct drgn_test_list_entry", "node"),
            NULL(self.prog, "struct drgn_test_list_entry *"),
        )
        self.assertEqual(
            list_first_entry_or_null(self.full, "struct drgn_test_list_entry", "node"),
            self.entry(0),
        )
        self.assertEqual(
            list_first_entry_or_null(
                self.singular, "struct drgn_test_list_entry", "node"
            ),
            self.singular_entry,
        )

    def test_list_last_entry(self):
        self.assertEqual(
            list_last_entry(self.full, "struct drgn_test_list_entry", "node"),
            self.entry(self.num_entries - 1),
        )
        self.assertEqual(
            list_last_entry(self.singular, "struct drgn_test_list_entry", "node"),
            self.singular_entry,
        )

    def test_list_next_entry(self):
        for i in range(self.num_entries - 1):
            self.assertEqual(list_next_entry(self.entry(i), "node"), self.entry(i + 1))

    def test_list_prev_entry(self):
        for i in range(1, self.num_entries):
            self.assertEqual(list_prev_entry(self.entry(i), "node"), self.entry(i - 1))

    def test_list_for_each(self):
        self.assertEqual(list(list_for_each(self.empty)), [])
        self.assertEqual(
            list(list_for_each(self.full)),
            [self.node(i) for i in range(self.num_entries)],
        )
        self.assertEqual(list(list_for_each(self.singular)), [self.singular_node])

    def test_list_for_each_reverse(self):
        self.assertEqual(list(list_for_each_reverse(self.empty)), [])
        self.assertEqual(
            list(list_for_each_reverse(self.full)),
            [self.node(i) for i in range(self.num_entries - 1, -1, -1)],
        )
        self.assertEqual(
            list(list_for_each_reverse(self.singular)), [self.singular_node]
        )

    def test_list_for_each_entry(self):
        self.assertEqual(
            list(
                list_for_each_entry("struct drgn_test_list_entry", self.empty, "node")
            ),
            [],
        )
        self.assertEqual(
            list(list_for_each_entry("struct drgn_test_list_entry", self.full, "node")),
            [self.entry(i) for i in range(self.num_entries)],
        )
        self.assertEqual(
            list(
                list_for_each_entry(
                    "struct drgn_test_list_entry", self.singular, "node"
                )
            ),
            [self.singular_entry],
        )

    def test_list_for_each_entry_reverse(self):
        self.assertEqual(
            list(
                list_for_each_entry_reverse(
                    "struct drgn_test_list_entry", self.empty, "node"
                )
            ),
            [],
        )
        self.assertEqual(
            list(
                list_for_each_entry_reverse(
                    "struct drgn_test_list_entry", self.full, "node"
                )
            ),
            [self.entry(i) for i in range(self.num_entries - 1, -1, -1)],
        )
        self.assertEqual(
            list(
                list_for_each_entry_reverse(
                    "struct drgn_test_list_entry", self.singular, "node"
                )
            ),
            [self.singular_entry],
        )

    def test_validate_list(self):
        for head in (self.empty, self.full, self.singular):
            validate_list(head)
        self.assertRaises(ValidationError, validate_list, self.corrupted)

    def test_validate_list_for_each(self):
        for head in (self.empty, self.full, self.singular):
            self.assertEqual(
                list(validate_list_for_each(head)), list(list_for_each(head))
            )
        self.assertRaises(
            ValidationError,
            collections.deque,
            validate_list_for_each(self.corrupted),
            0,
        )

    def test_validate_list_for_each_entry(self):
        for head in (self.empty, self.full, self.singular):
            self.assertEqual(
                list(
                    validate_list_for_each_entry(
                        "struct drgn_test_list_entry", head, "node"
                    )
                ),
                list(list_for_each_entry("struct drgn_test_list_entry", head, "node")),
            )
        self.assertRaises(
            ValidationError,
            collections.deque,
            validate_list_for_each_entry(
                "struct drgn_test_list_entry", self.corrupted, "node"
            ),
            0,
        )


@skip_unless_have_test_kmod
class TestHlist(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        cls.empty = cls.prog["drgn_test_empty_hlist"].address_of_()
        cls.full = cls.prog["drgn_test_full_hlist"].address_of_()
        cls.entries = cls.prog["drgn_test_hlist_entries"]
        cls.num_entries = 3

    def node(self, n):
        return self.entries[n].node.address_of_()

    def entry(self, n):
        return self.entries[n].address_of_()

    def test_hlist_empty(self):
        self.assertTrue(hlist_empty(self.empty))
        self.assertFalse(hlist_empty(self.full))

    def test_hlist_for_each(self):
        self.assertEqual(list(hlist_for_each(self.empty)), [])
        self.assertEqual(
            list(hlist_for_each(self.full)),
            [self.node(i) for i in range(self.num_entries)],
        )

    def test_hlist_for_each_entry(self):
        self.assertEqual(
            list(
                hlist_for_each_entry("struct drgn_test_hlist_entry", self.empty, "node")
            ),
            [],
        )
        self.assertEqual(
            list(
                hlist_for_each_entry("struct drgn_test_hlist_entry", self.full, "node")
            ),
            [self.entry(i) for i in range(self.num_entries)],
        )
