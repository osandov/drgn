# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux import (
    plist_first_entry,
    plist_for_each,
    plist_for_each_entry,
    plist_head_empty,
    plist_last_entry,
    plist_node_empty,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestPlist(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.empty = cls.prog["drgn_test_empty_plist"].address_of_()
        cls.full = cls.prog["drgn_test_full_plist"].address_of_()
        cls.entries = cls.prog["drgn_test_plist_entries"]
        cls.num_entries = 3

    def node(self, n):
        return self.entries[n].node.address_of_()

    def entry(self, n):
        return self.entries[n].address_of_()

    def test_plist_head_empty(self):
        self.assertTrue(plist_head_empty(self.empty))
        self.assertFalse(plist_head_empty(self.full))

    def test_plist_node_empty(self):
        self.assertTrue(
            plist_node_empty(self.prog["drgn_test_empty_plist_node"].address_of_())
        )
        self.assertFalse(plist_node_empty(self.node(0)))

    def test_plist_first_entry(self):
        self.assertEqual(
            plist_first_entry(self.full, "struct drgn_test_plist_entry", "node"),
            self.entry(0),
        )

    def test_plist_last_entry(self):
        self.assertEqual(
            plist_last_entry(self.full, "struct drgn_test_plist_entry", "node"),
            self.entry(self.num_entries - 1),
        )

    def test_plist_for_each(self):
        self.assertEqual(list(plist_for_each(self.empty)), [])
        self.assertEqual(
            list(plist_for_each(self.full)),
            [self.node(i) for i in range(self.num_entries)],
        )

    def test_plist_for_each_entry(self):
        self.assertEqual(
            list(
                plist_for_each_entry("struct drgn_test_plist_entry", self.empty, "node")
            ),
            [],
        )
        self.assertEqual(
            list(
                plist_for_each_entry("struct drgn_test_plist_entry", self.full, "node")
            ),
            [self.entry(i) for i in range(self.num_entries)],
        )
