# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import re
import signal

from drgn import NULL
from drgn.helpers.linux.rbtree import (
    RB_EMPTY_NODE,
    RB_EMPTY_ROOT,
    rb_find,
    rb_first,
    rb_last,
    rb_next,
    rb_parent,
    rb_prev,
    rbtree_inorder_for_each,
    rbtree_inorder_for_each_entry,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestRbtree(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = cls.prog["drgn_test_rb_root"].address_of_()
        cls.entries = cls.prog["drgn_test_rb_entries"]
        cls.num_entries = 4

    def node(self, n):
        return self.entries[n].node.address_of_()

    def entry(self, n):
        return self.entries[n].address_of_()

    def test_RB_EMPTY_ROOT(self):
        self.assertTrue(
            RB_EMPTY_ROOT(self.prog["drgn_test_empty_rb_root"].address_of_())
        )
        self.assertFalse(RB_EMPTY_ROOT(self.root))

    def test_RB_EMPTY_NODE(self):
        self.assertTrue(
            RB_EMPTY_NODE(self.prog["drgn_test_empty_rb_node"].address_of_())
        )
        self.assertFalse(RB_EMPTY_NODE(self.node(0)))

    def test_rb_parent(self):
        if self.root.rb_node.rb_left:
            self.assertEqual(rb_parent(self.root.rb_node.rb_left), self.root.rb_node)
        if self.root.rb_node.rb_right:
            self.assertEqual(rb_parent(self.root.rb_node.rb_right), self.root.rb_node)

    def test_rb_first(self):
        self.assertEqual(rb_first(self.root), self.node(0))

    def test_rb_last(self):
        self.assertEqual(rb_last(self.root), self.node(self.num_entries - 1))

    def test_rb_next(self):
        for i in range(self.num_entries - 1):
            self.assertEqual(rb_next(self.node(i)), self.node(i + 1))
        self.assertEqual(
            rb_next(self.node(self.num_entries - 1)),
            NULL(self.prog, "struct rb_node *"),
        )

    def test_rb_prev(self):
        for i in range(1, self.num_entries):
            self.assertEqual(rb_prev(self.node(i)), self.node(i - 1))
        self.assertEqual(rb_prev(self.node(0)), NULL(self.prog, "struct rb_node *"))

    def test_rbtree_inorder_for_each(self):
        self.assertEqual(
            list(rbtree_inorder_for_each(self.root)),
            [self.node(i) for i in range(self.num_entries)],
        )

    def test_rbtree_inorder_for_each_entry(self):
        self.assertEqual(
            list(
                rbtree_inorder_for_each_entry(
                    "struct drgn_test_rb_entry", self.root, "node"
                )
            ),
            [self.entry(i) for i in range(self.num_entries)],
        )

    def test_rb_find(self):
        def cmp(key, obj):
            value = obj.value.value_()
            return key - value

        for i in range(self.num_entries):
            self.assertEqual(
                rb_find("struct drgn_test_rb_entry", self.root, "node", i, cmp),
                self.entry(i),
            )
        self.assertEqual(
            rb_find(
                "struct drgn_test_rb_entry", self.root, "node", self.num_entries, cmp
            ),
            NULL(self.prog, "struct drgn_test_rb_entry *"),
        )
