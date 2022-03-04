# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import re
import signal

from drgn import Object, container_of
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.rbtree import (
    rb_find,
    rb_first,
    rb_last,
    rb_next,
    rb_prev,
    rbtree_inorder_for_each,
    rbtree_inorder_for_each_entry,
)
from tests.linux_kernel import LinuxKernelTestCase, fork_and_pause


class TestRbtree(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        # It'd be nice to just use addClassCleanup(), but that was added in
        # Python 3.8.
        cls.__cleanups = []
        try:
            super().setUpClass()

            pid = fork_and_pause()
            cls.__cleanups.append((os.waitpid, pid, 0))
            cls.__cleanups.append((os.kill, pid, signal.SIGKILL))

            cls.keys = []
            with open(f"/proc/{pid}/maps") as f:
                for line in f:
                    if line.endswith("[vsyscall]\n"):
                        # This isn't included in the VMA tree.
                        continue
                    match = re.match(r"([0-9a-f]+)-([0-9a-f]+)", line)
                    cls.keys.append((int(match.group(1), 16), int(match.group(2), 16)))

            cls.rb_root = find_task(cls.prog, pid).mm.mm_rb.address_of_()
            cls.ENTRY_TYPE = cls.prog.type("struct vm_area_struct")
            cls.NODE_MEMBER = "vm_rb"
        except:
            for cleanup in reversed(cls.__cleanups):
                cleanup[0](*cleanup[1:])
            raise

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        for cleanup in reversed(cls.__cleanups):
            cleanup[0](*cleanup[1:])

    @classmethod
    def _entry_to_key(cls, entry):
        return (entry.vm_start.value_(), entry.vm_end.value_())

    @classmethod
    def _node_to_key(cls, node):
        entry = container_of(node, cls.ENTRY_TYPE, cls.NODE_MEMBER)
        return cls._entry_to_key(entry)

    @classmethod
    def _cmp_key_to_entry(cls, key, entry):
        entry_key = cls._entry_to_key(entry)
        if key < entry_key:
            return -1
        elif key > entry_key:
            return 1
        else:
            return 0

    def test_rb_first(self):
        self.assertEqual(
            self._node_to_key(rb_first(self.rb_root)),
            self.keys[0],
        )

    def test_rb_last(self):
        self.assertEqual(
            self._node_to_key(rb_last(self.rb_root)),
            self.keys[-1],
        )

    # We don't have a good way to test rb_parent() explicitly, but it's used
    # internally by rb_next() and rb_prev(), so it still gets some coverage.

    def test_rb_next(self):
        keys = []
        node = rb_first(self.rb_root)
        while node:
            keys.append(self._node_to_key(node))
            node = rb_next(node)
        self.assertEqual(keys, self.keys)

    def test_rb_prev(self):
        keys = []
        node = rb_last(self.rb_root)
        while node:
            keys.append(self._node_to_key(node))
            node = rb_prev(node)
        self.assertEqual(keys, list(reversed(self.keys)))

    def test_rbtree_inorder_for_each(self):
        self.assertEqual(
            [self._node_to_key(node) for node in rbtree_inorder_for_each(self.rb_root)],
            self.keys,
        )

    def test_rbtree_inorder_for_each_entry(self):
        self.assertEqual(
            [
                self._entry_to_key(entry)
                for entry in rbtree_inorder_for_each_entry(
                    self.ENTRY_TYPE, self.rb_root, self.NODE_MEMBER
                )
            ],
            self.keys,
        )

    def test_rb_find(self):
        for key in self.keys:
            self.assertEqual(
                self._entry_to_key(
                    rb_find(
                        self.ENTRY_TYPE,
                        self.rb_root,
                        self.NODE_MEMBER,
                        key,
                        self._cmp_key_to_entry,
                    )
                ),
                key,
            )

    def test_rb_find_not_found(self):
        self.assertIdentical(
            rb_find(
                self.ENTRY_TYPE,
                self.rb_root,
                self.NODE_MEMBER,
                None,
                lambda key, entry: -1,
            ),
            Object(self.prog, self.prog.pointer_type(self.ENTRY_TYPE), 0),
        )
