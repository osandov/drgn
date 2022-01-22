# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import unittest

from drgn import Object, container_of
from drgn.helpers.linux.list import (
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
)
from tests.helpers.linux import LinuxHelperTestCase


class ListTestCaseMixin:
    @classmethod
    def _node_to_key(cls, node):
        entry = container_of(node, cls.ENTRY_TYPE, cls.NODE_MEMBER)
        return cls._entry_to_key(entry)

    def test_list_for_each(self):
        self.assertEqual(
            [self._node_to_key(node) for node in list_for_each(self.list)], self.keys
        )

    def test_list_for_each_reverse(self):
        self.assertEqual(
            [self._node_to_key(node) for node in list_for_each_reverse(self.list)],
            list(reversed(self.keys)),
        )

    def test_list_for_each_entry(self):
        self.assertEqual(
            [
                self._entry_to_key(entry)
                for entry in list_for_each_entry(
                    self.ENTRY_TYPE, self.list, self.NODE_MEMBER
                )
            ],
            self.keys,
        )

    def test_list_for_each_reverse_entry(self):
        self.assertEqual(
            [
                self._entry_to_key(entry)
                for entry in list_for_each_entry_reverse(
                    self.ENTRY_TYPE, self.list, self.NODE_MEMBER
                )
            ],
            list(reversed(self.keys)),
        )


class TestListNotEmpty(LinuxHelperTestCase, ListTestCaseMixin):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.keys = []
        try:
            with open("/proc/modules", "rb") as f:
                for line in f:
                    cls.keys.append(line.partition(b" ")[0])
        except FileNotFoundError:
            pass
        if not cls.keys:
            raise unittest.SkipTest("no modules loaded")
        cls.list = cls.prog["modules"].address_of_()
        cls.ENTRY_TYPE = cls.prog.type("struct module")
        cls.NODE_MEMBER = "list"

    @classmethod
    def _entry_to_key(cls, entry):
        return entry.name.string_()

    def test_list_empty(self):
        self.assertFalse(list_empty(self.list))

    def test_list_is_singular(self):
        self.assertEqual(list_is_singular(self.list), len(self.keys) == 1)

    def test_list_first_entry(self):
        self.assertEqual(
            self._entry_to_key(
                list_first_entry(self.list, self.ENTRY_TYPE, self.NODE_MEMBER)
            ),
            self.keys[0],
        )

    def test_list_first_entry_or_null(self):
        self.assertEqual(
            self._entry_to_key(
                list_first_entry_or_null(self.list, self.ENTRY_TYPE, self.NODE_MEMBER)
            ),
            self.keys[0],
        )

    def test_list_last_entry(self):
        self.assertEqual(
            self._entry_to_key(
                list_last_entry(self.list, self.ENTRY_TYPE, self.NODE_MEMBER)
            ),
            self.keys[-1],
        )

    def test_list_next_entry(self):
        entry = list_first_entry(self.list, self.ENTRY_TYPE, self.NODE_MEMBER)
        keys = []
        while True:
            keys.append(self._entry_to_key(entry))
            if getattr(entry, self.NODE_MEMBER).next == self.list:
                break
            entry = list_next_entry(entry, self.NODE_MEMBER)
        self.assertEqual(keys, self.keys)

    def test_list_prev_entry(self):
        entry = list_last_entry(self.list, self.ENTRY_TYPE, self.NODE_MEMBER)
        keys = []
        while True:
            keys.append(self._entry_to_key(entry))
            if getattr(entry, self.NODE_MEMBER).prev == self.list:
                break
            entry = list_prev_entry(entry, self.NODE_MEMBER)
        self.assertEqual(keys, list(reversed(self.keys)))


@unittest.skipIf(Path("/proc/vmcore").exists(), "list is not empty in kdump kernel")
class TestListEmpty(LinuxHelperTestCase, ListTestCaseMixin):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.keys = []
        try:
            # In the kdump kernel, this list is populated with chunks of memory
            # in the vmcore file. We can assume that it's empty otherwise.
            cls.list = cls.prog["vmcore_list"].address_of_()
        except LookupError:
            # If other definitions from the same file exist, then maybe
            # vmcore_list was removed or renamed. Fail hard so we update the
            # test.
            if "proc_vmcore" in cls.prog or "vmcore_init" in cls.prog:
                raise
            raise unittest.SkipTest("kernel not built with CONFIG_PROC_VMCORE")
        cls.ENTRY_TYPE = cls.prog.type("struct vmcore")
        cls.NODE_MEMBER = "list"

    @classmethod
    def _entry_to_key(cls, entry):
        return entry.paddr.value_()

    def test_list_empty(self):
        self.assertTrue(list_empty(self.list))

    def test_list_is_singular(self):
        self.assertFalse(list_is_singular(self.list))

    def test_list_first_entry_or_null(self):
        self.assertIdentical(
            list_first_entry_or_null(self.list, self.ENTRY_TYPE, self.NODE_MEMBER),
            Object(self.prog, self.prog.pointer_type(self.ENTRY_TYPE), 0),
        )
