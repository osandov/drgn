# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import DebugInfoOptions, KmodSearchMethod, Program
from tests import TestCase


class TestDebugInfoOptions(TestCase):
    def test_list_default(self):
        self.assertEqual(DebugInfoOptions().directories, ("/usr/lib/debug",))

    def test_list_init(self):
        self.assertEqual(
            DebugInfoOptions(directories=["foo", "bar"]).directories, ("foo", "bar")
        )
        self.assertRaises(TypeError, DebugInfoOptions, directories=None)

    def test_list_copy(self):
        self.assertEqual(
            DebugInfoOptions(DebugInfoOptions(directories=["foo", "bar"])).directories,
            ("foo", "bar"),
        )

    def test_list_set(self):
        options = DebugInfoOptions()
        options.directories = ("foo", "bar")
        self.assertEqual(options.directories, ("foo", "bar"))
        with self.assertRaises(TypeError):
            DebugInfoOptions().directories = None

    def test_directories_empty_string(self):
        with self.assertRaises(ValueError):
            DebugInfoOptions().directories = ("",)

    def test_bool_default(self):
        self.assertIs(DebugInfoOptions().try_build_id, True)

    def test_bool_init(self):
        self.assertIs(DebugInfoOptions(try_build_id=False).try_build_id, False)

    def test_bool_copy(self):
        self.assertIs(
            DebugInfoOptions(DebugInfoOptions(try_build_id=False)).try_build_id, False
        )

    def test_bool_set(self):
        options = DebugInfoOptions()
        options.try_build_id = False
        self.assertIs(options.try_build_id, False)

    def test_enum_default(self):
        self.assertEqual(DebugInfoOptions().try_kmod, KmodSearchMethod.DEPMOD_OR_WALK)

    def test_enum_init(self):
        self.assertEqual(
            DebugInfoOptions(try_kmod=KmodSearchMethod.WALK).try_kmod,
            KmodSearchMethod.WALK,
        )
        self.assertRaises(TypeError, DebugInfoOptions, try_kmod=False)

    def test_enum_copy(self):
        self.assertEqual(
            DebugInfoOptions(
                DebugInfoOptions(try_kmod=KmodSearchMethod.DEPMOD)
            ).try_kmod,
            KmodSearchMethod.DEPMOD,
        )

    def test_enum_set(self):
        options = DebugInfoOptions()
        options.try_kmod = KmodSearchMethod.DEPMOD_AND_WALK
        self.assertEqual(options.try_kmod, KmodSearchMethod.DEPMOD_AND_WALK)
        with self.assertRaises(TypeError):
            options.try_kmod = False

    def test_del(self):
        with self.assertRaises(AttributeError):
            del DebugInfoOptions().directories

    def test_repr(self):
        self.assertIn("directories=()", repr(DebugInfoOptions(directories=())))


class TestProgramDebugInfoOptions(TestCase):
    def test_default(self):
        self.assertEqual(
            Program().debug_info_options.directories, DebugInfoOptions().directories
        )

    def test_assign(self):
        prog = Program()
        prog.debug_info_options.directories = ("foo", "bar")
        prog.debug_info_options = DebugInfoOptions(directories=("bar", "baz"))
        self.assertEqual(prog.debug_info_options.directories, ("bar", "baz"))

    def test_assign_list(self):
        prog = Program()
        prog.debug_info_options.directories = ("bar", "foo")
        self.assertEqual(prog.debug_info_options.directories, ("bar", "foo"))
