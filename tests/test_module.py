# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

from drgn import (
    ExtraModule,
    MainModule,
    ModuleFileStatus,
    Program,
    RelocatableModule,
    SharedLibraryModule,
    VdsoModule,
)
from tests import TestCase


class IntWrapper:
    def __init__(self, value):
        self._value = value

    def __index__(self):
        return self._value


class TestModule(TestCase):
    def _test_module_init_common(self, module):
        self.assertIsNone(module.address_range)
        self.assertIsNone(module.build_id)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertIsNone(module.loaded_file_bias)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)
        self.assertIsNone(module.debug_file_bias)
        self.assertIsNone(module.supplementary_debug_file_kind)
        self.assertIsNone(module.supplementary_debug_file_path)

    def test_main_module(self):
        prog = Program()

        self.assertRaises(LookupError, prog.main_module)
        self.assertRaises(LookupError, prog.main_module, "/foo/bar")

        module = prog.main_module("/foo/bar", create=True)
        self.assertIsInstance(module, MainModule)

        self.assertEqual(prog.main_module(), module)
        self.assertEqual(prog.main_module(create=False), module)
        self.assertEqual(prog.main_module("/foo/bar"), module)
        self.assertEqual(prog.main_module(b"/foo/bar"), module)
        self.assertEqual(prog.main_module(Path("/foo/bar")), module)
        self.assertEqual(prog.main_module("/foo/bar", create=True), module)

        self.assertRaises(LookupError, prog.main_module, "/foo/baz")
        self.assertRaises(LookupError, prog.main_module, "/foo/baz", create=True)

        self.assertIs(module.prog, prog)
        self.assertEqual(module.name, "/foo/bar")
        self._test_module_init_common(module)

    def test_main_module_invalid(self):
        prog = Program()
        self.assertRaises(TypeError, prog.main_module, None)
        self.assertRaises(TypeError, prog.main_module, create=True)
        self.assertRaises(TypeError, prog.main_module, "/foo/bar", True)

    def test_shared_library_module(self):
        prog = Program()

        self.assertRaises(
            LookupError, prog.shared_library_module, "/foo/bar", 0x10000000
        )

        module = prog.shared_library_module("/foo/bar", 0x10000000, create=True)
        self.assertIsInstance(module, SharedLibraryModule)

        self.assertEqual(prog.shared_library_module("/foo/bar", 0x10000000), module)
        self.assertEqual(prog.shared_library_module(b"/foo/bar", 0x10000000), module)
        self.assertEqual(
            prog.shared_library_module(Path("/foo/bar"), IntWrapper(0x10000000)), module
        )
        self.assertEqual(
            prog.shared_library_module("/foo/bar", 0x10000000, create=True), module
        )

        self.assertRaises(
            LookupError, prog.shared_library_module, "/foo/bar", 0x20000000
        )
        self.assertRaises(
            LookupError, prog.shared_library_module, "/foo/baz", 0x10000000
        )

        self.assertNotEqual(
            prog.shared_library_module("/foo/bar", 0x20000000, create=True), module
        )
        self.assertNotEqual(
            prog.shared_library_module("/foo/baz", 0x10000000, create=True), module
        )
        self.assertNotEqual(
            prog.vdso_module("/foo/bar", 0x10000000, create=True), module
        )

        self.assertIs(module.prog, prog)
        self.assertEqual(module.name, "/foo/bar")
        self.assertEqual(module.dynamic_address, 0x10000000)
        self._test_module_init_common(module)

    def test_shared_library_module_invalid(self):
        prog = Program()
        self.assertRaises(TypeError, prog.shared_library_module)
        self.assertRaises(TypeError, prog.shared_library_module, "/foo/bar")
        self.assertRaises(TypeError, prog.shared_library_module, "/foo/bar", None)
        self.assertRaises(TypeError, prog.shared_library_module, None, 0)
        self.assertRaises(
            TypeError, prog.shared_library_module, "/foo/bar", 0x10000000, True
        )

    def test_vdso_module(self):
        prog = Program()

        self.assertRaises(LookupError, prog.vdso_module, "/foo/bar", 0x10000000)

        module = prog.vdso_module("/foo/bar", 0x10000000, create=True)
        self.assertIsInstance(module, VdsoModule)

        self.assertEqual(prog.vdso_module("/foo/bar", 0x10000000), module)
        self.assertEqual(prog.vdso_module(b"/foo/bar", 0x10000000), module)
        self.assertEqual(
            prog.vdso_module(Path("/foo/bar"), IntWrapper(0x10000000)), module
        )
        self.assertEqual(prog.vdso_module("/foo/bar", 0x10000000, create=True), module)

        self.assertRaises(LookupError, prog.vdso_module, "/foo/bar", 0x20000000)
        self.assertRaises(LookupError, prog.vdso_module, "/foo/baz", 0x10000000)

        self.assertNotEqual(
            prog.vdso_module("/foo/bar", 0x20000000, create=True), module
        )
        self.assertNotEqual(
            prog.vdso_module("/foo/baz", 0x10000000, create=True), module
        )
        self.assertNotEqual(
            prog.shared_library_module("/foo/bar", 0x10000000, create=True), module
        )

        self.assertIs(module.prog, prog)
        self.assertEqual(module.name, "/foo/bar")
        self.assertEqual(module.dynamic_address, 0x10000000)
        self._test_module_init_common(module)

    def test_vdso_module_invalid(self):
        prog = Program()
        self.assertRaises(TypeError, prog.vdso_module)
        self.assertRaises(TypeError, prog.vdso_module, "/foo/bar")
        self.assertRaises(TypeError, prog.vdso_module, "/foo/bar", None)
        self.assertRaises(TypeError, prog.vdso_module, None, 0)
        self.assertRaises(TypeError, prog.vdso_module, "/foo/bar", 0x10000000, True)

    def test_relocatable_module(self):
        prog = Program()

        self.assertRaises(LookupError, prog.relocatable_module, "/foo/bar", 0x10000000)

        module = prog.relocatable_module("/foo/bar", 0x10000000, create=True)
        self.assertIsInstance(module, RelocatableModule)

        self.assertEqual(prog.relocatable_module("/foo/bar", 0x10000000), module)
        self.assertEqual(prog.relocatable_module(b"/foo/bar", 0x10000000), module)
        self.assertEqual(
            prog.relocatable_module(Path("/foo/bar"), IntWrapper(0x10000000)), module
        )
        self.assertEqual(
            prog.relocatable_module("/foo/bar", 0x10000000, create=True), module
        )

        self.assertRaises(LookupError, prog.relocatable_module, "/foo/bar", 0x20000000)
        self.assertRaises(LookupError, prog.relocatable_module, "/foo/baz", 0x10000000)

        self.assertNotEqual(
            prog.relocatable_module("/foo/bar", 0x20000000, create=True), module
        )
        self.assertNotEqual(
            prog.relocatable_module("/foo/baz", 0x10000000, create=True), module
        )
        self.assertNotEqual(
            prog.shared_library_module("/foo/bar", 0x10000000, create=True), module
        )

        self.assertIs(module.prog, prog)
        self.assertEqual(module.name, "/foo/bar")
        self.assertEqual(module.address, 0x10000000)
        self._test_module_init_common(module)

    def test_section_addresses(self):
        prog = Program()
        module = prog.relocatable_module("/foo/bar", 0x10000000, create=True)

        self.assertNotIn(".text", module.section_addresses)
        self.assertNotIn(1, module.section_addresses)

        with self.assertRaises(KeyError):
            module.section_addresses[".text"]
        with self.assertRaises(KeyError):
            module.section_addresses[1]

        with self.assertRaises(KeyError):
            del module.section_addresses[".text"]
        with self.assertRaises(KeyError):
            del module.section_addresses[1]

        module.section_addresses[".text"] = 0x10000000
        self.assertIn(".text", module.section_addresses)
        self.assertEqual(module.section_addresses[".text"], 0x10000000)

        self.assertEqual(len(module.section_addresses), 1)
        self.assertCountEqual(list(module.section_addresses), [".text"])
        self.assertCountEqual(list(module.section_addresses.keys()), [".text"])
        self.assertCountEqual(list(module.section_addresses.values()), [0x10000000])
        self.assertCountEqual(
            list(module.section_addresses.items()), [(".text", 0x10000000)]
        )

        module.section_addresses[".data"] = 0x10001000

        self.assertEqual(len(module.section_addresses), 2)
        self.assertCountEqual(list(module.section_addresses), [".text", ".data"])
        self.assertCountEqual(list(module.section_addresses.keys()), [".text", ".data"])
        self.assertCountEqual(
            list(module.section_addresses.values()), [0x10000000, 0x10001000]
        )
        self.assertCountEqual(
            list(module.section_addresses.items()),
            [(".text", 0x10000000), (".data", 0x10001000)],
        )

        del module.section_addresses[".data"]

        self.assertEqual(len(module.section_addresses), 1)
        self.assertCountEqual(list(module.section_addresses), [".text"])
        self.assertCountEqual(list(module.section_addresses.keys()), [".text"])
        self.assertCountEqual(list(module.section_addresses.values()), [0x10000000])
        self.assertCountEqual(
            list(module.section_addresses.items()), [(".text", 0x10000000)]
        )

    def test_relocatable_module_invalid(self):
        prog = Program()
        self.assertRaises(TypeError, prog.relocatable_module)
        self.assertRaises(TypeError, prog.relocatable_module, "/foo/bar")
        self.assertRaises(TypeError, prog.relocatable_module, "/foo/bar", None)
        self.assertRaises(TypeError, prog.relocatable_module, None, 0)
        self.assertRaises(
            TypeError, prog.relocatable_module, "/foo/bar", 0x10000000, True
        )

    def test_extra_module(self):
        prog = Program()

        self.assertRaises(LookupError, prog.extra_module, "/foo/bar", 1234)

        module = prog.extra_module("/foo/bar", 1234, create=True)
        self.assertIsInstance(module, ExtraModule)

        self.assertEqual(prog.extra_module("/foo/bar", 1234), module)
        self.assertEqual(prog.extra_module(b"/foo/bar", 1234), module)
        self.assertEqual(prog.extra_module(Path("/foo/bar"), IntWrapper(1234)), module)
        self.assertEqual(prog.extra_module("/foo/bar", 1234, create=True), module)

        self.assertRaises(LookupError, prog.extra_module, "/foo/bar", 5678)
        self.assertRaises(LookupError, prog.extra_module, "/foo/baz", 1234)

        self.assertNotEqual(prog.extra_module("/foo/bar", 5678, create=True), module)
        self.assertNotEqual(prog.extra_module("/foo/baz", 1234, create=True), module)
        self.assertNotEqual(
            prog.shared_library_module("/foo/bar", 1234, create=True), module
        )
        self.assertEqual(prog.extra_module("/foo/bar", create=True).id, 0)

        self.assertIs(module.prog, prog)
        self.assertEqual(module.name, "/foo/bar")
        self.assertEqual(module.id, 1234)
        self._test_module_init_common(module)

    def test_extra_module_invalid(self):
        prog = Program()
        self.assertRaises(TypeError, prog.extra_module)
        self.assertRaises(TypeError, prog.extra_module, "/foo/bar", None)
        self.assertRaises(TypeError, prog.extra_module, None, 0)
        self.assertRaises(TypeError, prog.extra_module, "/foo/bar", 1234, True)

    def test_address_range(self):
        module = Program().extra_module("/foo/bar", create=True)

        module.address_range = (0x10000000, 0x10010000)
        self.assertEqual(module.address_range, (0x10000000, 0x10010000))

        module.address_range = (0x20000000, 0x20020000)
        self.assertEqual(module.address_range, (0x20000000, 0x20020000))

        module.address_range = None
        self.assertIsNone(module.address_range)

        module.address_range = None
        self.assertIsNone(module.address_range)

    def test_address_range_empty(self):
        module = Program().extra_module("/foo/bar", create=True)

        module.address_range = (0, 0)
        self.assertEqual(module.address_range, (0, 0))

    def test_address_range_type_error(self):
        module = Program().extra_module("/foo/bar", create=True)

        with self.assertRaises(TypeError):
            module.address_range = 1

        with self.assertRaises(TypeError):
            module.address_range = (1,)

        with self.assertRaises(TypeError):
            module.address_range = ("foo", 1)

        with self.assertRaises(TypeError):
            module.address_range = (1, "bar")

    def test_address_range_invalid(self):
        module = Program().extra_module("/foo/bar", create=True)

        with self.assertRaisesRegex(ValueError, "invalid module address range"):
            module.address_range = (0x10010000, 0x10000000)

        with self.assertRaisesRegex(ValueError, "invalid module address range"):
            module.address_range = (1, 1)

        with self.assertRaisesRegex(ValueError, "invalid module address range"):
            module.address_range = (2**64 - 1, 1)

        with self.assertRaisesRegex(ValueError, "invalid module address range"):
            module.address_range = (2**64 - 1, 2**64 - 1)

    def test_address_range_del(self):
        module = Program().extra_module("/foo/bar", create=True)
        with self.assertRaises(AttributeError):
            del module.address_range

    def test_build_id(self):
        module = Program().extra_module("/foo/bar", create=True)

        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

        module.build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"
        self.assertEqual(module.build_id, b"\xfe\xdc\xba\x98\x76\x54\x32\x10")

        module.build_id = None
        self.assertIsNone(module.build_id)

        module.build_id = None
        self.assertIsNone(module.build_id)

    def test_build_id_type_error(self):
        module = Program().extra_module("/foo/bar", create=True)
        with self.assertRaises(TypeError):
            module.build_id = "abcd"

    def test_build_id_invalid_empty(self):
        module = Program().extra_module("/foo/bar", create=True)
        with self.assertRaisesRegex(ValueError, "build ID cannot be empty"):
            module.build_id = b""

    def test_build_id_del(self):
        module = Program().extra_module("/foo/bar", create=True)
        with self.assertRaises(AttributeError):
            del module.build_id

    def test_find_by_name(self):
        prog = Program()
        self.assertRaises(LookupError, prog.module, "foo")

        module1 = prog.extra_module("foo", create=True)
        self.assertEqual(prog.module("foo"), module1)

        module2 = prog.main_module("foo", create=True)
        self.assertIn(prog.module("foo"), (module1, module2))

        self.assertRaises(LookupError, prog.module, "bar")

    def test_find_by_address(self):
        prog = Program()
        module1 = prog.extra_module("/foo/bar", create=True)
        module1.address_range = (0x10000000, 0x10010000)
        module2 = prog.extra_module("/asdf/jkl", create=True)
        module2.address_range = (0x20000000, 0x20020000)

        self.assertRaises(LookupError, prog.module, 0x0FFFFFFF)
        self.assertEqual(prog.module(0x10000000), module1)
        self.assertEqual(prog.module(0x10000001), module1)
        self.assertEqual(prog.module(0x1000FFFF), module1)
        self.assertRaises(LookupError, prog.module, 0x10010000)

        self.assertRaises(LookupError, prog.module, 0x1FFFFFFF)
        self.assertEqual(prog.module(0x20000000), module2)
        self.assertEqual(prog.module(0x20000001), module2)
        self.assertEqual(prog.module(0x2001FFFF), module2)
        self.assertRaises(LookupError, prog.module, 0x20020000)

    # Test all of the state transitions that we can without setting a file.
    def _test_file_status(self, which):
        module = Program().extra_module("/foo/bar", create=True)

        status_attr = which + "_file_status"
        wants_file = getattr(module, f"wants_{which}_file")

        self.assertRaises(TypeError, setattr, module, status_attr, 1)

        setattr(module, status_attr, ModuleFileStatus.WANT)
        self.assertEqual(getattr(module, status_attr), ModuleFileStatus.WANT)
        self.assertEqual(wants_file(), True)
        for status in set(ModuleFileStatus) - {
            ModuleFileStatus.WANT,
            ModuleFileStatus.DONT_WANT,
            ModuleFileStatus.DONT_NEED,
        }:
            with self.subTest(from_=ModuleFileStatus.WANT, to=status):
                self.assertRaises(ValueError, setattr, module, status_attr, status)
                self.assertEqual(getattr(module, status_attr), ModuleFileStatus.WANT)

        setattr(module, status_attr, ModuleFileStatus.DONT_WANT)
        self.assertEqual(getattr(module, status_attr), ModuleFileStatus.DONT_WANT)
        self.assertEqual(wants_file(), False)
        for status in set(ModuleFileStatus) - {
            ModuleFileStatus.WANT,
            ModuleFileStatus.DONT_WANT,
            ModuleFileStatus.DONT_NEED,
        }:
            with self.subTest(from_=ModuleFileStatus.DONT_WANT, to=status):
                self.assertRaises(ValueError, setattr, module, status_attr, status)
                self.assertEqual(
                    getattr(module, status_attr), ModuleFileStatus.DONT_WANT
                )

        setattr(module, status_attr, ModuleFileStatus.DONT_NEED)
        self.assertEqual(getattr(module, status_attr), ModuleFileStatus.DONT_NEED)
        self.assertEqual(wants_file(), False)
        for status in set(ModuleFileStatus) - {
            ModuleFileStatus.WANT,
            ModuleFileStatus.DONT_WANT,
            ModuleFileStatus.DONT_NEED,
        }:
            with self.subTest(from_=ModuleFileStatus.DONT_NEED, to=status):
                self.assertRaises(ValueError, setattr, module, status_attr, status)
                self.assertEqual(
                    getattr(module, status_attr), ModuleFileStatus.DONT_NEED
                )

        setattr(module, status_attr, ModuleFileStatus.DONT_WANT)
        self.assertEqual(getattr(module, status_attr), ModuleFileStatus.DONT_WANT)

        setattr(module, status_attr, ModuleFileStatus.WANT)
        self.assertEqual(getattr(module, status_attr), ModuleFileStatus.WANT)

        setattr(module, status_attr, ModuleFileStatus.DONT_NEED)
        self.assertEqual(getattr(module, status_attr), ModuleFileStatus.DONT_NEED)

        setattr(module, status_attr, ModuleFileStatus.WANT)
        self.assertEqual(getattr(module, status_attr), ModuleFileStatus.WANT)

        self.assertRaises(AttributeError, delattr, module, status_attr)

    def test_loaded_file_status(self):
        self._test_file_status("loaded")

    def test_debug_file_status(self):
        self._test_file_status("debug")


class TestCreatedModules(TestCase):
    def test_empty(self):
        self.assertEqual(list(Program().modules()), [])

    def test_one(self):
        module = Program().extra_module("/foo/bar", create=True)
        self.assertEqual(list(module.prog.modules()), [module])

    def test_multiple(self):
        prog = Program()
        modules = [
            prog.extra_module("/foo/bar", create=True),
            prog.extra_module("/asdf/jkl", create=True),
            prog.extra_module("/123/456", create=True),
        ]
        self.assertCountEqual(list(prog.modules()), modules)

    def test_same_name(self):
        prog = Program()
        modules = [
            prog.extra_module("foo", id=0, create=True),
            prog.main_module("foo", create=True),
        ]
        actual = list(prog.modules())
        self.assertCountEqual(actual, modules)
        self.assertEqual(actual[0], prog.main_module())

        modules.append(prog.extra_module("foo", id=1, create=True))
        actual = list(prog.modules())
        self.assertCountEqual(actual, modules)
        self.assertEqual(actual[0], prog.main_module())

    def test_change_during_iteration(self):
        prog = Program()
        prog.extra_module("/foo/bar", create=True)
        with self.assertRaisesRegex(Exception, "modules changed during iteration"):
            for module in prog.modules():
                prog.extra_module("/asdf/jkl", create=True)
                prog.extra_module("/123/456", create=True)
