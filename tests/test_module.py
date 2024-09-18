# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
from pathlib import Path
import tempfile
import unittest
import unittest.mock

from _drgn_util.elf import ET, PT, SHF, SHT
from drgn import (
    ExtraModule,
    MainModule,
    ModuleFileStatus,
    Program,
    SharedLibraryModule,
    VdsoModule,
)
from tests import TestCase
from tests.dwarfwriter import compile_dwarf
from tests.elfwriter import ElfSection, create_elf_file
from tests.resources import get_resource


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

        self.assertRaises(LookupError, prog.find_main_module)

        module = prog.main_module("/foo/bar")
        self.assertIsInstance(module, MainModule)

        self.assertEqual(prog.find_main_module(), module)

        self.assertEqual(prog.main_module(b"/foo/bar"), module)
        self.assertEqual(prog.main_module(Path("/foo/bar")), module)
        self.assertEqual(prog.main_module("/baz"), module)  # TODO: document this

        self.assertIs(module.prog, prog)
        self.assertEqual(module.name, "/foo/bar")
        self._test_module_init_common(module)

    def test_main_module_invalid(self):
        prog = Program()
        self.assertRaises(TypeError, prog.main_module)
        self.assertRaises(TypeError, prog.main_module, None)

    def test_shared_library_module(self):
        prog = Program()

        self.assertRaises(
            LookupError, prog.find_shared_library_module, "/foo/bar", 0x10000000
        )

        module = prog.shared_library_module("/foo/bar", 0x10000000)
        self.assertIsInstance(module, SharedLibraryModule)

        self.assertEqual(
            prog.find_shared_library_module("/foo/bar", 0x10000000), module
        )
        self.assertRaises(
            LookupError, prog.find_shared_library_module, "/foo/bar", 0x20000000
        )

        self.assertEqual(prog.shared_library_module(b"/foo/bar", 0x10000000), module)
        self.assertEqual(
            prog.shared_library_module(Path("/foo/bar"), IntWrapper(0x10000000)), module
        )

        self.assertNotEqual(prog.shared_library_module("/foo/bar", 0x20000000), module)
        self.assertNotEqual(prog.shared_library_module("/foo/baz", 0x10000000), module)

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

    def test_vdso_module(self):
        prog = Program()

        self.assertRaises(LookupError, prog.find_vdso_module, "/foo/bar", 0x10000000)

        module = prog.vdso_module("/foo/bar", 0x10000000)
        self.assertIsInstance(module, VdsoModule)

        self.assertEqual(prog.find_vdso_module("/foo/bar", 0x10000000), module)
        self.assertRaises(LookupError, prog.find_vdso_module, "/foo/bar", 0x20000000)

        self.assertEqual(prog.vdso_module(b"/foo/bar", 0x10000000), module)
        self.assertEqual(
            prog.vdso_module(Path("/foo/bar"), IntWrapper(0x10000000)), module
        )

        self.assertNotEqual(prog.vdso_module("/foo/bar", 0x20000000), module)
        self.assertNotEqual(prog.vdso_module("/foo/baz", 0x10000000), module)
        self.assertNotEqual(prog.shared_library_module("/foo/bar", 0x10000000), module)

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

    # TODO: linux_kernel_loadable_module

    def test_extra_module(self):
        prog = Program()

        self.assertRaises(LookupError, prog.find_extra_module, "/foo/bar", 1234)

        module = prog.extra_module("/foo/bar", 1234)
        self.assertIsInstance(module, ExtraModule)

        self.assertEqual(prog.find_extra_module("/foo/bar", 1234), module)
        self.assertRaises(LookupError, prog.find_extra_module, "/foo/bar", 5678)

        self.assertEqual(prog.extra_module(b"/foo/bar", 1234), module)
        self.assertEqual(prog.extra_module(Path("/foo/bar"), IntWrapper(1234)), module)

        self.assertNotEqual(prog.extra_module("/foo/bar", 5678), module)
        self.assertNotEqual(prog.extra_module("/foo/baz", 1234), module)
        self.assertNotEqual(prog.shared_library_module("/foo/bar", 1234), module)

        self.assertIs(module.prog, prog)
        self.assertEqual(module.name, "/foo/bar")
        self.assertEqual(module.id, 1234)
        self._test_module_init_common(module)

    def test_extra_module_invalid(self):
        prog = Program()
        self.assertRaises(TypeError, prog.extra_module)
        self.assertRaises(TypeError, prog.extra_module, "/foo/bar")
        self.assertRaises(TypeError, prog.extra_module, "/foo/bar", None)
        self.assertRaises(TypeError, prog.extra_module, None, 0)

    def test_address_range(self):
        module = Program().extra_module("/foo/bar", 0)

        module.address_range = (0x10000000, 0x10010000)
        self.assertEqual(module.address_range, (0x10000000, 0x10010000))

        module.address_range = (0x20000000, 0x20020000)
        self.assertEqual(module.address_range, (0x20000000, 0x20020000))

        module.address_range = None
        self.assertIsNone(module.address_range)

        module.address_range = None
        self.assertIsNone(module.address_range)

    def test_address_range_empty(self):
        module = Program().extra_module("/foo/bar", 0)

        module.address_range = (0, 0)
        self.assertEqual(module.address_range, (0, 0))

    def test_address_range_type_error(self):
        module = Program().extra_module("/foo/bar", 0)

        with self.assertRaises(TypeError):
            module.address_range = 1

        with self.assertRaises(TypeError):
            module.address_range = (1,)

        with self.assertRaises(TypeError):
            module.address_range = ("foo", 1)

        with self.assertRaises(TypeError):
            module.address_range = (1, "bar")

    def test_address_range_invalid(self):
        module = Program().extra_module("/foo/bar", 0)

        with self.assertRaisesRegex(ValueError, "invalid module address range"):
            module.address_range = (0x10010000, 0x10000000)

        with self.assertRaisesRegex(ValueError, "invalid module address range"):
            module.address_range = (1, 1)

        with self.assertRaisesRegex(ValueError, "invalid module address range"):
            module.address_range = (2**64 - 1, 1)

        with self.assertRaisesRegex(ValueError, "invalid module address range"):
            module.address_range = (2**64 - 1, 2**64 - 1)

    def test_build_id(self):
        module = Program().extra_module("/foo/bar", 0)

        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

        module.build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"
        self.assertEqual(module.build_id, b"\xfe\xdc\xba\x98\x76\x54\x32\x10")

        module.build_id = None
        self.assertIsNone(module.build_id)

        module.build_id = None
        self.assertIsNone(module.build_id)

    def test_build_id_type_error(self):
        module = Program().extra_module("/foo/bar", 0)
        with self.assertRaises(TypeError):
            module.build_id = "abcd"

    def test_build_id_invalid_empty(self):
        module = Program().extra_module("/foo/bar", 0)
        with self.assertRaisesRegex(ValueError, "build ID cannot be empty"):
            module.build_id = b""


class TestCreatedModules(TestCase):
    def test_empty(self):
        self.assertEqual(list(Program().created_modules()), [])

    def test_one(self):
        module = Program().extra_module("/foo/bar", 0)
        self.assertEqual(list(module.prog.created_modules()), [module])

    def test_multiple(self):
        prog = Program()
        modules = [
            prog.extra_module("/foo/bar", 0),
            prog.extra_module("/asdf/jkl", 0),
            prog.extra_module("/123/456", 0),
        ]
        self.assertCountEqual(list(prog.created_modules()), modules)

    def test_change_during_iteration(self):
        prog = Program()
        prog.extra_module("/foo/bar", 0)
        with self.assertRaisesRegex(Exception, "modules changed during iteration"):
            for module in prog.created_modules():
                prog.extra_module("/asdf/jkl", 0)
                prog.extra_module("/123/456", 0)


class TestLinuxUserspaceCoreDump(TestCase):
    def test_loaded_modules(self):
        prog = Program()
        prog.set_core_dump(get_resource("crashme.core"))

        loaded_modules = list(prog.loaded_modules())
        found_modules = []

        with self.subTest(module="main"):
            module = prog.find_main_module()
            found_modules.append(module)
            self.assertEqual(module.name, "/home/osandov/crashme")
            self.assertEqual(module.address_range, (0x400000, 0x404028))
            self.assertEqual(
                module.build_id.hex(), "2234a580c5a7ed96515417e2363e38fec4575281"
            )

        with self.subTest(module="crashme"):
            module = prog.find_shared_library_module(
                "/home/osandov/crashme.so", 0x7FE154D2CE20
            )
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FE154D29000, 0x7FE154D2D028))
            self.assertEqual(
                module.build_id.hex(), "045686d8fbc29df343dd452fc3b35de12cca3a7e"
            )

        with self.subTest(module="libc"):
            module = prog.find_shared_library_module("/lib64/libc.so.6", 0x7FE154D0BB80)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FE154B39000, 0x7FE154D15D50))
            self.assertEqual(
                module.build_id.hex(), "81daba31ee66dbd63efdc4252a872949d874d136"
            )

        with self.subTest(module="ld-linux"):
            module = prog.find_shared_library_module(
                "/lib64/ld-linux-x86-64.so.2", 0x7FE154D64DE0
            )
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FE154D30000, 0x7FE154D662B8))
            self.assertEqual(
                module.build_id.hex(), "bb6fec54c7521fddc569a2f4e141dfb97bf3acbe"
            )

        with self.subTest(module="vdso"):
            module = prog.find_vdso_module("linux-vdso.so.1", 0x7FFEB18EC3E0)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FFEB18EC000, 0x7FFEB18ECD5D))
            self.assertEqual(
                module.build_id.hex(), "320b9b38597b3c1894dc1a40674729b29a2de12c"
            )

        self.assertCountEqual(loaded_modules, found_modules)

    def test_vdso_file_in_core(self):
        prog = Program()
        prog.set_core_dump(get_resource("crashme.core"))
        for module in prog.loaded_modules():
            if isinstance(module, VdsoModule):
                status = module.try_local_files(want_debug=False)
                self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
                self.assertEqual(module.loaded_file_path, "")
                break

    def test_bias(self):
        prog = Program()
        prog.set_core_dump(get_resource("crashme.core"))

        for _ in prog.loaded_modules():
            pass

        with self.subTest(module="main"):
            module = prog.find_main_module()
            module.try_file(get_resource("crashme"))
            self.assertEqual(module.loaded_file_bias, 0)
            self.assertEqual(module.debug_file_bias, 0)

        with self.subTest(module="crashme"):
            module = prog.find_shared_library_module(
                "/home/osandov/crashme.so", 0x7FE154D2CE20
            )
            module.try_file(get_resource("crashme.so"))
            self.assertEqual(module.loaded_file_bias, 0x7FE154D29000)
            self.assertEqual(module.debug_file_bias, 0x7FE154D29000)

        with self.subTest(module="vdso"):
            module = prog.find_vdso_module("linux-vdso.so.1", 0x7FFEB18EC3E0)
            module.try_local_files(want_debug=False)
            self.assertEqual(module.loaded_file_bias, 0x7FFEB18EC000)
            self.assertIsNone(module.debug_file_bias)

    def test_loaded_modules_pie(self):
        prog = Program()
        prog.set_core_dump(get_resource("crashme_pie.core"))

        loaded_modules = list(prog.loaded_modules())
        found_modules = []

        with self.subTest(module="main"):
            module = prog.find_main_module()
            found_modules.append(module)
            self.assertEqual(module.name, "/home/osandov/crashme_pie")
            self.assertEqual(module.address_range, (0x55B3F015A000, 0x55B3F015E030))
            self.assertEqual(
                module.build_id.hex(), "678fde00d6638cecc07970153199f27e4a68175e"
            )

        with self.subTest(module="crashme"):
            module = prog.find_shared_library_module(
                "/home/osandov/crashme.so", 0x7FB63CE43E20
            )
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FB63CE40000, 0x7FB63CE44028))
            self.assertEqual(
                module.build_id.hex(), "045686d8fbc29df343dd452fc3b35de12cca3a7e"
            )

        with self.subTest(module="libc"):
            module = prog.find_shared_library_module("/lib64/libc.so.6", 0x7FB63CE22B80)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FB63CC50000, 0x7FB63CE2CD50))
            self.assertEqual(
                module.build_id.hex(), "81daba31ee66dbd63efdc4252a872949d874d136"
            )

        with self.subTest(module="ld-linux"):
            module = prog.find_shared_library_module(
                "/lib64/ld-linux-x86-64.so.2", 0x7FB63CE7BDE0
            )
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FB63CE47000, 0x7FB63CE7D2B8))
            self.assertEqual(
                module.build_id.hex(), "bb6fec54c7521fddc569a2f4e141dfb97bf3acbe"
            )

        with self.subTest(module="vdso"):
            module = prog.find_vdso_module("linux-vdso.so.1", 0x7FFF5557C3E0)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FFF5557C000, 0x7FFF5557CD5D))
            self.assertEqual(
                module.build_id.hex(), "320b9b38597b3c1894dc1a40674729b29a2de12c"
            )

        self.assertCountEqual(loaded_modules, found_modules)

    def test_bias_pie(self):
        prog = Program()
        prog.set_core_dump(get_resource("crashme_pie.core"))

        for _ in prog.loaded_modules():
            pass

        with self.subTest(module="main"):
            module = prog.find_main_module()
            module.try_file(get_resource("crashme_pie"))
            self.assertEqual(module.loaded_file_bias, 0x55B3F015A000)
            self.assertEqual(module.debug_file_bias, 0x55B3F015A000)

        with self.subTest(module="crashme"):
            module = prog.find_shared_library_module(
                "/home/osandov/crashme.so", 0x7FB63CE43E20
            )
            module.try_file(get_resource("crashme.so"))
            self.assertEqual(module.loaded_file_bias, 0x7FB63CE40000)
            self.assertEqual(module.debug_file_bias, 0x7FB63CE40000)

        with self.subTest(module="vdso"):
            module = prog.find_vdso_module("linux-vdso.so.1", 0x7FFF5557C3E0)
            module.try_local_files(want_debug=False)
            self.assertEqual(module.loaded_file_bias, 0x7FFF5557C000)
            self.assertIsNone(module.debug_file_bias)

    def test_loaded_modules_static(self):
        prog = Program()
        prog.set_core_dump(get_resource("crashme_static.core"))

        loaded_modules = list(prog.loaded_modules())
        found_modules = []

        with self.subTest(module="main"):
            module = prog.find_main_module()
            found_modules.append(module)
            self.assertEqual(module.name, "/home/osandov/crashme_static")
            self.assertEqual(module.address_range, (0x400000, 0x4042B8))
            self.assertEqual(
                module.build_id.hex(), "82dc250a5e1dca1bf312f6af36a4f394688c48f3"
            )

        with self.subTest(module="vdso"):
            module = prog.find_vdso_module("linux-vdso.so.1", 0x7FFC12B533E0)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FFC12B53000, 0x7FFC12B53D5D))
            self.assertEqual(
                module.build_id.hex(), "320b9b38597b3c1894dc1a40674729b29a2de12c"
            )

        self.assertCountEqual(loaded_modules, found_modules)

    def test_bias_static(self):
        prog = Program()
        prog.set_core_dump(get_resource("crashme_static.core"))

        for _ in prog.loaded_modules():
            pass

        with self.subTest(module="main"):
            module = prog.find_main_module()
            module.try_file(get_resource("crashme_static"))
            self.assertEqual(module.loaded_file_bias, 0x0)
            self.assertEqual(module.debug_file_bias, 0x0)

        with self.subTest(module="vdso"):
            module = prog.find_vdso_module("linux-vdso.so.1", 0x7FFC12B533E0)
            module.try_local_files(want_debug=False)
            self.assertEqual(module.loaded_file_bias, 0x7FFC12B53000)
            self.assertIsNone(module.debug_file_bias)

    def test_loaded_modules_static_pie(self):
        prog = Program()
        prog.set_core_dump(get_resource("crashme_static_pie.core"))

        loaded_modules = list(prog.loaded_modules())
        found_modules = []

        with self.subTest(module="main"):
            module = prog.find_main_module()
            found_modules.append(module)
            self.assertEqual(module.name, "/home/osandov/crashme_static_pie")
            self.assertEqual(module.address_range, (0x7F9FA3F4B000, 0x7F9FA3F4F298))
            self.assertEqual(
                module.build_id.hex(), "eb78014e8a1fc1a69b808dd724efe6ce5cf10e0d"
            )

        with self.subTest(module="vdso"):
            module = prog.find_vdso_module("linux-vdso.so.1", 0x7FFD67DF13E0)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FFD67DF1000, 0x7FFD67DF1D5D))
            self.assertEqual(
                module.build_id.hex(), "320b9b38597b3c1894dc1a40674729b29a2de12c"
            )

        self.assertCountEqual(loaded_modules, found_modules)

    def test_bias_static_pie(self):
        prog = Program()
        prog.set_core_dump(get_resource("crashme_static_pie.core"))

        for _ in prog.loaded_modules():
            pass

        with self.subTest(module="main"):
            module = prog.find_main_module()
            module.try_file(get_resource("crashme_static_pie"))
            self.assertEqual(module.loaded_file_bias, 0x7F9FA3F4B000)
            self.assertEqual(module.debug_file_bias, 0x7F9FA3F4B000)

        with self.subTest(module="vdso"):
            module = prog.find_vdso_module("linux-vdso.so.1", 0x7FFD67DF13E0)
            module.try_local_files(want_debug=False)
            self.assertEqual(module.loaded_file_bias, 0x7FFD67DF1000)
            self.assertIsNone(module.debug_file_bias)

    @unittest.expectedFailure  # TODO
    def test_loaded_modules_pie_no_headers(self):
        prog = Program()
        prog.set_core_dump(get_resource("crashme_pie_no_headers.core"))
        loaded_modules = list(prog.loaded_modules())

        # Without ELF headers saved in the core dump, and without the main ELF
        # file, only the main module (with limited information) and vDSO can be
        # found.
        found_modules = []

        with self.subTest(module="main"):
            module = prog.find_main_module()
            found_modules.append(module)
            self.assertEqual(module.name, "/home/osandov/crashme_pie")
            self.assertIsNone(module.address_range)
            self.assertIsNone(module.build_id)

        with self.subTest(module="vdso"):
            module = prog.find_vdso_module("linux-vdso.so.1", 0x7FFF8B5BB3E0)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FFF8B5BB000, 0x7FFF8B5BBD5D))
            self.assertEqual(
                module.build_id.hex(), "cdb1c24936a1dce1d1e13b795a8f5b776849da25"
            )

        self.assertCountEqual(loaded_modules, found_modules)

        # Once we add the main ELF file, we should be able to get everything.
        status = prog.find_main_module().try_file(
            get_resource("crashme_pie"), want_debug=False
        )
        self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
        loaded_modules = list(prog.loaded_modules())

        with self.subTest(module="main2"):
            module = prog.find_main_module()
            self.assertEqual(module.address_range, (0x55A9EFE63000, 0x55A9EFE67028))
            self.assertEqual(
                module.build_id.hex(), "40323a00d6c45293a571be6c0f91212ed06547fe"
            )

        with self.subTest(module="libc"):
            module = prog.find_shared_library_module("/lib64/libc.so.6", 0x7F8A24F0CB80)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7F8A24D3A000, 0x7F8A24F16D50))
            self.assertEqual(
                module.build_id.hex(), "81daba31ee66dbd63efdc4252a872949d874d136"
            )

        with self.subTest(module="ld-linux"):
            module = prog.find_shared_library_module(
                "/lib64/ld-linux-x86-64.so.2", 0x7F8A24F5FDE0
            )
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7F8A24F2B000, 0x7F8A24F612B8))
            self.assertEqual(
                module.build_id.hex(), "bb6fec54c7521fddc569a2f4e141dfb97bf3acbe"
            )

        self.assertCountEqual(loaded_modules, found_modules)
