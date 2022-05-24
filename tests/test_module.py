# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import binascii
import contextlib
import os.path
from pathlib import Path
import tempfile
import unittest
import unittest.mock

from drgn import (
    ExtraModule,
    MainModule,
    ModuleFileStatus,
    Program,
    SharedLibraryModule,
    VdsoModule,
)
from tests import TestCase, modifyenv
from tests.dwarfwriter import compile_dwarf
from tests.elf import ET, PT, SHF, SHT
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
        self.assertIsNone(module.loaded_file_path)
        self.assertIsNone(module.loaded_file_bias)
        self.assertIsNone(module.debug_file_path)
        self.assertIsNone(module.debug_file_bias)
        self.assertIsNone(module.gnu_debugaltlink_file_path)

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


ALLOCATED_SECTION = ElfSection(
    name=".bss",
    sh_type=SHT.PROGBITS,
    sh_flags=SHF.ALLOC,
    p_type=PT.LOAD,
    vaddr=0x10000000,
    memsz=0x1000,
)


@contextlib.contextmanager
def NamedTemporaryElfFile(loadable=True, debug=True, build_id=None):
    if loadable:
        sections = (ALLOCATED_SECTION,)
    else:
        sections = ()
    with tempfile.NamedTemporaryFile() as f:
        if debug:
            f.write(compile_dwarf((), sections=sections, build_id=build_id))
        else:
            f.write(create_elf_file(ET.EXEC, sections=sections, build_id=build_id))
        f.flush()
        yield f


class TestModuleTryFile(TestCase):
    def test_want_both(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile() as f:
            status = module.try_file(f.name)
        self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_path, f.name)

    def test_want_both_not_loadable(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False) as f:
            status = module.try_file(f.name)
        self.assertEqual(status.loaded_status, ModuleFileStatus.FAILED)
        self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_path, f.name)

    def test_want_both_no_debug(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(debug=False) as f:
            status = module.try_file(f.name)
        self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(status.debug_status, ModuleFileStatus.FAILED)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertIsNone(module.debug_file_path)

    def test_want_both_is_neither(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False, debug=False) as f:
            status = module.try_file(f.name)
        self.assertEqual(status.loaded_status, ModuleFileStatus.FAILED)
        self.assertEqual(status.debug_status, ModuleFileStatus.FAILED)
        self.assertIsNone(module.loaded_file_path)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile() as f:
            status = module.try_file(f.name, want_debug=False)
        self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(status.debug_status, ModuleFileStatus.NOT_WANTED)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded_not_loadable(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False) as f:
            status = module.try_file(f.name, want_debug=False)
        self.assertEqual(status.loaded_status, ModuleFileStatus.FAILED)
        self.assertEqual(status.debug_status, ModuleFileStatus.NOT_WANTED)
        self.assertIsNone(module.loaded_file_path)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded_no_debug(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(debug=False) as f:
            status = module.try_file(f.name, want_debug=False)
        self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(status.debug_status, ModuleFileStatus.NOT_WANTED)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded_is_neither(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False, debug=False) as f:
            status = module.try_file(f.name, want_debug=False)
        self.assertEqual(status.loaded_status, ModuleFileStatus.FAILED)
        self.assertEqual(status.debug_status, ModuleFileStatus.NOT_WANTED)
        self.assertIsNone(module.loaded_file_path)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_debug(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile() as f:
            status = module.try_file(f.name, want_loaded=False)
        self.assertEqual(status.loaded_status, ModuleFileStatus.NOT_WANTED)
        self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_path, f.name)

    def test_only_want_debug_not_loadable(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False) as f:
            status = module.try_file(f.name, want_loaded=False)
        self.assertEqual(status.loaded_status, ModuleFileStatus.NOT_WANTED)
        self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_path, f.name)

    def test_only_want_debug_no_debug(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(debug=False) as f:
            status = module.try_file(f.name, want_loaded=False)
        self.assertEqual(status.loaded_status, ModuleFileStatus.NOT_WANTED)
        self.assertEqual(status.debug_status, ModuleFileStatus.FAILED)
        self.assertIsNone(module.loaded_file_path)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_debug_is_neither(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False, debug=False) as f:
            status = module.try_file(f.name, want_loaded=False)
        self.assertEqual(status.loaded_status, ModuleFileStatus.NOT_WANTED)
        self.assertEqual(status.debug_status, ModuleFileStatus.FAILED)
        self.assertIsNone(module.loaded_file_path)
        self.assertIsNone(module.debug_file_path)

    def test_want_neither(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile() as f:
            status = module.try_file(f.name, want_loaded=False, want_debug=False)
        self.assertEqual(status.loaded_status, ModuleFileStatus.NOT_WANTED)
        self.assertEqual(status.debug_status, ModuleFileStatus.NOT_WANTED)
        self.assertIsNone(module.loaded_file_path)
        self.assertIsNone(module.debug_file_path)

    def test_separate_files_loaded_first(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(debug=False) as f1:
            module.try_file(f1.name)
        with NamedTemporaryElfFile(loadable=False) as f2:
            status = module.try_file(f2.name)
        self.assertEqual(status.loaded_status, ModuleFileStatus.ALREADY_HAD)
        self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(module.loaded_file_path, f1.name)
        self.assertEqual(module.debug_file_path, f2.name)

    def test_separate_files_debug_first(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False) as f1:
            module.try_file(f1.name)
        with NamedTemporaryElfFile(debug=False) as f2:
            status = module.try_file(f2.name)
        self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(status.debug_status, ModuleFileStatus.ALREADY_HAD)
        self.assertEqual(module.loaded_file_path, f2.name)
        self.assertEqual(module.debug_file_path, f1.name)

    def test_loadable_then_both(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(debug=False) as f1:
            module.try_file(f1.name)
        with NamedTemporaryElfFile() as f2:
            status = module.try_file(f2.name)
        self.assertEqual(status.loaded_status, ModuleFileStatus.ALREADY_HAD)
        self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(module.loaded_file_path, f1.name)
        self.assertEqual(module.debug_file_path, f2.name)

    def test_debug_then_both(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False) as f1:
            module.try_file(f1.name)
        with NamedTemporaryElfFile() as f2:
            status = module.try_file(f2.name)
        self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(status.debug_status, ModuleFileStatus.ALREADY_HAD)
        self.assertEqual(module.loaded_file_path, f2.name)
        self.assertEqual(module.debug_file_path, f1.name)

    def test_already_had_vs_not_wanted(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False) as f1:
            module.try_file(f1.name)
        with NamedTemporaryElfFile(debug=False) as f2:
            status = module.try_file(f2.name, want_debug=False)
        # ALREADY_HAD should take precedence over NOT_WANTED.
        self.assertEqual(status.debug_status, ModuleFileStatus.ALREADY_HAD)


class TestModuleTryFileBuildId(TestCase):
    def test_try_file_no_build_id(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile() as f:
            self.assertEqual(
                module.try_file(f.name).debug_status, ModuleFileStatus.SUCCEEDED
            )

    def test_try_file_no_build_id_force(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile() as f:
            self.assertEqual(
                module.try_file(f.name, force=True).debug_status,
                ModuleFileStatus.SUCCEEDED,
            )

    def test_try_file_no_build_id_file_has_build_id(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            self.assertEqual(
                module.try_file(f.name).debug_status, ModuleFileStatus.SUCCEEDED
            )
            self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_try_file_no_build_id_file_has_build_id_force(self):
        module = Program().extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            self.assertEqual(
                module.try_file(f.name, force=True).debug_status,
                ModuleFileStatus.SUCCEEDED,
            )

    def test_try_file_build_id_match(self):
        module = Program().extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            self.assertEqual(
                module.try_file(f.name).debug_status, ModuleFileStatus.SUCCEEDED
            )

    def test_try_file_build_id_match_force(self):
        module = Program().extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            self.assertEqual(
                module.try_file(f.name).debug_status, ModuleFileStatus.SUCCEEDED
            )

    def test_try_file_build_id_mismatch(self):
        module = Program().extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\x01\x02\x03\x04") as f:
            self.assertEqual(
                module.try_file(f.name).debug_status, ModuleFileStatus.FAILED
            )

    def test_try_file_build_id_mismatch_force(self):
        module = Program().extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\x01\x02\x03\x04") as f:
            self.assertEqual(
                module.try_file(f.name, force=True).debug_status,
                ModuleFileStatus.SUCCEEDED,
            )

    def test_try_file_build_id_missing(self):
        module = Program().extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile() as f:
            self.assertEqual(
                module.try_file(f.name).debug_status, ModuleFileStatus.FAILED
            )

    def test_try_file_build_id_missing_force(self):
        module = Program().extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile() as f:
            self.assertEqual(
                module.try_file(f.name, force=True).debug_status,
                ModuleFileStatus.SUCCEEDED,
            )


class TestModuleTryLocalFiles(TestCase):
    def test_by_module_name(self):
        with NamedTemporaryElfFile() as f:
            module = Program().extra_module(f.name, 0)
            status = module.try_local_files()
        self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_path, f.name)

    def test_reuse_loaded_file(self):
        with NamedTemporaryElfFile() as f:
            module = Program().extra_module(f.name, 0)
            module.try_local_files(want_debug=False)
        status = module.try_local_files()
        self.assertEqual(status.loaded_status, ModuleFileStatus.ALREADY_HAD)
        self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_path, f.name)

    def test_reuse_debug_file(self):
        with NamedTemporaryElfFile() as f:
            module = Program().extra_module(f.name, 0)
            module.try_local_files(want_loaded=False)
        status = module.try_local_files()
        self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
        self.assertEqual(status.debug_status, ModuleFileStatus.ALREADY_HAD)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_path, f.name)

    def test_by_build_id(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            module = Program().extra_module(bin_dir / "binary", 0)
            module.build_id = build_id

            build_id_dir = debug_dir / ".build-id" / build_id.hex()[:2]
            build_id_dir.mkdir(parents=True)
            with open(build_id_dir / build_id.hex()[2:], "wb") as f:
                f.write(compile_dwarf((), sections=(ALLOCATED_SECTION,)))

            status = module.try_local_files(debug_directories=[debug_dir])
            self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
            self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
            self.assertEqual(module.loaded_file_path, f.name)
            self.assertEqual(module.debug_file_path, f.name)

    def test_by_build_id_separate(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            module = Program().extra_module(bin_dir / "binary", 0)
            module.build_id = build_id

            build_id_dir = debug_dir / ".build-id" / build_id.hex()[:2]
            build_id_dir.mkdir(parents=True)
            with open(build_id_dir / build_id.hex()[2:], "wb") as f1:
                f1.write(create_elf_file(ET.EXEC, sections=(ALLOCATED_SECTION,)))
            with open(build_id_dir / (build_id.hex()[2:] + ".debug"), "wb") as f2:
                f2.write(compile_dwarf(()))

            status = module.try_local_files(debug_directories=[debug_dir])
            self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
            self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
            self.assertEqual(module.loaded_file_path, f1.name)
            self.assertEqual(module.debug_file_path, f2.name)

    def test_by_build_id_from_loaded(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            module = Program().extra_module(bin_dir / "binary", 0)

            with open(bin_dir / "binary", "wb") as f1:
                f1.write(
                    create_elf_file(
                        ET.EXEC, sections=(ALLOCATED_SECTION,), build_id=build_id
                    )
                )
            build_id_dir = debug_dir / ".build-id" / build_id.hex()[:2]
            build_id_dir.mkdir(parents=True)
            with open(build_id_dir / (build_id.hex()[2:] + ".debug"), "wb") as f2:
                f2.write(compile_dwarf(()))

            status = module.try_local_files(debug_directories=[debug_dir])
            self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
            self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
            self.assertEqual(module.loaded_file_path, f1.name)
            self.assertEqual(module.debug_file_path, f2.name)

    def test_by_gnu_debuglink(self):
        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            debug_file_contents = compile_dwarf(())
            crc = binascii.crc32(debug_file_contents)

            with open(bin_dir / "binary", "wb") as loadable:
                loadable.write(
                    create_elf_file(
                        ET.EXEC,
                        sections=(
                            ALLOCATED_SECTION,
                            ElfSection(
                                name=".gnu_debuglink",
                                sh_type=SHT.PROGBITS,
                                data=b"binary.debug\0\0\0\0"
                                + crc.to_bytes(4, "little"),
                            ),
                        ),
                    )
                )

            for debug_path in (
                bin_dir / "binary.debug",
                bin_dir / ".debug" / "binary.debug",
                debug_dir / bin_dir.relative_to("/") / "binary.debug",
            ):
                with self.subTest(debug_path=debug_path):
                    try:
                        debug_path.parent.mkdir(parents=True, exist_ok=True)

                        module = Program().extra_module(bin_dir / "binary", 0)
                        debug_path.write_bytes(debug_file_contents)

                        status = module.try_local_files(
                            debug_directories=["", ".debug", debug_dir]
                        )
                        self.assertEqual(
                            status.loaded_status, ModuleFileStatus.SUCCEEDED
                        )
                        self.assertEqual(
                            status.debug_status, ModuleFileStatus.SUCCEEDED
                        )
                        self.assertEqual(module.loaded_file_path, loadable.name)
                        self.assertEqual(module.debug_file_path, str(debug_path))
                    finally:
                        try:
                            debug_path.unlink()
                        except FileNotFoundError:
                            pass

    def test_gnu_debuglink_crc_mismatch(self):
        with tempfile.TemporaryDirectory(prefix="bin-") as bin_dir:
            bin_dir = Path(bin_dir)

            debug_file_contents = compile_dwarf(())
            crc = binascii.crc32(debug_file_contents)

            with open(bin_dir / "binary", "wb") as loadable:
                loadable.write(
                    create_elf_file(
                        ET.EXEC,
                        sections=(
                            ALLOCATED_SECTION,
                            ElfSection(
                                name=".gnu_debuglink",
                                sh_type=SHT.PROGBITS,
                                data=b"binary.debug\0\0\0\0"
                                + (crc ^ 1).to_bytes(4, "little"),
                            ),
                        ),
                    )
                )

            with open(bin_dir / "binary.debug", "wb") as debug:
                debug.write(debug_file_contents)

            self.assertEqual(
                Program()
                .extra_module(bin_dir / "binary", 0)
                .try_local_files(debug_directories=[""])
                .debug_status,
                ModuleFileStatus.FAILED,
            )

    def test_gnu_debugaltlink_callback(self):
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            module = Program().extra_module(bin_dir / "binary", 0)

            with open(bin_dir / "binary", "wb") as f:
                f.write(
                    compile_dwarf(
                        (),
                        sections=(
                            ALLOCATED_SECTION,
                            ElfSection(
                                name=".gnu_debugaltlink",
                                sh_type=SHT.PROGBITS,
                                data=bytes(debug_dir / "alt.debug")
                                + b"\0"
                                + alt_build_id,
                            ),
                        ),
                    )
                )

            callback = unittest.mock.Mock()
            status = module.try_local_files(need_gnu_debugaltlink_file=callback)

            callback.assert_called_once_with(
                module,
                f.name,
                str(debug_dir / "alt.debug"),
                alt_build_id,
                unittest.mock.ANY,
            )

            # We shouldn't use the file's debug info since we couldn't get the
            # gnu_debugaltlink file, but we should still use it as the loaded
            # file.
            self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
            self.assertEqual(status.debug_status, ModuleFileStatus.FAILED)
            self.assertEqual(module.loaded_file_path, f.name)
            self.assertIsNone(module.debug_file_path)
            self.assertIsNone(module.gnu_debugaltlink_file_path)

    def test_gnu_debugaltlink_absolute(self):
        # The default need_gnu_debugaltlink_file will try to download files.
        with modifyenv({"DEBUGINFOD_URLS": None}):
            alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

            with tempfile.TemporaryDirectory(
                prefix="bin-"
            ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
                bin_dir = Path(bin_dir)
                debug_dir = Path(debug_dir)

                with open(debug_dir / "alt.debug", "wb") as altf:
                    altf.write(compile_dwarf((), build_id=alt_build_id))

                module = Program().extra_module(bin_dir / "binary", 0)

                with open(bin_dir / "binary", "wb") as f:
                    f.write(
                        compile_dwarf(
                            (),
                            sections=(
                                ALLOCATED_SECTION,
                                ElfSection(
                                    name=".gnu_debugaltlink",
                                    sh_type=SHT.PROGBITS,
                                    data=bytes(debug_dir / "alt.debug")
                                    + b"\0"
                                    + alt_build_id,
                                ),
                            ),
                        )
                    )

                status = module.try_local_files(debug_directories=[])
                self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
                self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
                self.assertEqual(module.loaded_file_path, f.name)
                self.assertEqual(module.debug_file_path, f.name)
                self.assertEqual(module.gnu_debugaltlink_file_path, altf.name)

    def test_gnu_debugaltlink_relative(self):
        # The default need_gnu_debugaltlink_file will try to download files.
        with modifyenv({"DEBUGINFOD_URLS": None}):
            alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

            with tempfile.TemporaryDirectory(
                prefix="bin-"
            ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
                bin_dir = Path(bin_dir)
                debug_dir = Path(debug_dir)

                with open(debug_dir / "alt.debug", "wb") as altf:
                    altf.write(compile_dwarf((), build_id=alt_build_id))

                module = Program().extra_module(bin_dir / "binary", 0)

                with open(bin_dir / "binary", "wb") as f:
                    f.write(
                        compile_dwarf(
                            (),
                            sections=(
                                ALLOCATED_SECTION,
                                ElfSection(
                                    name=".gnu_debugaltlink",
                                    sh_type=SHT.PROGBITS,
                                    data=bytes(
                                        Path(os.path.relpath(debug_dir, bin_dir))
                                        / "alt.debug"
                                    )
                                    + b"\0"
                                    + alt_build_id,
                                ),
                            ),
                        )
                    )

                status = module.try_local_files(debug_directories=[])
                self.assertEqual(status.loaded_status, ModuleFileStatus.SUCCEEDED)
                self.assertEqual(status.debug_status, ModuleFileStatus.SUCCEEDED)
                self.assertEqual(module.loaded_file_path, f.name)
                self.assertEqual(module.debug_file_path, f.name)
                self.assertEqual(module.gnu_debugaltlink_file_path, altf.name)

    def test_gnu_debugaltlink_debug_directories(self):
        # The default need_gnu_debugaltlink_file will try to download files.
        with modifyenv({"DEBUGINFOD_URLS": None}):
            alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

            with tempfile.TemporaryDirectory(
                prefix="bin-"
            ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
                bin_dir = Path(bin_dir)
                debug_dir = Path(debug_dir)

                (debug_dir / ".dwz").mkdir()
                with open(debug_dir / ".dwz" / "alt.debug", "wb") as altf:
                    altf.write(compile_dwarf((), build_id=alt_build_id))

                for debugaltlink in bin_dir / "debug/.dwz/alt.debug", Path(
                    "debug/.dwz/alt.debug"
                ):
                    with self.subTest(debugaltlink=debugaltlink):
                        module = Program().extra_module(bin_dir / "binary", 0)

                        with open(bin_dir / "binary", "wb") as f:
                            f.write(
                                compile_dwarf(
                                    (),
                                    sections=(
                                        ALLOCATED_SECTION,
                                        ElfSection(
                                            name=".gnu_debugaltlink",
                                            sh_type=SHT.PROGBITS,
                                            data=bytes(debugaltlink)
                                            + b"\0"
                                            + alt_build_id,
                                        ),
                                    ),
                                )
                            )

                        status = module.try_local_files(debug_directories=[debug_dir])
                        self.assertEqual(
                            status.loaded_status, ModuleFileStatus.SUCCEEDED
                        )
                        self.assertEqual(
                            status.debug_status, ModuleFileStatus.SUCCEEDED
                        )
                        self.assertEqual(module.loaded_file_path, f.name)
                        self.assertEqual(module.debug_file_path, f.name)
                        self.assertEqual(module.gnu_debugaltlink_file_path, altf.name)


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
