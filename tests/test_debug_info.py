# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


import binascii
import contextlib
import http.server
import os
import os.path
from pathlib import Path
import re
import shutil
import socket
import socketserver
import tempfile
import threading
import unittest.mock

from _drgn_util.elf import ET, PT, SHF, SHT
from drgn import (
    MainModule,
    MissingDebugInfoError,
    ModuleFileStatus,
    Program,
    SupplementaryFileKind,
    VdsoModule,
)
from tests import TestCase, modifyenv
from tests.dwarfwriter import compile_dwarf
from tests.elfwriter import ElfSection, create_elf_file
from tests.resources import get_resource


def gnu_debuglink_section(path, crc):
    path = os.fsencode(path)
    return ElfSection(
        name=".gnu_debuglink",
        sh_type=SHT.PROGBITS,
        data=path + bytes(4 - len(path) % 4) + crc.to_bytes(4, "little"),
    )


def gnu_debugaltlink_section(path, build_id):
    return ElfSection(
        name=".gnu_debugaltlink",
        sh_type=SHT.PROGBITS,
        data=os.fsencode(path) + b"\0" + build_id,
    )


# TODO: remove
import logging  # noqa

from drgn.cli import _LogFormatter  # noqa

handler = logging.StreamHandler()
handler.setFormatter(_LogFormatter(True))
logging.getLogger().addHandler(handler)
logging.getLogger("drgn").setLevel(logging.DEBUG)

ALLOCATED_SECTION = ElfSection(
    name=".bss",
    sh_type=SHT.PROGBITS,
    sh_flags=SHF.ALLOC,
    p_type=PT.LOAD,
    vaddr=0x10000000,
    memsz=0x1000,
)


@contextlib.contextmanager
def NamedTemporaryElfFile(*, loadable=True, debug=True, build_id=None, sections=()):
    if loadable:
        sections = (ALLOCATED_SECTION,) + sections
    with tempfile.NamedTemporaryFile() as f:
        if debug:
            f.write(compile_dwarf((), sections=sections, build_id=build_id))
        else:
            f.write(create_elf_file(ET.EXEC, sections=sections, build_id=build_id))
        f.flush()
        yield f


# TODO: maybe this should go in test_module.py?
class TestModuleTryFile(TestCase):
    def setUp(self):
        self.prog = Program()
        self.prog.set_enabled_module_file_finders([])

    def test_want_both(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_want_both_not_loadable(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_want_both_no_debug(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)

    def test_want_both_is_neither(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False, debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded_not_loadable(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(loadable=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded_no_debug(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded_is_neither(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(loadable=False, debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_debug(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.loaded_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_only_want_debug_not_loadable(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.loaded_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(loadable=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_only_want_debug_no_debug(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.loaded_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_debug_is_neither(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.loaded_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(loadable=False, debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)

    def test_want_neither(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.loaded_file_status = ModuleFileStatus.DONT_WANT
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.debug_file_path)

    def test_separate_files_loaded_first(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(debug=False) as f1:
            module.try_file(f1.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f1.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)

        with NamedTemporaryElfFile(loadable=False) as f2:
            module.try_file(f2.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f1.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f2.name)

    def test_separate_files_debug_first(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False) as f1:
            module.try_file(f1.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f1.name)

        with NamedTemporaryElfFile(debug=False) as f2:
            module.try_file(f2.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f2.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f1.name)

    def test_loadable_then_both(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(debug=False) as f1:
            module.try_file(f1.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f1.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)

        with NamedTemporaryElfFile() as f2:
            module.try_file(f2.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f1.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f2.name)

    def test_debug_then_both(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(loadable=False) as f1:
            module.try_file(f1.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f1.name)

        with NamedTemporaryElfFile() as f2:
            module.try_file(f2.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f2.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f1.name)

    def test_no_build_id_force(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name, force=True)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_no_build_id_file_has_build_id(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            module.try_file(f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_no_build_id_file_has_build_id_force(self):
        module = self.prog.extra_module("/foo/bar", 0)
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            module.try_file(f.name, force=True)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    # TODO: fix the rest

    def test_build_id_match(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            module.try_file(f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_match_force(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            module.try_file(f.name, force=True)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_mismatch(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\xff\xff\xff\xff") as f:
            module.try_file(f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_mismatch_force(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\xff\xff\xff\xff") as f:
            # TODO: log something?
            module.try_file(f.name, force=True)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_missing(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_missing_force(self):
        module = self.prog.extra_module("/foo/bar", 0)
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile() as f:
            # TODO: log something?
            module.try_file(f.name, force=True)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_gnu_debugaltlink(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            alt_path = debug_dir / "alt.debug"
            alt_path.write_bytes(compile_dwarf((), build_id=alt_build_id))

            binary_path = bin_dir / "binary"
            binary_path.write_bytes(
                compile_dwarf(
                    (),
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debugaltlink_section(alt_path, alt_build_id),
                    ),
                    build_id=build_id,
                )
            )

            module = self.prog.extra_module(bin_dir / "binary", 0)
            module.build_id = build_id

            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
            self.assertRaises(ValueError, module.wanted_supplementary_debug_file)

            module.try_file(binary_path)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertIsNone(module.debug_file_path)
            self.assertIsNone(module.supplementary_debug_file_kind)
            self.assertIsNone(module.supplementary_debug_file_path)
            self.assertEqual(
                module.wanted_supplementary_debug_file(),
                (
                    SupplementaryFileKind.GNU_DEBUGALTLINK,
                    str(binary_path),
                    str(alt_path),
                    alt_build_id,
                ),
            )

            module.try_file(alt_path)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_path, str(binary_path))
            self.assertEqual(
                module.supplementary_debug_file_kind,
                SupplementaryFileKind.GNU_DEBUGALTLINK,
            )
            self.assertEqual(module.supplementary_debug_file_path, str(alt_path))
            self.assertRaises(ValueError, module.wanted_supplementary_debug_file)

    def test_gnu_debugaltlink_build_id_mismatch(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            alt_path = debug_dir / "alt.debug"
            alt_path.write_bytes(compile_dwarf((), build_id=alt_build_id[::-1]))

            binary_path = bin_dir / "binary"
            binary_path.write_bytes(
                compile_dwarf(
                    (),
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debugaltlink_section(alt_path, alt_build_id),
                    ),
                    build_id=build_id,
                )
            )

            module = self.prog.extra_module(bin_dir / "binary", 0)
            module.build_id = build_id  # TODO: without this, the wrong alt file gets used as the debug file. That feels wrong.

            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
            self.assertRaises(ValueError, module.wanted_supplementary_debug_file)

            module.try_file(binary_path)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertIsNone(module.debug_file_path)
            self.assertIsNone(module.supplementary_debug_file_kind)
            self.assertIsNone(module.supplementary_debug_file_path)
            self.assertEqual(
                module.wanted_supplementary_debug_file(),
                (
                    SupplementaryFileKind.GNU_DEBUGALTLINK,
                    str(binary_path),
                    str(alt_path),
                    alt_build_id,
                ),
            )

            module.try_file(alt_path)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertIsNone(module.debug_file_path)
            self.assertIsNone(module.supplementary_debug_file_kind)
            self.assertIsNone(module.supplementary_debug_file_path)
            self.assertEqual(
                module.wanted_supplementary_debug_file(),
                (
                    SupplementaryFileKind.GNU_DEBUGALTLINK,
                    str(binary_path),
                    str(alt_path),
                    alt_build_id,
                ),
            )


class TestLoadDebugInfo(TestCase):
    def setUp(self):
        self.prog = Program()
        self.prog.set_core_dump(get_resource("crashme.core"))
        self.prog.set_enabled_module_file_finders([])
        self.finder = unittest.mock.Mock()
        self.prog.register_module_file_finder("mock", self.finder, enable_index=0)

    def test_nothing(self):
        self.prog.load_debug_info(None, default=False, main=False)
        self.assertFalse(list(self.prog.created_modules()))
        self.finder.assert_not_called()

    def test_empty_list(self):
        self.prog.load_debug_info([], default=False, main=False)
        self.assertFalse(list(self.prog.created_modules()))
        self.finder.assert_not_called()

    def test_no_such_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            self.prog.load_debug_info([Path(tmp_dir) / "file"])
        self.assertFalse(list(self.prog.created_modules()))
        self.finder.assert_not_called()

    def test_not_elf(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"hello, world\n")
            f.flush()
            self.prog.load_debug_info([f.name])
        self.assertFalse(list(self.prog.created_modules()))
        self.finder.assert_not_called()

    def test_no_build_id(self):
        with NamedTemporaryElfFile() as f:
            self.prog.load_debug_info([f.name])
        self.assertFalse(list(self.prog.created_modules()))
        self.finder.assert_not_called()

    def test_only_main_path(self):
        crashme_path = get_resource("crashme")

        self.prog.load_debug_info([crashme_path])

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The provided path should be used for the main module.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_path),
        )
        # Finders shouldn't be called.
        self.finder.assert_not_called()

    def test_only_paths(self):
        crashme_path = get_resource("crashme")
        crashme_so_path = get_resource("crashme.so")

        self.prog.load_debug_info([crashme_path, crashme_so_path])

        modules = list(self.prog.created_modules())
        # All loaded modules should be created.
        self.assertEqual(len(modules), 5)
        # The provided files should be used for their respective modules.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_path),
        )
        crashme_so_module = next(
            module for module in modules if module.name == "/home/osandov/crashme.so"
        )
        self.assertEqual(
            crashme_so_module.loaded_file_path,
            str(crashme_so_path),
        )
        self.assertEqual(
            crashme_so_module.debug_file_path,
            str(crashme_so_path),
        )
        # The rest should not have a file.
        for module in modules:
            if module.name not in ("/home/osandov/crashme", "/home/osandov/crashme.so"):
                self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
                self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        # Finders shouldn't be called.
        self.finder.assert_not_called()

    def test_main_by_path(self):
        crashme_path = get_resource("crashme")

        self.prog.load_debug_info([crashme_path], main=True)

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The provided path should be used for the main module.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_path),
        )
        # Finders shouldn't be called.
        self.finder.assert_not_called()

    def test_main_by_finder(self):
        crashme_path = get_resource("crashme")

        def finder(modules):
            for module in modules:
                if module.name == "/home/osandov/crashme":
                    module.try_file(crashme_path)

        self.finder.side_effect = finder

        self.prog.load_debug_info(main=True)

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The finder should be called and set the file for the main module.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_path),
        )
        self.finder.assert_called_once_with([self.prog.find_main_module()])

    def test_default_by_paths(self):
        crashme_path = get_resource("crashme")
        crashme_so_path = get_resource("crashme.so")

        self.assertRaises(
            MissingDebugInfoError,
            self.prog.load_debug_info,
            [crashme_path, crashme_so_path],
            default=True,
        )

        # All loaded modules should be created.
        modules = list(self.prog.created_modules())
        self.assertEqual(len(modules), 5)
        # The provided files should be used for their respective modules.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_path),
        )
        crashme_so_module = next(
            module for module in modules if module.name == "/home/osandov/crashme.so"
        )
        self.assertEqual(
            crashme_so_module.loaded_file_path,
            str(crashme_so_path),
        )
        self.assertEqual(
            crashme_so_module.debug_file_path,
            str(crashme_so_path),
        )
        # The rest should not have a file.
        missing_modules = set()
        for module in modules:
            if module.name not in ("/home/osandov/crashme", "/home/osandov/crashme.so"):
                self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
                self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
                missing_modules.add(module)
        self.assertEqual(len(missing_modules), 3)
        # The finder should be called for the rest.
        self.assertEqual(self.finder.call_count, 1)
        self.assertEqual(set(self.finder.call_args.args[0]), missing_modules)

    def test_default_by_finder(self):
        crashme_path = get_resource("crashme")
        crashme_so_path = get_resource("crashme.so")

        def finder(modules):
            for module in modules:
                if module.name == "/home/osandov/crashme":
                    module.try_file(crashme_path)
                elif module.name == "/home/osandov/crashme.so":
                    module.try_file(crashme_so_path)

        self.finder.side_effect = finder

        self.assertRaises(
            MissingDebugInfoError, self.prog.load_debug_info, default=True
        )

        # All loaded modules should be created.
        modules = list(self.prog.created_modules())
        self.assertEqual(len(modules), 5)
        # The finder should be called and set the files for the matching
        # modules.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_path),
        )
        crashme_so_module = next(
            module for module in modules if module.name == "/home/osandov/crashme.so"
        )
        self.assertEqual(
            crashme_so_module.loaded_file_path,
            str(crashme_so_path),
        )
        self.assertEqual(
            crashme_so_module.debug_file_path,
            str(crashme_so_path),
        )
        # The rest should not have a file.
        for module in modules:
            if module.name not in ("/home/osandov/crashme", "/home/osandov/crashme.so"):
                self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
                self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        # The finder should be called for all loaded modules.
        self.assertEqual(self.finder.call_count, 1)
        self.assertEqual(set(self.finder.call_args.args[0]), set(modules))

    def test_main_gnu_debugaltlink_by_path(self):
        crashme_dwz_path = get_resource("crashme.dwz")
        crashme_alt_path = get_resource("crashme.alt")

        self.prog.load_debug_info([crashme_dwz_path, crashme_alt_path], main=True)

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The provided paths should be used for the main module.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        # Finders shouldn't be called.
        self.finder.assert_not_called()

    def test_main_gnu_debugaltlink_by_finder(self):
        crashme_dwz_path = get_resource("crashme.dwz")
        crashme_alt_path = get_resource("crashme.alt")

        def finder(modules):
            for module in modules:
                if module.name == "/home/osandov/crashme":
                    module.try_file(crashme_dwz_path)
                    module.try_file(crashme_alt_path)

        self.finder.side_effect = finder

        self.prog.load_debug_info(main=True)

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The finder should be called and set the files for the main module.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        self.finder.assert_called_once_with([self.prog.find_main_module()])

    def test_main_by_path_gnu_debugaltlink_not_found(self):
        crashme_dwz_path = get_resource("crashme.dwz")

        def finder(modules):
            for module in modules:
                if module.name == "/home/osandov/crashme":
                    self.assertEqual(
                        module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
                    )

        self.finder.side_effect = finder

        self.assertRaises(
            MissingDebugInfoError,
            self.prog.load_debug_info,
            [crashme_dwz_path],
            main=True,
        )

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The provided path should be used for the loaded file.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        # The finder should be called and fail to find the supplementary file
        # for the main module.
        self.assertEqual(
            self.prog.find_main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )
        self.assertEqual(
            self.prog.find_main_module().wanted_supplementary_debug_file()[:3],
            (
                SupplementaryFileKind.GNU_DEBUGALTLINK,
                str(crashme_dwz_path),
                "crashme.alt",
            ),
        )
        self.finder.assert_called_once_with([self.prog.find_main_module()])

    def test_main_by_finder_gnu_debugaltlink_not_found(self):
        crashme_dwz_path = get_resource("crashme.dwz")

        def finder(modules):
            for module in modules:
                if module.name == "/home/osandov/crashme":
                    self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
                    module.try_file(crashme_dwz_path)
                    self.assertEqual(
                        module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
                    )

        self.finder.side_effect = finder

        self.assertRaises(MissingDebugInfoError, self.prog.load_debug_info, main=True)

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The finder should be called and set the loaded file for the main
        # module but fail to find the supplementary file.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )
        self.assertEqual(
            self.prog.find_main_module().wanted_supplementary_debug_file()[:3],
            (
                SupplementaryFileKind.GNU_DEBUGALTLINK,
                str(crashme_dwz_path),
                "crashme.alt",
            ),
        )
        self.finder.assert_called_once_with([self.prog.find_main_module()])

    def test_main_by_path_gnu_debugaltlink_by_finder(self):
        crashme_dwz_path = get_resource("crashme.dwz")
        crashme_alt_path = get_resource("crashme.alt")

        def finder(modules):
            for module in modules:
                if (
                    module.name == "/home/osandov/crashme"
                    and module.debug_file_status == ModuleFileStatus.WANT_SUPPLEMENTARY
                ):
                    module.try_file(crashme_alt_path)

        self.finder.side_effect = finder

        self.prog.load_debug_info([crashme_dwz_path], main=True)

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The provided path should be used for the main module.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_dwz_path),
        )
        # The finder should be called and set the supplementary file for the
        # main module.
        self.assertEqual(
            self.prog.find_main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        self.finder.assert_called_once_with([self.prog.find_main_module()])

    def test_main_by_finder_gnu_debugaltlink_by_path(self):
        crashme_dwz_path = get_resource("crashme.dwz")
        crashme_alt_path = get_resource("crashme.alt")

        def finder(modules):
            for module in modules:
                if module.name == "/home/osandov/crashme":
                    module.try_file(crashme_dwz_path)

        self.finder.side_effect = finder

        self.prog.load_debug_info([crashme_alt_path], main=True)

        # The provided path should be used for the supplementary file for the
        # main module.
        self.assertEqual(
            self.prog.find_main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        # The finder should be called and set the file for the main module.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_dwz_path),
        )
        self.finder.assert_called_once_with([self.prog.find_main_module()])

    def test_main_wants_gnu_debugaltlink_by_path(self):
        crashme_dwz_path = get_resource("crashme.dwz")
        crashme_alt_path = get_resource("crashme.alt")

        for module in self.prog.loaded_modules():
            if isinstance(module, MainModule):
                module.try_file(crashme_dwz_path)
                break
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )

        self.prog.load_debug_info([crashme_alt_path], main=True)

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The provided path should be used for the supplementary file.
        self.assertEqual(
            self.prog.find_main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        # Finders shouldn't be called.
        self.finder.assert_not_called()

    def test_main_wants_gnu_debugaltlink_by_finder(self):
        crashme_dwz_path = get_resource("crashme.dwz")
        crashme_alt_path = get_resource("crashme.alt")

        for module in self.prog.loaded_modules():
            if isinstance(module, MainModule):
                module.try_file(crashme_dwz_path)
                break
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )

        def finder(modules):
            for module in modules:
                if (
                    module.name == "/home/osandov/crashme"
                    and module.debug_file_status == ModuleFileStatus.WANT_SUPPLEMENTARY
                ):
                    module.try_file(crashme_alt_path)

        self.finder.side_effect = finder

        self.prog.load_debug_info(main=True)

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The finder should be called and set the supplementary file for the
        # main module.
        self.assertEqual(
            self.prog.find_main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        self.finder.assert_called_once_with([self.prog.find_main_module()])

    def test_main_wants_gnu_debugaltlink_not_found(self):
        crashme_dwz_path = get_resource("crashme.dwz")

        for module in self.prog.loaded_modules():
            if isinstance(module, MainModule):
                module.try_file(crashme_dwz_path)
                break
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )

        self.assertRaises(MissingDebugInfoError, self.prog.load_debug_info, main=True)

        # Only the main module should be created.
        self.assertEqual(
            list(self.prog.created_modules()), [self.prog.find_main_module()]
        )
        # The finder should be called and fail to find the supplementary file
        # for the main module, but the supplementary file should still be
        # wanted.
        self.assertEqual(
            self.prog.find_main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )
        self.finder.assert_called_once_with([self.prog.find_main_module()])

    def test_default_gnu_debugaltlink_by_paths(self):
        crashme_dwz_path = get_resource("crashme.dwz")
        crashme_so_dwz_path = get_resource("crashme.so.dwz")
        crashme_alt_path = get_resource("crashme.alt")

        self.assertRaises(
            MissingDebugInfoError,
            self.prog.load_debug_info,
            [crashme_dwz_path, crashme_so_dwz_path, crashme_alt_path],
            default=True,
        )

        # All loaded modules should be created.
        modules = list(self.prog.created_modules())
        self.assertEqual(len(modules), 5)
        # The provided files should be used for their respective modules.
        self.assertEqual(
            self.prog.find_main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().debug_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.find_main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        crashme_so_module = next(
            module for module in modules if module.name == "/home/osandov/crashme.so"
        )
        self.assertEqual(
            crashme_so_module.loaded_file_path,
            str(crashme_so_dwz_path),
        )
        self.assertEqual(
            crashme_so_module.debug_file_path,
            str(crashme_so_dwz_path),
        )
        self.assertEqual(
            crashme_so_module.supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        # The rest should not have a file.
        missing_modules = set()
        for module in modules:
            if module.name not in ("/home/osandov/crashme", "/home/osandov/crashme.so"):
                self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
                self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
                missing_modules.add(module)
        self.assertEqual(len(missing_modules), 3)
        # The finder should be called for the rest.
        self.assertEqual(self.finder.call_count, 1)
        self.assertEqual(set(self.finder.call_args.args[0]), missing_modules)

    def test_dont_want(self):
        for module in self.prog.loaded_modules():
            if isinstance(module, MainModule):
                module.loaded_file_status = ModuleFileStatus.DONT_WANT
                module.debug_file_status = ModuleFileStatus.DONT_WANT
                break
        # DONT_WANT should be reset to WANT.
        self.assertRaises(MissingDebugInfoError, self.prog.load_debug_info, main=True)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.finder.assert_called_once_with([self.prog.find_main_module()])

    def test_dont_need(self):
        for module in self.prog.loaded_modules():
            if isinstance(module, MainModule):
                module.loaded_file_status = ModuleFileStatus.DONT_NEED
                module.debug_file_status = ModuleFileStatus.DONT_NEED
                break
        # DONT_NEED should be preserved.
        self.prog.load_debug_info(main=True)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_NEED)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_NEED)
        self.finder.assert_not_called()

    def test_unmatched(self):
        self.prog.load_debug_info([get_resource("crashme_static")])
        modules = list(self.prog.created_modules())
        # All loaded modules should be created.
        self.assertEqual(len(modules), 5)
        # None of them should have files.
        for module in modules:
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.finder.assert_not_called()


class TestStandardModuleFileFinder(TestCase):
    def setUp(self):
        self.prog = Program()
        self.prog.debug_info_path = None
        self.prog.set_enabled_module_file_finders(["standard"])

    def test_by_module_name(self):
        with NamedTemporaryElfFile() as f:
            module = self.prog.extra_module(f.name, 0)
            self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_path, f.name)

    def test_by_module_name_with_build_id(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(build_id=build_id) as f:
            module = self.prog.extra_module(f.name, 0)
            module.build_id = build_id
            self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_path, f.name)

    def test_by_module_name_missing_build_id(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile() as f:
            module = self.prog.extra_module(f.name, 0)
            module.build_id = build_id
            self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_by_module_name_build_id_mismatch(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(build_id=build_id[::-1]) as f:
            module = self.prog.extra_module(f.name, 0)
            module.build_id = build_id
            self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_reuse_loaded_file(self):
        with NamedTemporaryElfFile() as f:
            module = self.prog.extra_module(f.name, 0)
            module.debug_file_status = ModuleFileStatus.DONT_WANT
            self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)

        module.debug_file_status = ModuleFileStatus.WANT
        self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_reuse_debug_file(self):
        with NamedTemporaryElfFile() as f:
            module = self.prog.extra_module(f.name, 0)
            module.loaded_file_status = ModuleFileStatus.DONT_WANT
            self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

        module.loaded_file_status = ModuleFileStatus.WANT
        self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_reuse_wanted_supplementary_debug_file(self):
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with NamedTemporaryElfFile(
            sections=(gnu_debugaltlink_section("alt.debug", alt_build_id),),
        ) as f:
            module = self.prog.extra_module(f.name, 0)
            module.loaded_file_status = ModuleFileStatus.DONT_WANT
            self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY)

        module.loaded_file_status = ModuleFileStatus.WANT
        self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY)

    def test_vdso_in_core(self):
        self.prog.set_core_dump(get_resource("crashme.core"))
        for module in self.prog.loaded_modules():
            if isinstance(module, VdsoModule):
                break
        else:
            self.fail("vDSO module not found")
        self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, "[vdso]")
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    # TODO: test proc?

    def test_by_build_id(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            build_id_dir = debug_dir / ".build-id" / build_id.hex()[:2]
            build_id_dir.mkdir(parents=True)
            binary_path = build_id_dir / build_id.hex()[2:]
            binary_path.write_bytes(compile_dwarf((), sections=(ALLOCATED_SECTION,)))

            module = self.prog.extra_module(bin_dir / "binary", 0)
            module.build_id = build_id

            self.prog.debug_info_path = ":.debug:" + str(debug_dir)
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.loaded_file_path, str(binary_path))
            self.assertEqual(module.debug_file_path, str(binary_path))

    def test_by_build_id_separate(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            build_id_dir = debug_dir / ".build-id" / build_id.hex()[:2]
            build_id_dir.mkdir(parents=True)
            loadable_path = build_id_dir / build_id.hex()[2:]
            loadable_path.write_bytes(
                create_elf_file(ET.EXEC, sections=(ALLOCATED_SECTION,))
            )
            debug_path = build_id_dir / (build_id.hex()[2:] + ".debug")
            debug_path.write_bytes(compile_dwarf(()))

            module = self.prog.extra_module(bin_dir / "binary", 0)
            module.build_id = build_id

            self.prog.debug_info_path = ":.debug:" + str(debug_dir)
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.loaded_file_path, str(loadable_path))
            self.assertEqual(module.debug_file_path, str(debug_path))

    def test_by_build_id_from_loaded(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            loadable_path = bin_dir / "binary"
            loadable_path.write_bytes(
                create_elf_file(
                    ET.EXEC, sections=(ALLOCATED_SECTION,), build_id=build_id
                )
            )
            build_id_dir = debug_dir / ".build-id" / build_id.hex()[:2]
            build_id_dir.mkdir(parents=True)
            debug_path = build_id_dir / (build_id.hex()[2:] + ".debug")
            debug_path.write_bytes(compile_dwarf(()))

            module = self.prog.extra_module(bin_dir / "binary", 0)

            self.prog.debug_info_path = ":.debug:" + str(debug_dir)
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.loaded_file_path, str(loadable_path))
            self.assertEqual(module.debug_file_path, str(debug_path))

    def test_by_gnu_debuglink(self):
        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            debug_file_contents = compile_dwarf(())
            crc = binascii.crc32(debug_file_contents)

            loadable_path = bin_dir / "binary"
            loadable_path.write_bytes(
                create_elf_file(
                    ET.EXEC,
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debuglink_section("binary.debug", crc),
                    ),
                )
            )

            self.prog.debug_info_path = ":.debug:" + str(debug_dir)
            for i, debug_path in enumerate(
                (
                    bin_dir / "binary.debug",
                    bin_dir / ".debug" / "binary.debug",
                    debug_dir / bin_dir.relative_to("/") / "binary.debug",
                )
            ):
                with self.subTest(debug_path=debug_path):
                    try:
                        debug_path.parent.mkdir(parents=True, exist_ok=True)
                        debug_path.write_bytes(debug_file_contents)

                        module = self.prog.extra_module(bin_dir / "binary", i)

                        self.prog.find_module_files([module])
                        self.assertEqual(
                            module.loaded_file_status, ModuleFileStatus.HAVE
                        )
                        self.assertEqual(
                            module.debug_file_status, ModuleFileStatus.HAVE
                        )
                        self.assertEqual(module.loaded_file_path, str(loadable_path))
                        self.assertEqual(module.debug_file_path, str(debug_path))
                    finally:
                        try:
                            debug_path.unlink()
                        except FileNotFoundError:
                            pass

    def test_by_gnu_debuglink_absolute(self):
        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            debug_file_contents = compile_dwarf(())
            crc = binascii.crc32(debug_file_contents)
            debug_path = debug_dir / "binary.debug"

            loadable_path = bin_dir / "binary"
            loadable_path.write_bytes(
                create_elf_file(
                    ET.EXEC,
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debuglink_section(debug_path, crc),
                    ),
                )
            )

            debug_path.parent.mkdir(parents=True, exist_ok=True)
            debug_path.write_bytes(debug_file_contents)

            module = self.prog.extra_module(bin_dir / "binary", 0)

            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.loaded_file_path, str(loadable_path))
            self.assertEqual(module.debug_file_path, str(debug_path))

    def test_by_gnu_debuglink_crc_mismatch(self):
        with tempfile.TemporaryDirectory(prefix="bin-") as bin_dir:
            bin_dir = Path(bin_dir)

            debug_file_contents = compile_dwarf(())
            crc = binascii.crc32(debug_file_contents)

            loadable_path = bin_dir / "binary"
            loadable_path.write_bytes(
                create_elf_file(
                    ET.EXEC,
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debuglink_section("binary.debug", crc ^ 1),
                    ),
                )
            )

            debug_path = bin_dir / "binary.debug"
            debug_path.write_bytes(debug_file_contents)

            module = self.prog.extra_module(bin_dir / "binary", 0)
            self.prog.debug_info_path = ""
            self.prog.find_module_files([module])
            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_invalid_gnu_debuglink(self):
        with tempfile.TemporaryDirectory(prefix="bin-") as bin_dir:
            bin_dir = Path(bin_dir)

            loadable_path = bin_dir / "binary"
            loadable_path.write_bytes(
                create_elf_file(
                    ET.EXEC,
                    sections=(
                        ALLOCATED_SECTION,
                        ElfSection(
                            name=".gnu_debuglink", sh_type=SHT.PROGBITS, data=b"foo"
                        ),
                    ),
                )
            )

            module = self.prog.extra_module(bin_dir / "binary", 0)
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
            self.assertEqual(module.loaded_file_path, str(loadable_path))

    def test_gnu_debugaltlink_absolute(self):
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            alt_path = debug_dir / "alt.debug"
            alt_path.write_bytes(compile_dwarf((), build_id=alt_build_id))

            binary_path = bin_dir / "binary"
            binary_path.write_bytes(
                compile_dwarf(
                    (),
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debugaltlink_section(alt_path, alt_build_id),
                    ),
                )
            )

            module = self.prog.extra_module(bin_dir / "binary", 0)
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.loaded_file_path, str(binary_path))
            self.assertEqual(module.debug_file_path, str(binary_path))
            self.assertEqual(module.supplementary_debug_file_path, str(alt_path))

    def test_gnu_debugaltlink_not_found(self):
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            binary_path = bin_dir / "binary"
            binary_path.write_bytes(
                compile_dwarf(
                    (),
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debugaltlink_section(debug_dir / "alt.debug", alt_build_id),
                    ),
                )
            )

            module = self.prog.extra_module(bin_dir / "binary", 0)
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(
                module.wanted_supplementary_debug_file(),
                (
                    SupplementaryFileKind.GNU_DEBUGALTLINK,
                    str(binary_path),
                    str(debug_dir / "alt.debug"),
                    alt_build_id,
                ),
            )
            self.assertEqual(module.loaded_file_path, str(binary_path))

    def test_only_gnu_debugaltlink_absolute(self):
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            alt_path = debug_dir / "alt.debug"
            alt_path.write_bytes(compile_dwarf((), build_id=alt_build_id))

            binary_path = bin_dir / "binary"
            binary_path.write_bytes(
                compile_dwarf(
                    (),
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debugaltlink_section(alt_path, alt_build_id),
                    ),
                )
            )

            module = self.prog.extra_module(bin_dir / "binary", 0)
            module.try_file(binary_path)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(module.loaded_file_path, str(binary_path))

            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_path, str(binary_path))
            self.assertEqual(module.supplementary_debug_file_path, str(alt_path))

    def test_only_gnu_debugaltlink_not_found(self):
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            binary_path = bin_dir / "binary"
            binary_path.write_bytes(
                compile_dwarf(
                    (),
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debugaltlink_section(debug_dir / "alt.debug", alt_build_id),
                    ),
                )
            )

            module = self.prog.extra_module(bin_dir / "binary", 0)
            module.try_file(binary_path)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(module.loaded_file_path, str(binary_path))

            # TODO: it's a little awkward that this tries the module by name again
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(
                module.wanted_supplementary_debug_file(),
                (
                    SupplementaryFileKind.GNU_DEBUGALTLINK,
                    str(binary_path),
                    str(debug_dir / "alt.debug"),
                    alt_build_id,
                ),
            )

    def test_gnu_debugaltlink_relative(self):
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            alt_path = debug_dir / "alt.debug"
            alt_path.write_bytes(compile_dwarf((), build_id=alt_build_id))

            binary_path = bin_dir / "binary"
            binary_path.write_bytes(
                compile_dwarf(
                    (),
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debugaltlink_section(
                            Path(os.path.relpath(alt_path, bin_dir)), alt_build_id
                        ),
                    ),
                )
            )

            module = self.prog.extra_module(bin_dir / "binary", 0)
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.loaded_file_path, str(binary_path))
            self.assertEqual(module.debug_file_path, str(binary_path))
            self.assertEqual(module.supplementary_debug_file_path, str(alt_path))

    def test_gnu_debugaltlink_debug_directories(self):
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            alt_path = debug_dir / ".dwz/alt.debug"
            alt_path.parent.mkdir()
            alt_path.write_bytes(compile_dwarf((), build_id=alt_build_id))

            binary_path = bin_dir / "binary"

            self.prog.debug_info_path = ":.debug:" + str(debug_dir)
            for i, debugaltlink in enumerate(
                (
                    bin_dir / "debug/.dwz/alt.debug",
                    Path("debug/.dwz/alt.debug"),
                )
            ):
                with self.subTest(debugaltlink=debugaltlink):
                    binary_path.write_bytes(
                        compile_dwarf(
                            (),
                            sections=(
                                ALLOCATED_SECTION,
                                gnu_debugaltlink_section(debugaltlink, alt_build_id),
                            ),
                        )
                    )

                    module = self.prog.extra_module(bin_dir / "binary", i)
                    self.prog.find_module_files([module])
                    self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
                    self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
                    self.assertEqual(module.loaded_file_path, str(binary_path))
                    self.assertEqual(module.debug_file_path, str(binary_path))
                    self.assertEqual(
                        module.supplementary_debug_file_path, str(alt_path)
                    )

    def test_gnu_debugaltlink_build_id_mismatch(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            alt_path = debug_dir / "alt.debug"
            alt_path.write_bytes(compile_dwarf((), build_id=alt_build_id[::-1]))

            binary_path = bin_dir / "binary"
            binary_path.write_bytes(
                compile_dwarf(
                    (),
                    sections=(
                        ALLOCATED_SECTION,
                        gnu_debugaltlink_section(alt_path, alt_build_id),
                    ),
                    build_id=build_id,
                )
            )

            module = self.prog.extra_module(bin_dir / "binary", 0)
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(
                module.wanted_supplementary_debug_file(),
                (
                    SupplementaryFileKind.GNU_DEBUGALTLINK,
                    str(binary_path),
                    str(alt_path),
                    alt_build_id,
                ),
            )
            self.assertEqual(module.loaded_file_path, str(binary_path))

    def test_invalid_gnu_debugaltlink(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with tempfile.TemporaryDirectory(prefix="bin-") as bin_dir:
            bin_dir = Path(bin_dir)

            binary_path = bin_dir / "binary"
            binary_path.write_bytes(
                compile_dwarf(
                    (),
                    sections=(
                        ALLOCATED_SECTION,
                        ElfSection(
                            name=".gnu_debugaltlink",
                            sh_type=SHT.PROGBITS,
                            data=b"foo",
                        ),
                    ),
                    build_id=build_id,
                )
            )

            module = self.prog.extra_module(bin_dir / "binary", 0)
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
            self.assertEqual(module.loaded_file_path, str(binary_path))


class _DebuginfodHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        match = re.fullmatch(
            r"/buildid/((?:[0-9a-fA-F][0-9a-fA-F])+)/(executable|debuginfo)", self.path
        )
        if not match:
            self.send_error(http.HTTPStatus.BAD_REQUEST)
            return

        build_id = bytes.fromhex(match.group(1))
        type = match.group(2)

        try:
            file_path = self.server.build_ids[build_id][type]
        except KeyError:
            self.send_error(http.HTTPStatus.NOT_FOUND)
            return

        try:
            f = open(file_path, "rb")
        except OSError:
            self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        with f:
            self.send_response(http.HTTPStatus.OK)
            st = os.fstat(f.fileno())
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(st.st_size))
            self.send_header("X-Debuginfod-Size", str(st.st_size))
            self.send_header("Last-Modified", self.date_time_string(st.st_mtime))
            self.end_headers()
            shutil.copyfileobj(f, self.wfile)


class TestDebuginfodModuleFileFinder(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.TCPServer(("localhost", 0), _DebuginfodHTTPHandler)
        cls.server.build_ids = {}
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True
        )
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        # By default, serve_forever() only checks if it should shut down every
        # 0.5 seconds. Shutting down the socket makes it check immediately.
        cls.server.socket.shutdown(socket.SHUT_RD)
        cls.server.shutdown()
        cls.server_thread.join()

    def setUp(self):
        self.prog = Program()
        try:
            self.prog.set_enabled_module_file_finders(["debuginfod"])
        except ValueError:
            self.skipTest("no debuginfod support")

        self.server.build_ids.clear()
        self.cache_dir = Path(
            self.enterContext(tempfile.TemporaryDirectory(prefix="debuginfod-cache-"))
        )
        self.enterContext(
            modifyenv(
                {
                    "DEBUGINFOD_URLS": "http://{}:{}/".format(
                        *self.server.server_address
                    ),
                    "DEBUGINFOD_CACHE_PATH": str(self.cache_dir),
                }
            )
        )

    def test_no_build_id(self):
        module = self.prog.extra_module("foo", 0)
        self.prog.find_module_files([module])
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_separate(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(
            loadable=True, debug=False, build_id=build_id
        ) as loadable_file, NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=build_id
        ) as debug_file:
            self.server.build_ids[build_id] = {
                "executable": loadable_file.name,
                "debuginfo": debug_file.name,
            }

            module = self.prog.extra_module("foo", 0)
            module.build_id = build_id
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.loaded_file_path,
                str(self.cache_dir / build_id.hex() / "executable"),
            )
            self.assertEqual(
                module.debug_file_path,
                str(self.cache_dir / build_id.hex() / "debuginfo"),
            )

    def test_no_servers(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(
            loadable=True, debug=False, build_id=build_id
        ) as loadable_file, NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=build_id
        ) as debug_file, modifyenv(
            {"DEBUGINFOD_URLS": None}
        ):
            self.server.build_ids[build_id] = {
                "executable": loadable_file.name,
                "debuginfo": debug_file.name,
            }

            module = self.prog.extra_module("foo", 0)
            module.build_id = build_id
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_cache_hit(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=build_id
        ) as debug_file:
            self.server.build_ids[build_id] = {"debuginfo": debug_file.name}

            for i in range(2):
                module = self.prog.extra_module("foo", i)
                module.build_id = build_id
                self.prog.find_module_files([module])
                self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
                self.assertEqual(
                    module.debug_file_path,
                    str(self.cache_dir / build_id.hex() / "debuginfo"),
                )

    def test_gnu_debugaltlink(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with NamedTemporaryElfFile(
            loadable=True, debug=False, build_id=build_id
        ) as loadable_file, NamedTemporaryElfFile(
            loadable=False,
            debug=True,
            build_id=build_id,
            sections=(gnu_debugaltlink_section("alt.debug", alt_build_id),),
        ) as debug_file, NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=alt_build_id
        ) as alt_f:
            self.server.build_ids[build_id] = {
                "executable": loadable_file.name,
                "debuginfo": debug_file.name,
            }
            self.server.build_ids[alt_build_id] = {"debuginfo": alt_f.name}

            module = self.prog.extra_module("foo", 0)
            module.build_id = build_id
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.loaded_file_path,
                str(self.cache_dir / build_id.hex() / "executable"),
            )
            self.assertEqual(
                module.debug_file_path,
                str(self.cache_dir / build_id.hex() / "debuginfo"),
            )
            self.assertEqual(
                module.supplementary_debug_file_path,
                str(self.cache_dir / alt_build_id.hex() / "debuginfo"),
            )

    def test_gnu_debugaltlink_not_found(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with NamedTemporaryElfFile(
            loadable=True, debug=False, build_id=build_id
        ) as loadable_file, NamedTemporaryElfFile(
            loadable=False,
            debug=True,
            build_id=build_id,
            sections=(gnu_debugaltlink_section("alt.debug", alt_build_id),),
        ) as debug_file:
            self.server.build_ids[build_id] = {
                "executable": loadable_file.name,
                "debuginfo": debug_file.name,
            }

            module = self.prog.extra_module("foo", 0)
            module.build_id = build_id
            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(
                module.wanted_supplementary_debug_file(),
                (
                    SupplementaryFileKind.GNU_DEBUGALTLINK,
                    str(self.cache_dir / build_id.hex() / "debuginfo"),
                    "alt.debug",
                    alt_build_id,
                ),
            )
            self.assertEqual(
                module.loaded_file_path,
                str(self.cache_dir / build_id.hex() / "executable"),
            )

    def test_only_gnu_debugaltlink(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with NamedTemporaryElfFile(
            build_id=build_id,
            sections=(gnu_debugaltlink_section("alt.debug", alt_build_id),),
        ) as f, NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=alt_build_id
        ) as alt_f:
            self.server.build_ids[alt_build_id] = {"debuginfo": alt_f.name}

            module = self.prog.extra_module("foo", 0)
            module.try_file(f.name)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(module.loaded_file_path, f.name)

            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_path, f.name)
            self.assertEqual(
                module.supplementary_debug_file_path,
                str(self.cache_dir / alt_build_id.hex() / "debuginfo"),
            )

    def test_only_gnu_debugaltlink_not_found(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with NamedTemporaryElfFile(
            build_id=build_id,
            sections=(gnu_debugaltlink_section("alt.debug", alt_build_id),),
        ) as f:
            module = self.prog.extra_module("foo", 0)
            module.try_file(f.name)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(
                module.wanted_supplementary_debug_file(),
                (
                    SupplementaryFileKind.GNU_DEBUGALTLINK,
                    f.name,
                    "alt.debug",
                    alt_build_id,
                ),
            )
            self.assertEqual(module.loaded_file_path, f.name)

            self.prog.find_module_files([module])
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
