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
import unittest
import unittest.mock

from _drgn_util.elf import ET, PT, SHF, SHT
from drgn import (
    DebugInfoOptions,
    MainModule,
    MissingDebugInfoError,
    ModuleFileStatus,
    Program,
    SharedLibraryModule,
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


class TestModuleTryFile(TestCase):
    def setUp(self):
        self.prog = Program()
        self.prog.set_enabled_debug_info_finders([])

    def test_want_both(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

        for status in set(ModuleFileStatus) - {ModuleFileStatus.HAVE}:
            for file in ("loaded", "debug"):
                with self.subTest(file=file):
                    self.assertEqual(getattr(module, f"wants_{file}_file")(), False)
                    # Test that we can't unset the file once it's set.
                    status_attr = file + "_file_status"
                    with self.subTest(from_=ModuleFileStatus.HAVE, to=status):
                        self.assertRaises(
                            ValueError, setattr, module, status_attr, status
                        )
                        self.assertEqual(
                            getattr(module, status_attr), ModuleFileStatus.HAVE
                        )

    def test_want_both_not_loadable(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        with NamedTemporaryElfFile(loadable=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_want_both_no_debug(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        with NamedTemporaryElfFile(debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)

    def test_want_both_is_neither(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        with NamedTemporaryElfFile(loadable=False, debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded_not_loadable(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(loadable=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded_no_debug(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_loaded_is_neither(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(loadable=False, debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_debug(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.loaded_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_only_want_debug_not_loadable(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.loaded_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(loadable=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_only_want_debug_no_debug(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.loaded_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)

    def test_only_want_debug_is_neither(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.loaded_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile(loadable=False, debug=False) as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)

    def test_want_neither(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.loaded_file_status = ModuleFileStatus.DONT_WANT
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.loaded_file_path)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)
        self.assertIsNone(module.debug_file_path)

    def test_separate_files_loaded_first(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
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
        module = self.prog.extra_module("/foo/bar", create=True)[0]
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
        module = self.prog.extra_module("/foo/bar", create=True)[0]
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
        module = self.prog.extra_module("/foo/bar", create=True)[0]
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
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name, force=True)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_no_build_id_file_has_build_id(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            module.try_file(f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_no_build_id_file_has_build_id_force(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            module.try_file(f.name, force=True)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_match(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            module.try_file(f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_match_force(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\x01\x23\x45\x67\x89\xab\xcd\xef") as f:
            module.try_file(f.name, force=True)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_mismatch(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\xff\xff\xff\xff") as f:
            module.try_file(f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_mismatch_force(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile(build_id=b"\xff\xff\xff\xff") as f:
            module.try_file(f.name, force=True)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_missing(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.assertIsNone(module.debug_file_path)
        self.assertEqual(module.build_id, b"\x01\x23\x45\x67\x89\xab\xcd\xef")

    def test_build_id_missing_force(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        with NamedTemporaryElfFile() as f:
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            module.build_id = build_id

            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
            self.assertRaises(ValueError, module.wanted_supplementary_debug_file)

            module.try_file(binary_path)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(module.wants_debug_file(), True)
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

            with self.assertRaises(ValueError):
                module.debug_file_status = ModuleFileStatus.HAVE
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            module.debug_file_status = ModuleFileStatus.WANT_SUPPLEMENTARY
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
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

    def test_gnu_debugaltlink_then_both(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            alt_path = debug_dir / "alt.debug"
            alt_path.write_bytes(compile_dwarf((), build_id=alt_build_id))

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            module.build_id = build_id
            with NamedTemporaryElfFile(
                sections=(gnu_debugaltlink_section(alt_path, alt_build_id),),
                build_id=build_id,
            ) as f1:
                module.try_file(f1.name)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )

            with NamedTemporaryElfFile(build_id=build_id) as f2:
                module.try_file(f2.name)

            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.loaded_file_path, f1.name)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_path, f2.name)

    def test_gnu_debugaltlink_cancel(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with tempfile.TemporaryDirectory(
            prefix="bin-"
        ) as bin_dir, tempfile.TemporaryDirectory(prefix="debug-") as debug_dir:
            bin_dir = Path(bin_dir)
            debug_dir = Path(debug_dir)

            alt_path = debug_dir / "alt.debug"
            alt_path.write_bytes(compile_dwarf((), build_id=alt_build_id))

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            module.build_id = build_id
            with NamedTemporaryElfFile(
                sections=(gnu_debugaltlink_section(alt_path, alt_build_id),),
                build_id=build_id,
            ) as f:
                module.try_file(f.name)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )

            module.debug_file_status = ModuleFileStatus.WANT
            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
            self.assertEqual(module.wants_debug_file(), True)
            self.assertRaises(ValueError, module.wanted_supplementary_debug_file)

    def test_extra_module_no_address_range(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertIsNone(module.address_range)
        self.assertEqual(module.loaded_file_bias, 0)
        self.assertEqual(module.debug_file_bias, 0)

    def test_extra_module_address_range(self):
        module = self.prog.extra_module("/foo/bar", create=True)[0]
        module.address_range = (0x40000000, 0x40001000)
        with NamedTemporaryElfFile() as f:
            module.try_file(f.name)
        self.assertEqual(module.address_range, (0x40000000, 0x40001000))
        self.assertEqual(module.loaded_file_bias, 0x30000000)
        self.assertEqual(module.debug_file_bias, 0x30000000)


class TestLinuxUserspaceCoreDump(TestCase):
    def setUp(self):
        self.prog = Program()
        self.prog.debug_info_options.directories = ()
        self.prog.set_enabled_debug_info_finders(["standard"])

    def test_loaded_modules(self):
        self.prog.set_core_dump(get_resource("crashme.core"))

        loaded_modules = []
        for module, new in self.prog.loaded_modules():
            self.assertEqual(new, True)
            loaded_modules.append(module)
        found_modules = []

        with self.subTest(module="main"):
            module = self.prog.main_module()
            found_modules.append(module)
            self.assertEqual(module.name, "/home/osandov/crashme")
            self.assertEqual(module.address_range, (0x400000, 0x404010))
            self.assertEqual(
                module.build_id.hex(), "99a6524c4df01fbff9b43a6ead3d8e8e6201568b"
            )

        with self.subTest(module="crashme"):
            module = self.prog.shared_library_module(
                "/home/osandov/crashme.so", 0x7F6112CACE08
            )
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7F6112CA9000, 0x7F6112CAD010))
            self.assertEqual(
                module.build_id.hex(), "7bd58f10e741c3c8fbcf2031aa65f830f933d616"
            )

        with self.subTest(module="libc"):
            module = self.prog.shared_library_module("/lib64/libc.so.6", 0x7F6112C94960)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7F6112AAE000, 0x7F6112C9EB70))
            self.assertEqual(
                module.build_id.hex(), "77c77fee058b19c6f001cf2cb0371ce3b8341211"
            )

        with self.subTest(module="ld-linux"):
            module = self.prog.shared_library_module(
                "/lib64/ld-linux-x86-64.so.2", 0x7F6112CEAE68
            )
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7F6112CB6000, 0x7F6112CEC2D8))
            self.assertEqual(
                module.build_id.hex(), "91dcd0244204201b616bbf59427771b3751736ce"
            )

        with self.subTest(module="vdso"):
            module = self.prog.vdso_module("linux-vdso.so.1", 0x7F6112CB4438)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7F6112CB4000, 0x7F6112CB590F))
            self.assertEqual(
                module.build_id.hex(), "fdc3e4d463911345fbc6d9cc432e5ebc276e8e03"
            )

        self.assertCountEqual(loaded_modules, found_modules)

        loaded_modules = []
        for module, new in self.prog.loaded_modules():
            self.assertEqual(new, False)
            loaded_modules.append(module)
        self.assertCountEqual(loaded_modules, found_modules)

    def _try_vdso_in_core(self, module):
        module.debug_file_status = ModuleFileStatus.DONT_WANT
        self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)

    def test_bias(self):
        self.prog.set_core_dump(get_resource("crashme.core"))

        for _ in self.prog.loaded_modules():
            pass

        with self.subTest(module="main"):
            module = self.prog.main_module()
            module.try_file(get_resource("crashme"))
            self.assertEqual(module.loaded_file_bias, 0)
            self.assertEqual(module.debug_file_bias, 0)

        with self.subTest(module="crashme"):
            module = self.prog.shared_library_module(
                "/home/osandov/crashme.so", 0x7F6112CACE08
            )
            module.try_file(get_resource("crashme.so"))
            self.assertEqual(module.loaded_file_bias, 0x7F6112CA9000)
            self.assertEqual(module.debug_file_bias, 0x7F6112CA9000)

        with self.subTest(module="vdso"):
            module = self.prog.vdso_module("linux-vdso.so.1", 0x7F6112CB4438)
            self._try_vdso_in_core(module)
            self.assertEqual(module.loaded_file_bias, 0x7F6112CB4000)
            self.assertIsNone(module.debug_file_bias)

    def test_loaded_modules_pie(self):
        self.prog.set_core_dump(get_resource("crashme_pie.core"))

        loaded_modules = []
        for module, new in self.prog.loaded_modules():
            self.assertEqual(new, True)
            loaded_modules.append(module)
        found_modules = []

        with self.subTest(module="main"):
            module = self.prog.main_module()
            found_modules.append(module)
            self.assertEqual(module.name, "/home/osandov/crashme_pie")
            self.assertEqual(module.address_range, (0x557ED343D000, 0x557ED3441018))
            self.assertEqual(
                module.build_id.hex(), "eb4ad7aaded3815ab133a6d7784a2c95a4e52998"
            )

        with self.subTest(module="crashme"):
            module = self.prog.shared_library_module(
                "/home/osandov/crashme.so", 0x7FAB2C38DE08
            )
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FAB2C38A000, 0x7FAB2C38E010))
            self.assertEqual(
                module.build_id.hex(), "7bd58f10e741c3c8fbcf2031aa65f830f933d616"
            )

        with self.subTest(module="libc"):
            module = self.prog.shared_library_module("/lib64/libc.so.6", 0x7FAB2C375960)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FAB2C18F000, 0x7FAB2C37FB70))
            self.assertEqual(
                module.build_id.hex(), "77c77fee058b19c6f001cf2cb0371ce3b8341211"
            )

        with self.subTest(module="ld-linux"):
            module = self.prog.shared_library_module(
                "/lib64/ld-linux-x86-64.so.2", 0x7FAB2C3CBE68
            )
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FAB2C397000, 0x7FAB2C3CD2D8))
            self.assertEqual(
                module.build_id.hex(), "91dcd0244204201b616bbf59427771b3751736ce"
            )

        with self.subTest(module="vdso"):
            module = self.prog.vdso_module("linux-vdso.so.1", 0x7FAB2C395438)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FAB2C395000, 0x7FAB2C39690F))
            self.assertEqual(
                module.build_id.hex(), "fdc3e4d463911345fbc6d9cc432e5ebc276e8e03"
            )

        self.assertCountEqual(loaded_modules, found_modules)

        loaded_modules = []
        for module, new in self.prog.loaded_modules():
            self.assertEqual(new, False)
            loaded_modules.append(module)
        self.assertCountEqual(loaded_modules, found_modules)

    def test_bias_pie(self):
        self.prog.set_core_dump(get_resource("crashme_pie.core"))

        for _ in self.prog.loaded_modules():
            pass

        with self.subTest(module="main"):
            module = self.prog.main_module()
            module.try_file(get_resource("crashme_pie"))
            self.assertEqual(module.loaded_file_bias, 0x557ED343D000)
            self.assertEqual(module.debug_file_bias, 0x557ED343D000)

        with self.subTest(module="crashme"):
            module = self.prog.shared_library_module(
                "/home/osandov/crashme.so", 0x7FAB2C38DE08
            )
            module.try_file(get_resource("crashme.so"))
            self.assertEqual(module.loaded_file_bias, 0x7FAB2C38A000)
            self.assertEqual(module.debug_file_bias, 0x7FAB2C38A000)

        with self.subTest(module="vdso"):
            module = self.prog.vdso_module("linux-vdso.so.1", 0x7FAB2C395438)
            self._try_vdso_in_core(module)
            self.assertEqual(module.loaded_file_bias, 0x7FAB2C395000)
            self.assertIsNone(module.debug_file_bias)

    def test_loaded_modules_static(self):
        self.prog.set_core_dump(get_resource("crashme_static.core"))

        loaded_modules = []
        for module, new in self.prog.loaded_modules():
            self.assertEqual(new, True)
            loaded_modules.append(module)
        found_modules = []

        with self.subTest(module="main"):
            module = self.prog.main_module()
            found_modules.append(module)
            self.assertEqual(module.name, "/home/osandov/crashme_static")
            self.assertEqual(module.address_range, (0x400000, 0x4042B8))
            self.assertEqual(
                module.build_id.hex(), "a0b6befad9f0883c52c475ba3cee9c549cd082cf"
            )

        with self.subTest(module="vdso"):
            module = self.prog.vdso_module("linux-vdso.so.1", 0x7FBC73A66438)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FBC73A66000, 0x7FBC73A6790F))
            self.assertEqual(
                module.build_id.hex(), "fdc3e4d463911345fbc6d9cc432e5ebc276e8e03"
            )

        self.assertCountEqual(loaded_modules, found_modules)

        loaded_modules = []
        for module, new in self.prog.loaded_modules():
            self.assertEqual(new, False)
            loaded_modules.append(module)
        self.assertCountEqual(loaded_modules, found_modules)

    def test_bias_static(self):
        self.prog.set_core_dump(get_resource("crashme_static.core"))

        for _ in self.prog.loaded_modules():
            pass

        with self.subTest(module="main"):
            module = self.prog.main_module()
            module.try_file(get_resource("crashme_static"))
            self.assertEqual(module.loaded_file_bias, 0x0)
            self.assertEqual(module.debug_file_bias, 0x0)

        with self.subTest(module="vdso"):
            module = self.prog.vdso_module("linux-vdso.so.1", 0x7FBC73A66438)
            self._try_vdso_in_core(module)
            self.assertEqual(module.loaded_file_bias, 0x7FBC73A66000)
            self.assertIsNone(module.debug_file_bias)

    def test_loaded_modules_static_pie(self):
        self.prog.set_core_dump(get_resource("crashme_static_pie.core"))

        loaded_modules = []
        for module, new in self.prog.loaded_modules():
            self.assertEqual(new, True)
            loaded_modules.append(module)
        found_modules = []

        with self.subTest(module="main"):
            module = self.prog.main_module()
            found_modules.append(module)
            self.assertEqual(module.name, "/home/osandov/crashme_static_pie")
            self.assertEqual(module.address_range, (0x7FD981DC9000, 0x7FD981DCD278))
            self.assertEqual(
                module.build_id.hex(), "3e0bc47f80d7e64724e11fc021a251ed0d35bc2c"
            )

        with self.subTest(module="vdso"):
            module = self.prog.vdso_module("linux-vdso.so.1", 0x7FD981DC7438)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7FD981DC7000, 0x7FD981DC890F))
            self.assertEqual(
                module.build_id.hex(), "fdc3e4d463911345fbc6d9cc432e5ebc276e8e03"
            )

        self.assertCountEqual(loaded_modules, found_modules)

        loaded_modules = []
        for module, new in self.prog.loaded_modules():
            self.assertEqual(new, False)
            loaded_modules.append(module)
        self.assertCountEqual(loaded_modules, found_modules)

    def test_bias_static_pie(self):
        self.prog.set_core_dump(get_resource("crashme_static_pie.core"))

        for _ in self.prog.loaded_modules():
            pass

        with self.subTest(module="main"):
            module = self.prog.main_module()
            module.try_file(get_resource("crashme_static_pie"))
            self.assertEqual(module.loaded_file_bias, 0x7FD981DC9000)
            self.assertEqual(module.debug_file_bias, 0x7FD981DC9000)

        with self.subTest(module="vdso"):
            module = self.prog.vdso_module("linux-vdso.so.1", 0x7FD981DC7438)
            self._try_vdso_in_core(module)
            self.assertEqual(module.loaded_file_bias, 0x7FD981DC7000)
            self.assertIsNone(module.debug_file_bias)

    def test_loaded_modules_pie_no_headers(self):
        self.prog.set_core_dump(get_resource("crashme_pie_no_headers.core"))

        loaded_modules = []
        for module, new in self.prog.loaded_modules():
            self.assertEqual(new, True)
            loaded_modules.append(module)
        found_modules = []

        # Without ELF headers saved in the core dump, and without the main ELF
        # file, only the main module (with limited information) and vDSO can be
        # found.
        with self.subTest(module="main"):
            module = self.prog.main_module()
            found_modules.append(module)
            self.assertEqual(module.name, "/home/osandov/crashme_pie")
            self.assertIsNone(module.address_range)
            self.assertIsNone(module.build_id)

        with self.subTest(module="vdso"):
            module = self.prog.vdso_module("linux-vdso.so.1", 0x7F299F607438)
            found_modules.append(module)
            self.assertEqual(module.address_range, (0x7F299F607000, 0x7F299F60890F))
            self.assertEqual(
                module.build_id.hex(), "fdc3e4d463911345fbc6d9cc432e5ebc276e8e03"
            )

        self.assertCountEqual(loaded_modules, found_modules)

        loaded_modules = []
        for module, new in self.prog.loaded_modules():
            self.assertEqual(new, False)
            loaded_modules.append(module)
        self.assertCountEqual(loaded_modules, found_modules)

        # If we can read the file headers (specifically, the program header
        # table and the interpreter path), then we should be able to get all of
        # the modules (with limited information).
        exe_file = self.enterContext(open(get_resource("crashme_pie"), "rb"))

        def read_headers(address, count, offset, physical):
            exe_file.seek(offset)
            return exe_file.read(count)

        self.prog.add_memory_segment(0x5623363D6000, 4096, read_headers, False)

        old_loaded_modules = []
        new_loaded_modules = []
        for module, new in self.prog.loaded_modules():
            (new_loaded_modules if new else old_loaded_modules).append(module)
        new_found_modules = []

        with self.subTest(module="main2"):
            module = self.prog.main_module()
            self.assertIsNone(module.address_range)
            self.assertIsNone(module.build_id)

        with self.subTest(module="crashme"):
            module = self.prog.shared_library_module(
                "/home/osandov/crashme.so", 0x7F299F5FFE08
            )
            new_found_modules.append(module)
            self.assertIsNone(module.address_range)
            self.assertIsNone(module.build_id)

        with self.subTest(module="libc"):
            module = self.prog.shared_library_module("/lib64/libc.so.6", 0x7F299F5E7960)
            new_found_modules.append(module)
            self.assertIsNone(module.address_range)
            self.assertIsNone(module.build_id)

        with self.subTest(module="ld-linux"):
            module = self.prog.shared_library_module(
                "/lib64/ld-linux-x86-64.so.2", 0x7F299F63DE68
            )
            new_found_modules.append(module)
            self.assertIsNone(module.address_range)
            self.assertIsNone(module.build_id)

        self.assertCountEqual(old_loaded_modules, loaded_modules)
        self.assertCountEqual(new_loaded_modules, new_found_modules)


class TestLoadDebugInfo(TestCase):
    def setUp(self):
        self.prog = Program()
        self.prog.set_core_dump(get_resource("crashme.core"))
        self.prog.set_enabled_debug_info_finders([])
        self.finder = unittest.mock.Mock()
        self.prog.register_debug_info_finder("mock", self.finder, enable_index=0)

    def test_nothing(self):
        self.prog.load_debug_info(None, default=False, main=False)
        self.assertFalse(list(self.prog.modules()))
        self.finder.assert_not_called()

    def test_empty_list(self):
        self.prog.load_debug_info([], default=False, main=False)
        self.assertFalse(list(self.prog.modules()))
        self.finder.assert_not_called()

    def test_no_such_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            self.prog.load_debug_info([Path(tmp_dir) / "file"])
        self.assertFalse(list(self.prog.modules()))
        self.finder.assert_not_called()

    def test_not_elf(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"hello, world\n")
            f.flush()
            self.prog.load_debug_info([f.name])
        self.assertFalse(list(self.prog.modules()))
        self.finder.assert_not_called()

    def test_no_build_id(self):
        with NamedTemporaryElfFile() as f:
            self.prog.load_debug_info([f.name])
        self.assertFalse(list(self.prog.modules()))
        self.finder.assert_not_called()

    def test_only_main_path(self):
        crashme_path = get_resource("crashme")

        self.prog.load_debug_info([crashme_path])

        # Only the main module should be created.
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The provided path should be used for the main module.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
            str(crashme_path),
        )
        # Finders shouldn't be called.
        self.finder.assert_not_called()

    def test_only_paths(self):
        crashme_path = get_resource("crashme")
        crashme_so_path = get_resource("crashme.so")

        self.prog.load_debug_info([crashme_path, crashme_so_path])

        modules = list(self.prog.modules())
        # All loaded modules should be created.
        self.assertEqual(len(modules), 5)
        # The provided files should be used for their respective modules.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
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
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The provided path should be used for the main module.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
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
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The finder should be called and set the file for the main module.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
            str(crashme_path),
        )
        self.finder.assert_called_once_with([self.prog.main_module()])

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
        modules = list(self.prog.modules())
        self.assertEqual(len(modules), 5)
        # The provided files should be used for their respective modules.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
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
        missing_modules = []
        for module in modules:
            if module.name not in ("/home/osandov/crashme", "/home/osandov/crashme.so"):
                self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
                self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
                missing_modules.append(module)
        self.assertEqual(len(missing_modules), 3)
        # The finder should be called for the rest.
        self.finder.assert_called_once()
        self.assertCountEqual(self.finder.call_args[0][0], missing_modules)

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
        modules = list(self.prog.modules())
        self.assertEqual(len(modules), 5)
        # The finder should be called and set the files for the matching
        # modules.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
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
        self.finder.assert_called_once()
        self.assertCountEqual(self.finder.call_args[0][0], modules)

    def test_main_gnu_debugaltlink_by_path(self):
        crashme_dwz_path = get_resource("crashme.dwz")
        crashme_alt_path = get_resource("crashme.alt")

        self.prog.load_debug_info([crashme_dwz_path, crashme_alt_path], main=True)

        # Only the main module should be created.
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The provided paths should be used for the main module.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().supplementary_debug_file_path,
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
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The finder should be called and set the files for the main module.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        self.finder.assert_called_once_with([self.prog.main_module()])

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
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The provided path should be used for the loaded file.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        # The finder should be called and fail to find the supplementary file
        # for the main module.
        self.assertEqual(
            self.prog.main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )
        self.assertEqual(
            self.prog.main_module().wanted_supplementary_debug_file()[:3],
            (
                SupplementaryFileKind.GNU_DEBUGALTLINK,
                str(crashme_dwz_path),
                "crashme.alt",
            ),
        )
        self.finder.assert_called_once_with([self.prog.main_module()])

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
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The finder should be called and set the loaded file for the main
        # module but fail to find the supplementary file.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )
        self.assertEqual(
            self.prog.main_module().wanted_supplementary_debug_file()[:3],
            (
                SupplementaryFileKind.GNU_DEBUGALTLINK,
                str(crashme_dwz_path),
                "crashme.alt",
            ),
        )
        self.finder.assert_called_once_with([self.prog.main_module()])

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
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The provided path should be used for the main module.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
            str(crashme_dwz_path),
        )
        # The finder should be called and set the supplementary file for the
        # main module.
        self.assertEqual(
            self.prog.main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        self.finder.assert_called_once_with([self.prog.main_module()])

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
            self.prog.main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        # The finder should be called and set the file for the main module.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
            str(crashme_dwz_path),
        )
        self.finder.assert_called_once_with([self.prog.main_module()])

    def test_main_wants_gnu_debugaltlink_by_path(self):
        crashme_dwz_path = get_resource("crashme.dwz")
        crashme_alt_path = get_resource("crashme.alt")

        for module, _ in self.prog.loaded_modules():
            if isinstance(module, MainModule):
                module.try_file(crashme_dwz_path)
                break
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )

        self.prog.load_debug_info([crashme_alt_path], main=True)

        # Only the main module should be created.
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The provided path should be used for the supplementary file.
        self.assertEqual(
            self.prog.main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        # Finders shouldn't be called.
        self.finder.assert_not_called()

    def test_main_wants_gnu_debugaltlink_by_finder(self):
        crashme_dwz_path = get_resource("crashme.dwz")
        crashme_alt_path = get_resource("crashme.alt")

        for module, _ in self.prog.loaded_modules():
            if isinstance(module, MainModule):
                module.try_file(crashme_dwz_path)
                break
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_status,
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
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The finder should be called and set the supplementary file for the
        # main module.
        self.assertEqual(
            self.prog.main_module().supplementary_debug_file_path,
            str(crashme_alt_path),
        )
        self.finder.assert_called_once_with([self.prog.main_module()])

    def test_main_wants_gnu_debugaltlink_not_found(self):
        crashme_dwz_path = get_resource("crashme.dwz")

        for module, _ in self.prog.loaded_modules():
            if isinstance(module, MainModule):
                module.try_file(crashme_dwz_path)
                break
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )

        self.assertRaises(MissingDebugInfoError, self.prog.load_debug_info, main=True)

        # Only the main module should be created.
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The finder should be called and fail to find the supplementary file
        # for the main module, but the supplementary file should still be
        # wanted.
        self.assertEqual(
            self.prog.main_module().debug_file_status,
            ModuleFileStatus.WANT_SUPPLEMENTARY,
        )
        self.finder.assert_called_once_with([self.prog.main_module()])

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
        modules = list(self.prog.modules())
        self.assertEqual(len(modules), 5)
        # The provided files should be used for their respective modules.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
            str(crashme_dwz_path),
        )
        self.assertEqual(
            self.prog.main_module().supplementary_debug_file_path,
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
        missing_modules = []
        for module in modules:
            if module.name not in ("/home/osandov/crashme", "/home/osandov/crashme.so"):
                self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
                self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
                missing_modules.append(module)
        self.assertEqual(len(missing_modules), 3)
        # The finder should be called for the rest.
        self.finder.assert_called_once()
        self.assertCountEqual(self.finder.call_args[0][0], missing_modules)

    def test_dont_want(self):
        for module, _ in self.prog.loaded_modules():
            if isinstance(module, MainModule):
                module.loaded_file_status = ModuleFileStatus.DONT_WANT
                module.debug_file_status = ModuleFileStatus.DONT_WANT
                break
        # DONT_WANT should be reset to WANT.
        self.assertRaises(MissingDebugInfoError, self.prog.load_debug_info, main=True)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.finder.assert_called_once_with([self.prog.main_module()])

    def test_dont_need(self):
        for module, _ in self.prog.loaded_modules():
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
        modules = list(self.prog.modules())
        # All loaded modules should be created.
        self.assertEqual(len(modules), 5)
        # None of them should have files.
        for module in modules:
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)
        self.finder.assert_not_called()


class TestLoadDebugInfoCoreNoHeaders(TestCase):
    def setUp(self):
        self.prog = Program()
        self.prog.set_core_dump(get_resource("crashme_pie_no_headers.core"))
        self.prog.set_enabled_debug_info_finders([])
        self.finder = unittest.mock.Mock()
        self.prog.register_debug_info_finder("mock", self.finder, enable_index=0)

    def test_main_by_finder(self):
        crashme_pie_path = get_resource("crashme_pie")

        def finder(modules):
            for module in modules:
                if module.name == "/home/osandov/crashme_pie":
                    module.try_file(crashme_pie_path)

        self.finder.side_effect = finder

        self.prog.load_debug_info(main=True)

        # Only the main module should be created.
        self.assertEqual(list(self.prog.modules()), [self.prog.main_module()])
        # The finder should be called and set the files, address range, and
        # build ID for the main module.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_pie_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
            str(crashme_pie_path),
        )
        self.assertEqual(
            self.prog.main_module().address_range, (0x5623363D6000, 0x5623363DA018)
        )
        self.assertEqual(
            self.prog.main_module().build_id.hex(),
            "eb4ad7aaded3815ab133a6d7784a2c95a4e52998",
        )
        self.finder.assert_called_once_with([self.prog.main_module()])

    @unittest.expectedFailure  # Issue #291
    def test_default_by_finder(self):
        crashme_pie_path = get_resource("crashme_pie")
        crashme_so_path = get_resource("crashme.so")

        def finder(modules):
            for module in modules:
                if module.name == "/home/osandov/crashme_pie":
                    module.try_file(crashme_pie_path)
                elif module.name == "/home/osandov/crashme.so":
                    module.try_file(crashme_so_path)
                else:
                    module.loaded_file_status = ModuleFileStatus.DONT_NEED
                    module.debug_file_status = ModuleFileStatus.DONT_NEED

        self.finder.side_effect = finder

        self.prog.load_debug_info(default=True)

        # All loaded modules should be created (except ld-linux.so; see
        # tests.test_module.TestLinuxUserspaceCoreDump.test_loaded_modules_pie_no_headers).
        self.assertCountEqual(
            list(self.prog.modules()),
            [
                self.prog.main_module(),
                self.prog.vdso_module("linux-vdso.so.1", 0x7F299F607438),
                self.prog.shared_library_module(
                    "/home/osandov/crashme.so", 0x7F299F5FFE08
                ),
                self.prog.shared_library_module("/lib64/libc.so.6", 0x7F299F5E7960),
                self.prog.shared_library_module(
                    "/lib64/ld-linux-x86-64.so.2", 0x7F299F63DE68
                ),
            ],
        )
        # The finder should be called and set the files, address range, and
        # build ID for the main and crashme.so modules.
        self.assertEqual(
            self.prog.main_module().loaded_file_path,
            str(crashme_pie_path),
        )
        self.assertEqual(
            self.prog.main_module().debug_file_path,
            str(crashme_pie_path),
        )
        self.assertEqual(
            self.prog.main_module().address_range, (0x5623363D6000, 0x5623363DA018)
        )
        self.assertEqual(
            self.prog.main_module().build_id.hex(),
            "eb4ad7aaded3815ab133a6d7784a2c95a4e52998",
        )
        self.assertEqual(
            self.prog.shared_library_module(
                "/home/osandov/crashme.so", 0x7F299F5FFE08
            ).loaded_file_path,
            str(crashme_so_path),
        )
        self.assertEqual(
            self.prog.shared_library_module(
                "/home/osandov/crashme.so", 0x7F299F5FFE08
            ).debug_file_path,
            str(crashme_so_path),
        )
        self.assertEqual(
            self.prog.shared_library_module(
                "/home/osandov/crashme.so", 0x7F299F5FFE08
            ).address_range,
            (0x7F299F5FC000, 0x7F299F600010),
        )
        self.assertEqual(
            self.prog.shared_library_module(
                "/home/osandov/crashme.so", 0x7F299F5FFE08
            ).build_id.hex(),
            "7bd58f10e741c3c8fbcf2031aa65f830f933d616",
        )
        self.finder.assert_called()


class TestLoadModuleDebugInfo(TestCase):
    def setUp(self):
        self.prog = Program()
        self.prog.set_enabled_debug_info_finders([])
        self.finder = unittest.mock.Mock()
        self.prog.register_debug_info_finder("mock", self.finder, enable_index=0)

    def test_empty(self):
        self.prog.load_module_debug_info()
        self.finder.assert_not_called()

    def test_multiple(self):
        self.prog.load_module_debug_info(
            self.prog.extra_module("/foo/bar", create=True)[0],
            self.prog.extra_module("/foo/baz", create=True)[0],
        )
        self.finder.assert_called_once()
        self.assertCountEqual(
            self.finder.call_args[0][0],
            [
                self.prog.extra_module("/foo/bar"),
                self.prog.extra_module("/foo/baz"),
            ],
        )

    def test_wrong_program(self):
        self.assertRaisesRegex(
            ValueError,
            "module from wrong program",
            self.prog.load_module_debug_info,
            self.prog.extra_module("/foo/bar", create=True)[0],
            Program().extra_module("/foo/baz", create=True)[0],
        )

    def test_type_error(self):
        self.assertRaises(
            TypeError,
            self.prog.load_module_debug_info,
            self.prog.extra_module("/foo/bar", create=True)[0],
            None,
        )


class TestStandardDebugInfoFinder(TestCase):
    def setUp(self):
        self.prog = Program()
        self.prog.debug_info_options.directories = ()
        self.prog.set_enabled_debug_info_finders(["standard"])

    def test_by_module_name(self):
        with NamedTemporaryElfFile() as f:
            module = self.prog.extra_module(f.name, create=True)[0]
            self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_path, f.name)

    def test_by_module_name_with_build_id(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(build_id=build_id) as f:
            module = self.prog.extra_module(f.name, create=True)[0]
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_path, f.name)

    def test_by_module_name_missing_build_id(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile() as f:
            module = self.prog.extra_module(f.name, create=True)[0]
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_by_module_name_build_id_mismatch(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(build_id=build_id[::-1]) as f:
            module = self.prog.extra_module(f.name, create=True)[0]
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_reuse_loaded_file(self):
        with NamedTemporaryElfFile() as f:
            module = self.prog.extra_module(f.name, create=True)[0]
            module.debug_file_status = ModuleFileStatus.DONT_WANT
            self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.DONT_WANT)

        module.debug_file_status = ModuleFileStatus.WANT
        self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_reuse_debug_file(self):
        with NamedTemporaryElfFile() as f:
            module = self.prog.extra_module(f.name, create=True)[0]
            module.loaded_file_status = ModuleFileStatus.DONT_WANT
            self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

        module.loaded_file_status = ModuleFileStatus.WANT
        self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.debug_file_path, f.name)

    def test_reuse_wanted_supplementary_debug_file(self):
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with NamedTemporaryElfFile(
            sections=(gnu_debugaltlink_section("alt.debug", alt_build_id),),
        ) as f:
            module = self.prog.extra_module(f.name, create=True)[0]
            module.loaded_file_status = ModuleFileStatus.DONT_WANT
            self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.DONT_WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY)

        module.loaded_file_status = ModuleFileStatus.WANT
        self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, f.name)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY)

    def test_vdso_in_core(self):
        self.prog.set_core_dump(get_resource("crashme.core"))
        for module, _ in self.prog.loaded_modules():
            if isinstance(module, VdsoModule):
                break
        else:
            self.fail("vDSO module not found")
        self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, "[vdso]")
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_main_by_proc(self):
        self.prog.set_pid(os.getpid())
        for module, _ in self.prog.loaded_modules():
            if isinstance(module, MainModule):
                break
        else:
            self.fail("main module not found")
        self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)

    def test_vdso_by_proc(self):
        self.prog.set_pid(os.getpid())
        for module, _ in self.prog.loaded_modules():
            if isinstance(module, VdsoModule):
                break
        else:
            self.skipTest("vDSO module not found")
        self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
        self.assertEqual(module.loaded_file_path, "[vdso]")
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_shared_library_by_proc(self):
        self.prog.set_pid(os.getpid())
        for module, _ in self.prog.loaded_modules():
            if isinstance(module, SharedLibraryModule):
                break
        else:
            self.skipTest("shared library module not found")
        self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)

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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            module.build_id = build_id

            self.prog.debug_info_options.directories = ("", ".debug", str(debug_dir))
            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            module.build_id = build_id

            self.prog.debug_info_options.directories = ("", ".debug", str(debug_dir))
            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]

            self.prog.debug_info_options.directories = ("", ".debug", str(debug_dir))
            self.prog.load_module_debug_info(module)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.loaded_file_path, str(loadable_path))
            self.assertEqual(module.debug_file_path, str(debug_path))

    def test_by_build_id_method(self):
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            module.build_id = build_id

            self.prog.find_standard_debug_info(
                [module],
                options=DebugInfoOptions(directories=("", ".debug", str(debug_dir))),
            )
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.loaded_file_path, str(binary_path))
            self.assertEqual(module.debug_file_path, str(binary_path))

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

            self.prog.debug_info_options.directories = ("", ".debug", str(debug_dir))
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

                        module = self.prog.extra_module(
                            bin_dir / "binary", i, create=True
                        )[0]

                        self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]

            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            self.prog.debug_info_options.directories = ("",)
            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            module.try_file(binary_path)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(module.loaded_file_path, str(binary_path))

            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            module.try_file(binary_path)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(module.loaded_file_path, str(binary_path))

            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            self.prog.load_module_debug_info(module)
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

            self.prog.debug_info_options.directories = ("", ".debug", str(debug_dir))
            for i, debugaltlink in enumerate(
                (
                    bin_dir / "debug/.dwz/alt.debug",
                    Path("debug/.dwz/alt.debug"),
                )
            ):
                with self.subTest(debugaltlink=debugaltlink):
                    binary_path = bin_dir / f"binary{i}"
                    binary_path.write_bytes(
                        compile_dwarf(
                            (),
                            sections=(
                                ALLOCATED_SECTION,
                                gnu_debugaltlink_section(debugaltlink, alt_build_id),
                            ),
                        )
                    )

                    module = self.prog.extra_module(binary_path, create=True)[0]
                    self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module(bin_dir / "binary", create=True)[0]
            self.prog.load_module_debug_info(module)
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


class TestDebuginfodDebugInfoFinder(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
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
            self.prog.set_enabled_debug_info_finders(["debuginfod"])
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
        module = self.prog.extra_module("foo", create=True)[0]
        self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module("foo", create=True)[0]
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module("foo", create=True)[0]
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_cache_hit(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=build_id
        ) as debug_file:
            self.server.build_ids[build_id] = {"debuginfo": debug_file.name}

            for i in range(2):
                module = self.prog.extra_module("foo", i, create=True)[0]
                module.build_id = build_id
                self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module("foo", create=True)[0]
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module("foo", create=True)[0]
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
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

            module = self.prog.extra_module("foo", create=True)[0]
            module.try_file(f.name)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(module.loaded_file_path, f.name)

            self.prog.load_module_debug_info(module)
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
            module = self.prog.extra_module("foo", create=True)[0]
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

            self.prog.load_module_debug_info(module)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
