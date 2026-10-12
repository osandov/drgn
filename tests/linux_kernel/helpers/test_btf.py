# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import struct
import unittest
from unittest import mock

from drgn import (
    FindObjectFlags,
    Program,
    Symbol,
    SymbolBinding,
    SymbolIndex,
    SymbolKind,
    TypeKind,
    TypeMember,
    host_platform,
)
from drgn.helpers.experimental.btf import (
    build_c_declaration_object_finder,
    load_builtin_btf,
)
from tests import TestCase, skip_unless_have_libbpf
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod
from tests.linux_kernel.helpers import test_block, test_fs

VMLINUX_BTF_PATH = "/sys/kernel/btf/vmlinux"
DRGN_TEST_BTF_PATH = "/sys/kernel/btf/drgn_test"


@skip_unless_have_libbpf
class TestBtfLoading(LinuxKernelTestCase):

    def setUp(self):
        if not os.path.exists(VMLINUX_BTF_PATH):
            raise unittest.SkipTest("BTF is not available")

        # For these tests we need a new kernel program each time.
        # Each test will load BTF in a different way.
        # However, we still reuse the LinuxKernelTestCase so we can guarantee
        # that any reason why we may have wanted to skip the test (e.g. lack of
        # permissions) is already handled.
        self.dwarf_prog = self.prog
        self.prog = Program()
        self.prog.set_kernel()
        self.prog.main_module("kernel", create=True)

        # Even though we're loading BTF repeatedly, we really don't want to
        # parse kallsyms repeatedly: it's rather slow. These are the minimum
        # symbols necessary, copy them from the DWARF program. This is purely a
        # speed optimization: they *are* present in kallsyms.
        syms = []
        names = [
            # Needed for module discovery:
            "modules",
            # Needed to find built-in BTF:
            "__start_BTF",
            "__stop_BTF",
        ]
        optional_names = [
            # Needed for BTF module discovery, but it is missing on kernels
            # which do not have module BTF -- that's ok.
            "btf_modules",
            # Needed as the base address for percpu DATASEC vars. However, on
            # !SMP configurations, some architectures don't have the symbol at
            # all, so make it optional.
            "__per_cpu_start",
        ]
        for name in names + optional_names:
            try:
                syms.append(self.dwarf_prog.symbol(name))
            except LookupError:
                # Some kernels have BTF but not built-in module BTF
                if name not in optional_names:
                    raise
        self.prog.register_symbol_finder(
            "required_symbols", SymbolIndex(syms), enable_index=0
        )

    def _skip_unless_have_module_btf(self):
        try:
            self.dwarf_prog.symbol("btf_modules")
        except LookupError:
            # Module BTF is introduced in 36e68442d1afd ("bpf: Load and verify
            # kernel module BTFs").
            self.skipTest("Module BTF is not available")

    def _do_vmlinux_btf_smoke(self):
        task_struct = self.prog.type("struct task_struct")
        self.assertEqual(task_struct.kind, TypeKind.STRUCT)
        self.assertGreater(len(task_struct.members), 20)

    def _load_vmlinux_kernfs_btf(self):
        with open(VMLINUX_BTF_PATH, "rb") as f:
            btf = f.read()
        self.prog.main_module().load_btf(data=btf)

    def test_kernfs_smoke(self):
        self._load_vmlinux_kernfs_btf()
        self._do_vmlinux_btf_smoke()

    def test_builtin_smoke(self):
        try:
            start_sym = self.dwarf_prog.symbol("__start_BTF")
            stop_sym = self.dwarf_prog.symbol("__stop_BTF")
        except LookupError:
            self.skipTest("Built-in BTF not available")
        addr = start_sym.address
        size = stop_sym.address - start_sym.address
        btf = self.dwarf_prog.read(addr, size)
        self.prog.main_module().load_btf(data=btf)
        self._do_vmlinux_btf_smoke()

    def _do_drgn_test_kmod_smoke(self):
        t = self.prog.type("drgn_test_anonymous_union")
        self.assertEqual(t.kind, TypeKind.TYPEDEF)
        union = t.type
        self.assertEqual(union.kind, TypeKind.UNION)

    @skip_unless_have_test_kmod
    def test_kmod_smoke(self):
        self._skip_unless_have_module_btf()
        self._load_vmlinux_kernfs_btf()
        self.prog.create_loaded_modules()
        with open(DRGN_TEST_BTF_PATH, "rb") as f:
            btf = f.read()
        drgn_test = self.prog.module("drgn_test")
        # The default is main_module_base=True for the kernel
        drgn_test.load_btf(data=btf)
        self._do_drgn_test_kmod_smoke()

    @skip_unless_have_test_kmod
    def test_load_builtin_btf_kernfs(self):
        self._skip_unless_have_module_btf()
        with mock.patch(
            "drgn.helpers.experimental.btf.load_vmlinux_kallsyms",
            return_value=lambda *_: [],
        ), mock.patch(
            "os.path.isdir",
            return_value=True,
        ):
            load_builtin_btf(self.prog)
            self._do_vmlinux_btf_smoke()
            self._do_drgn_test_kmod_smoke()

    @skip_unless_have_test_kmod
    def test_load_bulitin_btf_internal(self):
        self._skip_unless_have_module_btf()
        with mock.patch(
            "drgn.helpers.experimental.btf.load_vmlinux_kallsyms",
            return_value=lambda *_: [],
        ), mock.patch(
            "os.path.isdir",
            return_value=False,
        ):
            load_builtin_btf(self.prog)
            self._do_vmlinux_btf_smoke()
            self._do_drgn_test_kmod_smoke()


class LinuxKernelBtfTestCase(LinuxKernelTestCase):

    btf_prog = None
    declarations = """
    // Needed by BTF loading:
    struct list_head btf_modules, modules;
    // Needed for tests.linux_kernel.helpers.test_block:
    struct drgn_test_blkdev drgn_test_blkdevs[2];
    const struct class block_class;
    struct super_block *blockdev_superblock;
    struct kset *class_kset;
    // Needed for tests.linux_kernel.helpers.test_fs:
    struct task_struct init_task;
    struct pid_namespace init_pid_ns;
    """

    @classmethod
    def setUpClass(cls):
        # Similar to LinuxKernelTestCase, create the program just once and cache
        # it on the class. The overhead of parsing kallsyms is quite a lot.
        super().setUpClass()
        try:
            cls.prog.symbol("btf_modules")
        except LookupError:
            raise unittest.SkipTest("Module BTF is not available")

        if cls.btf_prog is None:
            cls.dwarf_prog = cls.prog
            cls.btf_prog = Program()
            cls.btf_prog.set_kernel()
            load_builtin_btf(cls.btf_prog, cls.declarations)

    def setUp(self):
        super().setUp()
        self.prog = self.btf_prog


@skip_unless_have_libbpf
class TestKernelBTF(LinuxKernelBtfTestCase):
    def test_per_cpu_global_var(self):
        # Since v2.6.34-rc2 commit 259354deaaf03 ("module: encapsulate percpu
        # handling better and record percpu_size"), the percpu field of struct
        # module has been guarded exclusively by CONFIG_SMP.
        if not self.prog.type("struct module").has_member("percpu"):
            self.skipTest("No percpu variables on !SMP")
        # Percpu variables are the only ones for which BTF already contains a
        # DATASEC. Test that the BTF object finder can find the percpu base
        # address for vmlinux.
        obj = self.prog["runqueues"]
        dwarf_obj = self.dwarf_prog["runqueues"]
        self.assertEqual(obj.address_, dwarf_obj.address_)


@skip_unless_have_test_kmod
@skip_unless_have_libbpf
class TestKmod(LinuxKernelBtfTestCase):
    def test_unions(self):
        # The test isn't really about the correct definition of u32/s32, which
        # changes over kernel versions and architectures.
        u32 = self.prog.type("u32")
        s32 = self.prog.type("s32")
        u64 = self.prog.type("u64")
        s64 = self.prog.type("s64")

        drgn_test_union = self.prog.union_type(
            "drgn_test_union",
            4,
            (
                TypeMember(u32, "u", 0),
                TypeMember(s32, "s", 0),
            ),
        )
        self.assertIdentical(drgn_test_union, self.prog.type("union drgn_test_union"))
        anon_union = self.prog.union_type(
            None,
            8,
            (
                TypeMember(u64, "u", 0),
                TypeMember(s64, "s", 0),
            ),
        )
        anon_union_typedef = self.prog.typedef_type(
            "drgn_test_anonymous_union",
            anon_union,
        )
        self.assertIdentical(
            anon_union_typedef, self.prog.type("drgn_test_anonymous_union")
        )

    def test_per_cpu_global_var(self):
        # Since v2.6.34-rc2 commit 259354deaaf03 ("module: encapsulate percpu
        # handling better and record percpu_size"), the percpu field of struct
        # module has been guarded exclusively by CONFIG_SMP.
        if not self.prog.type("struct module").has_member("percpu"):
            self.skipTest("No percpu variables on !SMP")
        # Percpu variables are the only ones for which BTF already contains a
        # DATASEC. Test that the BTF object finder can find the percpu base
        # address for the drgn_test module.
        obj = self.prog["drgn_test_percpu_static"]
        dwarf_obj = self.dwarf_prog["drgn_test_percpu_static"]
        self.assertEqual(obj.address_, dwarf_obj.address_)


@skip_unless_have_libbpf
class TestFsBTF(test_fs.TestFs, LinuxKernelBtfTestCase):
    pass


@skip_unless_have_libbpf
class TestBlockBTF(test_block.TestBlock, LinuxKernelBtfTestCase):
    pass


@skip_unless_have_libbpf
class TestCDeclarationObjectFinder(TestCase):
    def setUp(self):
        self.prog = Program(host_platform)

        int_type = self.prog.int_type("int", 4, True)
        pair_type = self.prog.struct_type(
            "pair",
            8,
            (
                TypeMember(int_type, "first", 0),
                TypeMember(int_type, "second", 32),
            ),
        )
        types = {
            (TypeKind.INT, "int"): int_type,
            (TypeKind.STRUCT, "pair"): pair_type,
        }

        def type_finder(prog, kinds, name, filename):
            if filename is None:
                for kind in kinds:
                    type_ = types.get((kind, name))
                    if type_ is not None:
                        return type_
            return None

        symbols = {
            "number": Symbol(
                "number", 0x1000, 4, SymbolBinding.GLOBAL, SymbolKind.OBJECT
            ),
            "numbers": Symbol(
                "numbers", 0x1004, 8, SymbolBinding.GLOBAL, SymbolKind.OBJECT
            ),
            "number_pointer": Symbol(
                "number_pointer", 0x100C, 8, SymbolBinding.GLOBAL, SymbolKind.OBJECT
            ),
            "pair": Symbol("pair", 0x1014, 8, SymbolBinding.GLOBAL, SymbolKind.OBJECT),
        }
        memory = struct.pack("=iiiQii", 42, 1, 2, 0x1000, -3, 4)

        def symbol_finder(prog, name, address, one):
            if name is not None and name in symbols:
                return (symbols[name],)
            return ()

        def memory_reader(address, count, offset, physical):
            return memory[offset : offset + count]

        self.prog.register_type_finder("test", type_finder, enable_index=0)
        self.prog.register_symbol_finder("test", symbol_finder, enable_index=0)
        self.prog.add_memory_segment(0x1000, len(memory), memory_reader)
        self.prog.register_object_finder(
            "test",
            build_c_declaration_object_finder(
                """
                // Declarations can be split over multiple lines.
                int number, numbers[2];
                int *number_pointer;

                struct pair pair; // And can have trailing comments.
                """
            ),
            enable_index=0,
        )

    def test_find_declared_objects(self):
        self.assertEqual(self.prog["number"].value_(), 42)
        self.assertEqual(self.prog["numbers"].value_(), [1, 2])
        self.assertEqual(self.prog["number_pointer"][0].value_(), 42)
        self.assertEqual(self.prog["pair"].value_(), {"first": -3, "second": 4})

        self.assertEqual(
            self.prog.object("number", FindObjectFlags.VARIABLE).value_(), 42
        )
        with self.assertRaises(LookupError):
            self.prog.object("number", FindObjectFlags.CONSTANT)
        with self.assertRaises(LookupError):
            self.prog.object("undeclared_symbol")

    def test_invalid_declaration(self):
        with self.assertRaisesRegex(ValueError, "Invalid declaration"):
            build_c_declaration_object_finder("int function(void);")
