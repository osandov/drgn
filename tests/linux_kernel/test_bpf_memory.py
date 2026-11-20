# Copyright (c) 2026, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import re
import unittest

from drgn import FaultError, Program, ProgramFlags
from drgn.helpers.linux.boot import kaslr_offset
from drgn.helpers.linux.mm import _page_type_mapcount_value, cmdline, follow_phys
from drgn.helpers.linux.pid import find_task, for_each_task
from tests.linux_kernel import LinuxKernelTestCase


def _kernel_version():
    match = re.match(r"(\d+)\.(\d+)", os.uname().release)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


# Reading kernel memory with BPF uses BPF_PROG_TYPE_SYSCALL (Linux 5.14).
@unittest.skipIf(_kernel_version() < (5, 14), "requires Linux 5.14 or newer")
class TestBpfMemory(LinuxKernelTestCase):
    # self.prog reads /proc/kcore; bpf_prog reads the same kernel with BPF.
    bpf_prog = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if TestBpfMemory.bpf_prog is None:
            prog = Program()
            try:
                prog.set_kernel_bpf()
            except NotImplementedError as e:
                # Not supported on this architecture.
                raise unittest.SkipTest(str(e))
            cls._load_debug_info(prog)
            TestBpfMemory.bpf_prog = prog

    def test_flags(self):
        self.assertEqual(
            self.bpf_prog.flags,
            ProgramFlags.IS_LINUX_KERNEL | ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL,
        )
        self.assertIsNone(self.bpf_prog.core_dump_path)

    def test_read_virtual(self):
        address = self.prog.symbol("linux_banner").address
        self.assertEqual(self.bpf_prog.read(address, 64), self.prog.read(address, 64))

    def test_read_large(self):
        # More than one BPF program run's worth, of memory that doesn't
        # change.
        address = self.prog.symbol("__start_rodata").address
        size = min(self.prog.symbol("__end_rodata").address - address, 1 << 20)
        self.assertGreater(size, 40000)
        self.assertEqual(
            self.bpf_prog.read(address, size), self.prog.read(address, size)
        )

    def test_read_physical(self):
        address = self.prog.symbol("linux_banner").address
        phys_addr = follow_phys(self.prog["init_mm"].address_of_(), address)
        self.assertEqual(
            self.bpf_prog.read(phys_addr, 64, True),
            self.prog.read(phys_addr, 64, True),
        )

    def test_page_table_walk(self):
        # Translating an address uses the physical memory segment.
        address = self.prog.symbol("linux_banner").address
        self.assertEqual(
            follow_phys(self.bpf_prog["init_mm"].address_of_(), address).value_(),
            follow_phys(self.prog["init_mm"].address_of_(), address).value_(),
        )

    def test_read_user(self):
        # User memory is read through the process's page tables.
        self.assertEqual(
            cmdline(find_task(self.bpf_prog, os.getpid())),
            cmdline(find_task(self.prog, os.getpid())),
        )

    def test_search_all_memory(self):
        # Searches of all kernel memory are done through the physical memory
        # segments, which must not include holes. The needle can be anywhere
        # (including in this test's own memory), so just check the match.
        needle = b"Linux version "
        address = next(self.bpf_prog.search_memory(needle))
        self.assertEqual(self.bpf_prog.read(address, len(needle)), needle)

    def test_fault(self):
        # Not a valid kernel address on any supported architecture.
        self.assertRaises(FaultError, self.bpf_prog.read, 1 << 63, 8)

    def test_tasks(self):
        pids = {task.pid.value_() for task in for_each_task(self.bpf_prog)}
        self.assertIn(1, pids)
        self.assertIn(os.getpid(), pids)


def _parse_vmcoreinfo(raw):
    info = {}
    for line in raw.decode().splitlines():
        key, sep, value = line.partition("=")
        if sep:
            info[key] = value
    return info


def _pre_lpa2_52_bit_pa(real):
    # Before Linux kernel commit bf74bb73cd87 ("arm64/mm: Reduce PA space to
    # 48 bits when LPA2 is not enabled"), AArch64 with 52-bit VA_BITS had a
    # 52-bit MAX_PHYSMEM_BITS even without LPA2, but no memory above 48 bits.
    # drgn uses 48.
    return (
        int(real.get("NUMBER(MAX_PHYSMEM_BITS)", "0"), 0) == 52
        and int(real.get("NUMBER(TCR_EL1_T1SZ)", "0"), 0) == 16
    )


# The vmtest kernels all have VMCOREINFO, so ignore it to test building it.
@unittest.skipIf(_kernel_version() < (5, 14), "requires Linux 5.14 or newer")
class TestBpfSynthesizedVmcoreinfo(LinuxKernelTestCase):
    bpf_prog = None
    kaslr_offset_error = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if TestBpfSynthesizedVmcoreinfo.bpf_prog is None:
            prog = Program()
            os.environ["DRGN_SYNTHESIZE_VMCOREINFO"] = "1"
            try:
                prog.set_kernel_bpf()
            except NotImplementedError as e:
                raise unittest.SkipTest(str(e))
            finally:
                del os.environ["DRGN_SYNTHESIZE_VMCOREINFO"]
            try:
                kaslr_offset(prog)
            except ValueError as e:
                TestBpfSynthesizedVmcoreinfo.kaslr_offset_error = e
            cls._load_debug_info(prog)
            TestBpfSynthesizedVmcoreinfo.bpf_prog = prog

    def test_vmcoreinfo(self):
        real = _parse_vmcoreinfo(self.prog["VMCOREINFO"].string_())
        synthesized = _parse_vmcoreinfo(self.bpf_prog["VMCOREINFO"].string_())

        def value(key, s):
            if key == "OSRELEASE":
                return s
            base = 16 if key == "KERNELOFFSET" or key.startswith("SYMBOL(") else 0
            # NUMBER()s may be printed as signed.
            return int(s, base) % (1 << 64)

        # Compare every key that the kernel also has.
        self.assertIn("SYMBOL(swapper_pg_dir)", synthesized)
        self.assertNotIn("KERNELOFFSET", synthesized)
        keys = [key for key in synthesized if key in real]
        expected = {key: value(key, real[key]) for key in keys}
        if _pre_lpa2_52_bit_pa(real):
            expected["NUMBER(MAX_PHYSMEM_BITS)"] = 48
        self.assertEqual({key: value(key, synthesized[key]) for key in keys}, expected)

    def test_from_debug_info(self):
        # These aren't in the synthesized VMCOREINFO, so they are computed
        # from debug info.
        names = (
            "NR_SECTION_ROOTS",
            "SECTIONS_PER_ROOT",
            "SECTION_SIZE_BITS",
            "MAX_PHYSMEM_BITS",
            "vmemmap",
        )
        expected = {name: self.prog[name].value_() for name in names}
        real = _parse_vmcoreinfo(self.prog["VMCOREINFO"].string_())
        if _pre_lpa2_52_bit_pa(real):
            expected["MAX_PHYSMEM_BITS"] = 48
            expected["NR_SECTION_ROOTS"] >>= 4
        self.assertEqual(
            {name: self.bpf_prog[name].value_() for name in names}, expected
        )
        page_types = ("buddy", "slab")
        self.assertEqual(
            {
                name: _page_type_mapcount_value(self.bpf_prog, name)
                for name in page_types
            },
            {name: _page_type_mapcount_value(self.prog, name) for name in page_types},
        )

    def test_kaslr_offset(self):
        # It isn't known until the kernel image is loaded.
        self.assertIsNotNone(self.kaslr_offset_error)
        self.assertEqual(kaslr_offset(self.bpf_prog), kaslr_offset(self.prog))

    def test_read(self):
        self.assertEqual(
            self.bpf_prog["init_task"].comm.string_(),
            self.prog["init_task"].comm.string_(),
        )
        address = self.prog.symbol("linux_banner").address
        self.assertEqual(
            follow_phys(self.bpf_prog["init_mm"].address_of_(), address).value_(),
            follow_phys(self.prog["init_mm"].address_of_(), address).value_(),
        )
        self.assertEqual(
            cmdline(find_task(self.bpf_prog, os.getpid())),
            cmdline(find_task(self.prog, os.getpid())),
        )
