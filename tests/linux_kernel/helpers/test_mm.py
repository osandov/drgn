# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import ctypes
import mmap
import os
import struct
import sys
import tempfile
import unittest

from drgn import NULL, FaultError
from drgn.helpers.linux.mm import (
    PFN_PHYS,
    PHYS_PFN,
    PageCompound,
    PageHead,
    PageSwapBacked,
    PageTail,
    PageWriteback,
    access_process_vm,
    access_remote_vm,
    cmdline,
    compound_head,
    compound_nr,
    compound_order,
    decode_page_flags,
    environ,
    find_vmap_area,
    follow_page,
    follow_pfn,
    follow_phys,
    for_each_vma,
    for_each_vmap_area,
    page_size,
    page_to_pfn,
    page_to_phys,
    page_to_virt,
    pfn_to_page,
    pfn_to_virt,
    phys_to_page,
    phys_to_virt,
    totalram_pages,
    virt_to_page,
    virt_to_pfn,
    virt_to_phys,
    vma_find,
    vmalloc_to_page,
    vmalloc_to_pfn,
)
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import (
    LinuxKernelTestCase,
    fork_and_stop,
    iter_maps,
    mlock,
    prng32,
    skip_unless_have_full_mm_support,
    skip_unless_have_test_kmod,
)
from util import NORMALIZED_MACHINE_NAME


class TestMm(LinuxKernelTestCase):
    def test_page_constants(self):
        self.assertEqual(self.prog["PAGE_SIZE"], mmap.PAGESIZE)
        self.assertEqual(1 << self.prog["PAGE_SHIFT"], mmap.PAGESIZE)
        self.assertEqual(~self.prog["PAGE_MASK"] + 1, mmap.PAGESIZE)

    # Returns an mmap.mmap object for a file mapping in /dev/shm, its mapped
    # address, and the pfns backing it.
    @contextlib.contextmanager
    def _pages(self):
        if not os.path.exists("/proc/self/pagemap"):
            self.skipTest("kernel does not support pagemap")

        pages = 4
        with tempfile.TemporaryFile(dir="/dev/shm") as f:
            f.write(os.urandom(pages * mmap.PAGESIZE))
            f.flush()
            with mmap.mmap(f.fileno(), pages * mmap.PAGESIZE) as map:
                f.close()
                address = ctypes.addressof(ctypes.c_char.from_buffer(map))
                # Make sure the pages are faulted in and stay that way.
                mlock(address, pages * mmap.PAGESIZE)

                with open("/proc/self/pagemap", "rb", buffering=0) as pagemap:
                    pagemap.seek(address // mmap.PAGESIZE * 8)
                    pfns = [
                        entry & ((1 << 54) - 1)
                        for entry in struct.unpack(f"{pages}Q", pagemap.read(pages * 8))
                    ]
                yield map, address, pfns

    def test_page_flag_getters(self):
        with self._pages() as (map, _, pfns):
            page = pfn_to_page(self.prog, pfns[0])
            # The page flag getters are generated, so just pick a positive case
            # and a negative case to cover all of them.
            self.assertTrue(PageSwapBacked(page))
            self.assertFalse(PageWriteback(page))

    @skip_unless_have_test_kmod
    def test_PageCompound(self):
        self.assertFalse(PageCompound(self.prog["drgn_test_page"]))
        self.assertTrue(PageCompound(self.prog["drgn_test_compound_page"]))
        self.assertTrue(PageCompound(self.prog["drgn_test_compound_page"] + 1))

    @skip_unless_have_test_kmod
    def test_PageHead(self):
        self.assertFalse(PageHead(self.prog["drgn_test_page"]))
        self.assertTrue(PageHead(self.prog["drgn_test_compound_page"]))
        self.assertFalse(PageHead(self.prog["drgn_test_compound_page"] + 1))

    @skip_unless_have_test_kmod
    def test_PageTail(self):
        self.assertFalse(PageTail(self.prog["drgn_test_page"]))
        self.assertFalse(PageTail(self.prog["drgn_test_compound_page"]))
        self.assertTrue(PageTail(self.prog["drgn_test_compound_page"] + 1))

    @skip_unless_have_test_kmod
    def test_compound_head(self):
        self.assertEqual(
            compound_head(self.prog["drgn_test_page"]), self.prog["drgn_test_page"]
        )
        self.assertEqual(
            compound_head(self.prog["drgn_test_compound_page"]),
            self.prog["drgn_test_compound_page"],
        )
        self.assertEqual(
            compound_head(self.prog["drgn_test_compound_page"] + 1),
            self.prog["drgn_test_compound_page"],
        )

    @skip_unless_have_test_kmod
    def test_compound_order(self):
        self.assertEqual(compound_order(self.prog["drgn_test_page"]), 0)
        self.assertEqual(compound_order(self.prog["drgn_test_compound_page"]), 1)

    @skip_unless_have_test_kmod
    def test_compound_nr(self):
        self.assertEqual(compound_nr(self.prog["drgn_test_page"]), 1)
        self.assertEqual(compound_nr(self.prog["drgn_test_compound_page"]), 2)

    @skip_unless_have_test_kmod
    def test_page_size(self):
        self.assertEqual(page_size(self.prog["drgn_test_page"]), self.prog["PAGE_SIZE"])
        self.assertEqual(
            page_size(self.prog["drgn_test_compound_page"]), 2 * self.prog["PAGE_SIZE"]
        )

    @skip_unless_have_full_mm_support
    def test_decode_page_flags(self):
        with self._pages() as (map, _, pfns):
            page = pfn_to_page(self.prog, pfns[0])
            self.assertIn("PG_swapbacked", decode_page_flags(page))

    @skip_unless_have_test_kmod
    def test_PFN_PHYS(self):
        self.assertEqual(
            PFN_PHYS(self.prog["drgn_test_pfn"]), self.prog["drgn_test_pa"]
        )

    @skip_unless_have_test_kmod
    def test_PHYS_PFN(self):
        self.assertEqual(
            PHYS_PFN(self.prog["drgn_test_pa"]), self.prog["drgn_test_pfn"]
        )

    @skip_unless_have_test_kmod
    def test_page_to_pfn(self):
        self.assertEqual(
            page_to_pfn(self.prog["drgn_test_page"]), self.prog["drgn_test_pfn"]
        )

    @skip_unless_have_test_kmod
    def test_page_to_phys(self):
        self.assertEqual(
            page_to_phys(self.prog["drgn_test_page"]), self.prog["drgn_test_pa"]
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_page_to_virt(self):
        self.assertEqual(
            page_to_virt(self.prog["drgn_test_page"]), self.prog["drgn_test_va"]
        )

    @skip_unless_have_test_kmod
    def test_pfn_to_page(self):
        self.assertEqual(
            pfn_to_page(self.prog["drgn_test_pfn"]), self.prog["drgn_test_page"]
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_pfn_to_virt(self):
        self.assertEqual(
            pfn_to_virt(self.prog["drgn_test_pfn"]), self.prog["drgn_test_va"]
        )

    @skip_unless_have_test_kmod
    def test_phys_to_page(self):
        self.assertEqual(
            phys_to_page(self.prog["drgn_test_pa"]), self.prog["drgn_test_page"]
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_phys_to_virt(self):
        self.assertEqual(
            phys_to_virt(self.prog["drgn_test_pa"]), self.prog["drgn_test_va"]
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_virt_to_page(self):
        self.assertEqual(
            virt_to_page(self.prog["drgn_test_va"]), self.prog["drgn_test_page"]
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_virt_to_pfn(self):
        self.assertEqual(
            virt_to_pfn(self.prog["drgn_test_va"]), self.prog["drgn_test_pfn"]
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_virt_to_phys(self):
        self.assertEqual(
            virt_to_phys(self.prog["drgn_test_va"]), self.prog["drgn_test_pa"]
        )

    @skip_unless_have_test_kmod
    def test_read_physical(self):
        expected = bytearray()
        for x in prng32("PAGE"):
            expected.extend(x.to_bytes(4, sys.byteorder))
            if len(expected) >= mmap.PAGESIZE:
                break
        self.assertEqual(
            self.prog.read(self.prog["drgn_test_pa"], mmap.PAGESIZE, True), expected
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_follow_phys(self):
        self.assertEqual(
            follow_phys(self.prog["init_mm"].address_of_(), self.prog["drgn_test_va"]),
            self.prog["drgn_test_pa"],
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_follow_page(self):
        self.assertEqual(
            follow_page(self.prog["init_mm"].address_of_(), self.prog["drgn_test_va"]),
            self.prog["drgn_test_page"],
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_follow_pfn(self):
        self.assertEqual(
            follow_pfn(self.prog["init_mm"].address_of_(), self.prog["drgn_test_va"]),
            self.prog["drgn_test_pfn"],
        )
        task = find_task(self.prog, os.getpid())
        with self._pages() as (map, address, pfns):
            self.assertEqual(follow_pfn(task.mm, address), pfns[0])

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_vmalloc_to_page(self):
        self.assertEqual(
            vmalloc_to_page(self.prog["drgn_test_vmalloc_va"]),
            self.prog["drgn_test_vmalloc_page"],
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_vmalloc_to_pfn(self):
        self.assertEqual(
            vmalloc_to_pfn(self.prog["drgn_test_vmalloc_va"]),
            self.prog["drgn_test_vmalloc_pfn"],
        )

    @skip_unless_have_test_kmod
    def test_find_vmap_area(self):
        self.assertEqual(
            find_vmap_area(
                self.prog, self.prog["drgn_test_vmalloc_va"] + 1234
            ).va_start.value_(),
            self.prog["drgn_test_vmalloc_va"].value_(),
        )

        with self.subTest("non-vmap address"):
            self.assertIdentical(
                find_vmap_area(self.prog, self.prog["drgn_test_va"]),
                NULL(self.prog, "struct vmap_area *"),
            )

    @skip_unless_have_test_kmod
    def test_for_each_vmap_area(self):
        self.assertTrue(
            any(
                va.va_start.value_() == self.prog["drgn_test_vmalloc_va"].value_()
                for va in for_each_vmap_area(self.prog)
            )
        )

    @skip_unless_have_full_mm_support
    def test_access_process_vm(self):
        task = find_task(self.prog, os.getpid())
        data = b"hello, world"
        buf = ctypes.create_string_buffer(data)
        address = ctypes.addressof(buf)
        self.assertEqual(access_process_vm(task, address, len(data)), data)
        self.assertEqual(access_remote_vm(task.mm, address, len(data)), data)
        self.assertRaises(FaultError, access_process_vm, task, 0, 8)

    @skip_unless_have_full_mm_support
    def test_access_process_vm_big(self):
        task = find_task(self.prog, os.getpid())
        # 32M = 2**(log2(16K) + log2(16K / 8)), so 32MB + 1 is enough so that
        # even with 16KB pages on a 64-bit architecture, we're guaranteed to
        # read across two second-level page table entries. (The same for 64KB
        # pages is 512MB + 1, which is too big to test reliably in vmtest.)
        max_size = 32 * 1024 * 1024 + 1
        expected = os.getrandom(max_size)
        while len(expected) < max_size:
            expected += os.getrandom(max_size - len(expected))
        address = ctypes.memmove(expected, expected, 0)
        expected = memoryview(expected)
        for size in (1, 65537, max_size):
            with self.subTest(size=size):
                self.assertEqual(
                    access_process_vm(task, address, size), expected[:size]
                )

    @skip_unless_have_full_mm_support
    def test_access_remote_vm_init_mm(self):
        data = self.prog["UTS_RELEASE"].string_()
        self.assertEqual(
            access_remote_vm(
                self.prog["init_mm"].address_of_(),
                self.prog["init_uts_ns"].name.release + 0,
                len(data),
            ),
            data,
        )

    @unittest.skipUnless(NORMALIZED_MACHINE_NAME == "x86_64", "machine is not x86_64")
    def test_non_canonical_x86_64(self):
        task = find_task(self.prog, os.getpid())
        data = b"hello, world"
        buf = ctypes.create_string_buffer(data)
        address = ctypes.addressof(buf)
        self.assertRaises(
            FaultError, access_process_vm, task, address ^ (1 << 63), len(data)
        )

    @skip_unless_have_full_mm_support
    def test_cmdline(self):
        with open("/proc/self/cmdline", "rb") as f:
            proc_cmdline = f.read().split(b"\0")[:-1]
        task = find_task(self.prog, os.getpid())
        self.assertEqual(cmdline(task), proc_cmdline)

    def test_cmdline_kernel_thread(self):
        self.assertIsNone(cmdline(find_task(self.prog, 2)))

    @skip_unless_have_full_mm_support
    def test_environ(self):
        with open("/proc/self/environ", "rb") as f:
            proc_environ = f.read().split(b"\0")[:-1]
        task = find_task(self.prog, os.getpid())
        self.assertEqual(environ(task), proc_environ)

    def test_environ_kernel_thread(self):
        self.assertIsNone(environ(find_task(self.prog, 2)))

    def test_vma_find(self):
        with fork_and_stop() as pid:
            mm = find_task(self.prog, pid).mm

            prev_end = 0
            for map in iter_maps(pid):
                # Gate VMAs are not included in vma_find().
                if map.is_gate():
                    continue

                if map.start != prev_end:
                    self.assertIdentical(
                        vma_find(mm, prev_end),
                        NULL(self.prog, "struct vm_area_struct *"),
                    )
                    self.assertIdentical(
                        vma_find(mm, map.start - 1),
                        NULL(self.prog, "struct vm_area_struct *"),
                    )
                vma = vma_find(mm, map.start)
                self.assertEqual((map.start, map.end), (vma.vm_start, vma.vm_end))

                vma = vma_find(mm, (map.start + map.end) // 2)
                self.assertEqual((map.start, map.end), (vma.vm_start, vma.vm_end))

                vma = vma_find(mm, map.end - 1)
                self.assertEqual((map.start, map.end), (vma.vm_start, vma.vm_end))

                prev_end = map.end

            self.assertIdentical(
                vma_find(mm, prev_end), NULL(self.prog, "struct vm_area_struct *")
            )

    def test_for_each_vma(self):
        with fork_and_stop() as pid:
            self.assertEqual(
                [
                    (vma.vm_start, vma.vm_end)
                    for vma in for_each_vma(find_task(self.prog, pid).mm)
                ],
                [
                    (map.start, map.end)
                    for map in iter_maps(pid)
                    # Gate VMAs are not included in for_each_vma().
                    if not map.is_gate()
                ],
            )

    def test_totalram_pages(self):
        with open("/proc/meminfo") as f:
            lines = f.read().splitlines()
            line = [line for line in lines if line.startswith("MemTotal:")][0]
            parts = line.split()
            self.assertEqual(parts[2], "kB")

            proc_totalram = 1024 * int(parts[1])
            page_size = self.prog["PAGE_SIZE"].value_()
            self.assertEqual(totalram_pages(self.prog) * page_size, proc_totalram)
