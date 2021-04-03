# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import contextlib
import ctypes
import mmap
import os
import platform
import struct
import tempfile
import unittest

from drgn import FaultError
from drgn.helpers.linux.mm import (
    access_process_vm,
    access_remote_vm,
    cmdline,
    environ,
    page_to_pfn,
    pfn_to_page,
    pfn_to_virt,
    virt_to_pfn,
)
from drgn.helpers.linux.pid import find_task
from tests.helpers.linux import LinuxHelperTestCase, mlock


class TestMm(LinuxHelperTestCase):
    def test_page_constants(self):
        self.assertEqual(self.prog["PAGE_SIZE"], mmap.PAGESIZE)
        self.assertEqual(1 << self.prog["PAGE_SHIFT"], mmap.PAGESIZE)
        self.assertEqual(~self.prog["PAGE_MASK"] + 1, mmap.PAGESIZE)

    # Returns an mmap.mmap object for a file mapping, its mapped address, and
    # the pfns backing it.
    @contextlib.contextmanager
    def _pages(self):
        if not os.path.exists("/proc/self/pagemap"):
            self.skipTest("kernel does not support pagemap")

        pages = 4
        with tempfile.TemporaryFile() as f:
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

    def test_virt_to_from_pfn(self):
        with self._pages() as (map, _, pfns):
            for i, pfn in enumerate(pfns):
                virt = pfn_to_virt(self.prog, pfn)
                # Test that we got the correct virtual address by reading from
                # it and comparing it to the mmap.
                self.assertEqual(
                    self.prog.read(virt, mmap.PAGESIZE),
                    map[i * mmap.PAGESIZE : (i + 1) * mmap.PAGESIZE],
                )
                # Test the opposite direction.
                self.assertEqual(virt_to_pfn(virt), pfn)

    def test_pfn_to_from_page(self):
        with self._pages() as (map, _, pfns):
            for i, pfn in enumerate(pfns):
                page = pfn_to_page(self.prog, pfn)
                # Test that we got the correct page by looking at the index: it
                # should be page i in the file.
                self.assertEqual(page.index, i)
                # Test the opposite direction.
                self.assertEqual(page_to_pfn(page), pfn)

    def test_read_physical(self):
        with self._pages() as (map, _, pfns):
            for i, pfn in enumerate(pfns):
                self.assertEqual(
                    self.prog.read(pfn * mmap.PAGESIZE, mmap.PAGESIZE, True),
                    map[i * mmap.PAGESIZE : (i + 1) * mmap.PAGESIZE],
                )

    def test_access_process_vm(self):
        task = find_task(self.prog, os.getpid())
        data = b"hello, world"
        buf = ctypes.create_string_buffer(data)
        address = ctypes.addressof(buf)
        self.assertEqual(access_process_vm(task, address, len(data)), data)
        self.assertEqual(access_remote_vm(task.mm, address, len(data)), data)
        self.assertRaises(FaultError, access_process_vm, task, 0, 8)

    def test_access_process_vm_big(self):
        task = find_task(self.prog, os.getpid())
        with self._pages() as (map, address, _):
            self.assertEqual(access_process_vm(task, address, len(map)), map[:])
            self.assertEqual(
                access_process_vm(task, address + 1, len(map) - 1), map[1:]
            )
            self.assertEqual(
                access_process_vm(task, address + 1, len(map) - 2), map[1:-1]
            )

    @unittest.skipUnless(platform.machine() == "x86_64", "machine is not x86_64")
    def test_non_canonical_x86_64(self):
        task = find_task(self.prog, os.getpid())
        data = b"hello, world"
        buf = ctypes.create_string_buffer(data)
        address = ctypes.addressof(buf)
        self.assertRaises(
            FaultError, access_process_vm, task, address ^ (1 << 63), len(data)
        )

    def test_cmdline(self):
        with open("/proc/self/cmdline", "rb") as f:
            proc_cmdline = f.read().split(b"\0")[:-1]
        task = find_task(self.prog, os.getpid())
        self.assertEqual(cmdline(task), proc_cmdline)

    def test_environ(self):
        with open("/proc/self/environ", "rb") as f:
            proc_environ = f.read().split(b"\0")[:-1]
        task = find_task(self.prog, os.getpid())
        self.assertEqual(environ(task), proc_environ)
