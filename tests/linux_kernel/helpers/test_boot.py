# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from ctypes import c_int, c_int64, c_size_t, c_void_p
import mmap
import re
import unittest

from _drgn_util.platform import NORMALIZED_MACHINE_NAME
from drgn.helpers.linux.boot import pgtable_l5_enabled
from tests.linux_kernel import LinuxKernelTestCase, _c


def first_available_slot(size, min_addr):
    for line in open("/proc/self/maps"):
        start_str, end_str = re.match(r"([0-9a-f]+)-([0-9a-f]+).*", line).groups()
        start = int(start_str, 16)
        end = int(end_str, 16)
        if start >= min_addr + size:
            break
        elif end >= min_addr:
            min_addr = end
    return min_addr


def can_mmap_high_address():
    mmap_func = _c.mmap
    mmap_func.argtypes = [c_void_p, c_size_t, c_int, c_int, c_int, c_int64]
    mmap_func.restype = c_void_p
    munmap_func = _c.munmap
    munmap_func.argtypes = [c_void_p, c_size_t]
    hint_addr = first_available_slot(mmap.PAGESIZE, 1 << 48)

    ret = mmap_func(
        hint_addr,
        mmap.PAGESIZE,
        mmap.PROT_READ | mmap.PROT_WRITE,
        # Ideally we would use MAP_FIXED, but its value is not exposed by the
        # mmap module, and it varies by architecture. Having identified a free
        # slot in our memory mappings (and hopefully not changing them since
        # then), we can be reasonably confident that we should get the address
        # we hinted anyway.
        mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
        -1,
        0,
    )
    if ret != c_void_p(-1).value:
        munmap_func(ret, mmap.PAGESIZE)
    return ret == hint_addr


class TestBoot(LinuxKernelTestCase):
    @unittest.skipUnless(NORMALIZED_MACHINE_NAME == "x86_64", "machine is not x86_64")
    def test_pgtable_l5_enabled(self):
        self.assertEqual(pgtable_l5_enabled(self.prog), can_mmap_high_address())
