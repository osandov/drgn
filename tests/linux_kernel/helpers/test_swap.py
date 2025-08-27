# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import collections
import contextlib
import mmap
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import NamedTuple

from drgn.helpers.linux.swap import (
    for_each_swap_info,
    swap_file_path,
    swap_is_file,
    swap_total_usage,
    swap_usage_in_pages,
    total_swapcache_pages,
)
from tests.linux_kernel import (
    LinuxKernelTestCase,
    MbrPartition,
    MbrPartitionType,
    fallocate,
    meminfo_field_in_pages,
    mkswap,
    mount,
    skip_unless_have_test_disk,
    swapoff,
    swapon,
    umount,
    write_mbr,
)


class SwapInfo(NamedTuple):
    filename: str
    type: str
    size: int
    used: int
    priority: int


def iter_swaps():
    with open("/proc/swaps", "rb") as f:
        f.readline()
        for line in f:
            tokens = line.split()
            yield SwapInfo(
                filename=tokens[0].decode("unicode-escape"),
                type=tokens[1].decode("ascii"),
                size=int(tokens[2]) * 1024,
                used=int(tokens[3]) * 1024,
                priority=int(tokens[4]),
            )


@contextlib.contextmanager
def tmp_swaps():
    disk = os.environ["DRGN_TEST_DISK"]
    swaps = []

    with contextlib.ExitStack() as exit_stack:
        write_mbr(
            disk,
            [
                MbrPartition(
                    type=MbrPartitionType.LINUX_SWAP,
                    start=1024 * 1024,
                    size=8 * 1024 * 1024,
                ),
                MbrPartition(
                    type=MbrPartitionType.LINUX,
                    start=9 * 1024 * 1024,
                    size=8 * 1024 * 1024,
                ),
            ],
        )

        part_prefix = os.environ["DRGN_TEST_DISK"]
        if part_prefix[:-1].isdigit():
            part_prefix += "p"
        part1 = part_prefix + "1"
        part2 = part_prefix + "2"

        mkswap(part1)
        swapon(part1)
        exit_stack.callback(swapoff, part1)
        swaps.append((part1, False))

        subprocess.check_call(["mke2fs", "-qF", part2])
        tmp = Path(exit_stack.enter_context(tempfile.TemporaryDirectory()))
        mount(part2, tmp, "ext2")
        exit_stack.callback(umount, tmp)
        swap_file = tmp / "swap_file"
        fallocate(swap_file, 0, 1024 * 1024)
        mkswap(swap_file)
        swapon(swap_file)
        exit_stack.callback(swapoff, swap_file)
        swaps.append((swap_file, True))

        yield swaps


@skip_unless_have_test_disk
class TestSwap(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.enterClassContext(tmp_swaps())

    # There is no test_for_each_swap_info() because we test it implicitly in
    # the other tests. These tests also handle duplicate swap filenames, which
    # are unlikely but theoretically possible with namespace shenanigans.

    def test_swap_file_path(self):
        self.assertCountEqual(
            [os.fsdecode(swap_file_path(si)) for si in for_each_swap_info(self.prog)],
            [swap_info.filename for swap_info in iter_swaps()],
        )

    def test_swap_is_file(self):
        self.assertCountEqual(
            [
                (os.fsdecode(swap_file_path(si)), swap_is_file(si))
                for si in for_each_swap_info(self.prog)
            ],
            [
                (swap_info.filename, swap_info.type == "file")
                for swap_info in iter_swaps()
            ],
        )

    def test_swap_usage_in_pages(self):
        actual = collections.Counter()
        for si in for_each_swap_info(self.prog):
            actual[os.fsdecode(swap_file_path(si))] += (
                swap_usage_in_pages(si) * mmap.PAGESIZE
            )

        expected = collections.Counter()
        for swap_info in iter_swaps():
            expected[swap_info.filename] += swap_info.used

        for filename, used in expected.items():
            # Generous delta to allow for stuff getting swapped in/out while
            # the test is running.
            self.assertAlmostEqual(used, actual[filename], delta=1024 * 1024 * 1024)

    def test_swap_total_usage(self):
        swap_usage = swap_total_usage(self.prog)

        with open("/proc/meminfo", "r") as f:
            for line in f:
                if match := re.match(r"Swap(Total|Free):\s*([0-9]+)\s*kB", line):
                    value = int(match.group(2)) * 1024 // mmap.PAGESIZE
                    if match.group(1) == "Total":
                        pages = value
                    else:
                        free_pages = value

        self.assertEqual(swap_usage.pages, pages)
        # Generous delta to allow for stuff getting swapped in/out while the
        # test is running.
        self.assertAlmostEqual(
            swap_usage.free_pages, free_pages, delta=1024 * 1024 * 1024
        )

    def test_total_swapcache_pages(self):
        self.assertAlmostEqual(
            total_swapcache_pages(self.prog),
            meminfo_field_in_pages("SwapCached"),
            delta=1024 * 1024 * 1024,
        )
