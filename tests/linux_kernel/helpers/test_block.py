# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import os.path

from drgn import Object
from drgn.helpers.linux.block import (
    bdev_partno,
    disk_devt,
    disk_name,
    for_each_disk,
    for_each_partition,
    part_devt,
    part_name,
)
from drgn.helpers.linux.device import MAJOR, MINOR
from tests.linux_kernel import LinuxKernelTestCase


class TestBlock(LinuxKernelTestCase):
    def test_disk_devt(self):
        for disk in for_each_disk(self.prog):
            path = os.path.join(b"/sys/block", disk_name(disk), b"dev")
            with open(path, "r") as f:
                expected = f.read().strip()
            devt = disk_devt(disk).value_()
            self.assertEqual(f"{MAJOR(devt)}:{MINOR(devt)}", expected)

    def test_for_each_disk(self):
        self.assertEqual(
            {disk_name(disk).decode() for disk in for_each_disk(self.prog)},
            set(os.listdir("/sys/block")),
        )

    def test_part_devt(self):
        for part in for_each_partition(self.prog):
            path = os.path.join(b"/sys/class/block", part_name(part), b"dev")
            with open(path, "r") as f:
                expected = f.read().strip()
            devt = part_devt(part).value_()
            self.assertEqual(f"{MAJOR(devt)}:{MINOR(devt)}", expected)

    def test_for_each_partition(self):
        self.assertEqual(
            {part_name(part).decode() for part in for_each_partition(self.prog)},
            set(os.listdir("/sys/class/block")),
        )

    def test_bdev_partno(self):
        for part in for_each_partition(self.prog):
            try:
                with open(
                    os.path.join(b"/sys/class/block", part_name(part), b"partition"),
                    "r",
                ) as f:
                    partition = int(f.read())
            except FileNotFoundError:
                partition = 0
            if part.type_.type.tag == "hd_struct":
                self.skipTest("can't get bdev easily on old kernels")
            self.assertIdentical(bdev_partno(part), Object(self.prog, "u8", partition))
