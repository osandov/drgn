# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import errno
from fcntl import ioctl
import os
import os.path
import sys
import tempfile

from drgn.helpers.linux.block import (
    disk_devt,
    disk_name,
    for_each_disk,
    for_each_partition,
    part_devt,
    part_name,
)
from drgn.helpers.linux.device import MAJOR, MINOR, MKDEV
from tests.helpers.linux import LinuxHelperTestCase

LOOP_SET_FD = 0x4C00
LOOP_SET_STATUS64 = 0x4C04
LOOP_GET_STATUS64 = 0x4C05
LOOP_CTL_GET_FREE = 0x4C82

LO_FLAGS_AUTOCLEAR = 4


class TestBlock(LinuxHelperTestCase):
    @staticmethod
    def _losetup():
        with tempfile.TemporaryFile() as temp:
            os.truncate(temp.fileno(), 1024 * 1024 * 1024)
            with open("/dev/loop-control", "r") as loop_control:
                while True:
                    index = ioctl(loop_control.fileno(), LOOP_CTL_GET_FREE)
                    close_loop = True
                    loop = open(f"/dev/loop{index}", "r")
                    try:
                        try:
                            ioctl(loop.fileno(), LOOP_SET_FD, temp.fileno())
                        except OSError as e:
                            if e.errno == errno.EBUSY:
                                continue
                            raise
                        info = bytearray(232)  # sizeof(struct loop_info64)
                        ioctl(loop.fileno(), LOOP_GET_STATUS64, info)
                        lo_flags = int.from_bytes(info[52:56], sys.byteorder)
                        lo_flags |= LO_FLAGS_AUTOCLEAR
                        info[52:56] = lo_flags.to_bytes(4, sys.byteorder)
                        ioctl(loop.fileno(), LOOP_SET_STATUS64, info, False)
                        close_loop = False
                        return loop
                    finally:
                        if close_loop:
                            loop.close()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Try to set up a loop device so that there's at least one block
        # device.
        try:
            cls.loop = cls._losetup()
        except OSError:
            cls.loop = None

    @classmethod
    def tearDownClass(cls):
        if cls.loop:
            cls.loop.close()
        super().tearDownClass()

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

    def test_loop_disk(self):
        if not self.loop:
            self.skipTest("could not create loop device")
        rdev = os.stat(self.loop.fileno()).st_rdev
        devt = MKDEV(os.major(rdev), os.minor(rdev))
        for disk in for_each_disk(self.prog):
            if disk_devt(disk) == devt:
                break
        else:
            self.fail("loop disk not found")
        self.assertEqual(disk_name(disk), os.path.basename(self.loop.name).encode())

    def test_loop_part(self):
        if not self.loop:
            self.skipTest("could not create loop device")
        rdev = os.stat(self.loop.fileno()).st_rdev
        devt = MKDEV(os.major(rdev), os.minor(rdev))
        for part in for_each_partition(self.prog):
            if part_devt(part) == devt:
                break
        else:
            self.fail("loop partition not found")
        self.assertEqual(part_name(part), os.path.basename(self.loop.name).encode())
