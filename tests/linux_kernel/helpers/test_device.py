# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os

from drgn import TypeKind
from drgn.helpers.linux.device import (
    MAJOR,
    bus_for_each_dev,
    class_for_each_device,
    dev_name,
    for_each_registered_blkdev,
    for_each_registered_chrdev,
)
from tests.linux_kernel import LinuxKernelTestCase


class TestDevice(LinuxKernelTestCase):
    def test_bus_for_each_dev(self):
        # This also tests dev_name() and bus_to_subsys().
        self.assertCountEqual(
            [
                dev_name(dev)
                for dev in bus_for_each_dev(self.prog["cpu_subsys"].address_of_())
            ],
            os.listdir(b"/sys/bus/cpu/devices"),
        )

    def test_class_for_each_device(self):
        # Before Linux kernel commit 7671284b6c77 ("/dev/mem: make mem_class a
        # static const structure") (in v6.5), mem_class is a pointer instead of
        # a struct.
        mem_class = self.prog["mem_class"]
        if mem_class.type_.unaliased_kind() != TypeKind.POINTER:
            mem_class = mem_class.address_of_()
        # This also tests dev_name() and class_to_subsys().
        self.assertCountEqual(
            [dev_name(dev) for dev in class_for_each_device(mem_class)],
            os.listdir(b"/sys/class/mem"),
        )

    def test_for_each_registered_chrdev(self):
        expected = []
        with open("/proc/devices", "rb") as f:
            ignore = True
            for line in f:
                line = line.rstrip(b"\n")
                if line == b"Character devices:":
                    ignore = False
                elif ignore:
                    pass
                elif not line:
                    break
                else:
                    tokens = line.split(maxsplit=1)
                    expected.append((int(tokens[0]), tokens[1]))

        actual = []
        for dev, _, name, cdev in for_each_registered_chrdev(self.prog):
            actual.append((MAJOR(dev), name))
            self.assertEqual(cdev.type_.type_name(), "struct cdev *")

        self.assertCountEqual(actual, expected)

    def test_for_each_registered_blkdev(self):
        expected = []
        with open("/proc/devices", "rb") as f:
            ignore = True
            for line in f:
                line = line.rstrip(b"\n")
                if line == b"Block devices:":
                    ignore = False
                elif ignore:
                    pass
                elif not line:
                    break
                else:
                    tokens = line.split(maxsplit=1)
                    expected.append((int(tokens[0]), tokens[1]))

        actual = []
        for major, name, obj in for_each_registered_blkdev(self.prog):
            actual.append((major, name))
            self.assertEqual(obj.type_.type_name(), "struct blk_major_name *")

        self.assertCountEqual(actual, expected)
