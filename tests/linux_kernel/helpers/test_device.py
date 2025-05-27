# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


from drgn.helpers.linux.device import (
    MAJOR,
    for_each_registered_blkdev,
    for_each_registered_chrdev,
)
from tests.linux_kernel import LinuxKernelTestCase


class TestDevice(LinuxKernelTestCase):
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

        self.assertCountEqual(
            [
                (MAJOR(dev), name)
                for dev, _, name, _ in for_each_registered_chrdev(self.prog)
            ],
            expected,
        )

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

        self.assertCountEqual(
            [(major, name) for major, name in for_each_registered_blkdev(self.prog)],
            expected,
        )
