# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os

from drgn import TypeKind
from drgn.helpers.linux.device import bus_for_each_dev, class_for_each_device, dev_name
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
