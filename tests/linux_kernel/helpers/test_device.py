# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os

from drgn.helpers.linux.device import bus_for_each_dev, dev_name
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
