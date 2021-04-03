# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.percpu import per_cpu
from tests.helpers.linux import LinuxHelperTestCase


class TestPerCpu(LinuxHelperTestCase):
    def test_per_cpu(self):
        for cpu in for_each_possible_cpu(self.prog):
            self.assertEqual(per_cpu(self.prog["runqueues"], cpu).cpu, cpu)
