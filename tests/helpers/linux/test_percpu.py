# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.percpu import per_cpu
from tests.linux_kernel import LinuxKernelTestCase, smp_enabled


class TestPerCpu(LinuxKernelTestCase):
    def test_per_cpu(self):
        smp = smp_enabled()
        for cpu in for_each_possible_cpu(self.prog):
            if smp:
                self.assertEqual(per_cpu(self.prog["runqueues"], cpu).cpu, cpu)
            else:
                # struct rq::cpu only exists if CONFIG_SMP=y, so just check
                # that we get something valid.
                self.assertEqual(
                    per_cpu(self.prog["runqueues"], cpu).idle.comm.string_(), b"swapper"
                )
