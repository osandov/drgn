# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.percpu import per_cpu, per_cpu_ptr
from tests.linux_kernel import (
    LinuxKernelTestCase,
    prng32,
    skip_unless_have_test_kmod,
    smp_enabled,
)


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

    @skip_unless_have_test_kmod
    def test_per_cpu_module_static(self):
        for cpu, expected in zip(for_each_possible_cpu(self.prog), prng32("PCPU")):
            self.assertEqual(
                per_cpu(self.prog["drgn_test_percpu_static"], cpu), expected
            )

    @skip_unless_have_test_kmod
    def test_per_cpu_module_dynamic(self):
        for cpu, expected in zip(for_each_possible_cpu(self.prog), prng32("pcpu")):
            self.assertEqual(
                per_cpu_ptr(self.prog["drgn_test_percpu_dynamic"], cpu)[0], expected
            )
