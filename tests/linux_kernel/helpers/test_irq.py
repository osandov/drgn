# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path
import unittest

from _drgn_util.platform import NORMALIZED_MACHINE_NAME
from drgn.helpers.linux.cpumask import for_each_cpu
from drgn.helpers.linux.irq import (
    for_each_irq_desc,
    gate_desc_func,
    irq_desc_action_names,
    irq_desc_affinity_mask,
    irq_desc_chip_name,
    irq_desc_kstat_cpu,
    irq_to_desc,
)
from tests.linux_kernel import LinuxKernelTestCase, parse_range_list, possible_cpus


def proc_irq_smp_affinity_list(path):
    try:
        return (path / "smp_affinity_list").read_text()
    except FileNotFoundError:
        # The smp_affinity_list file doesn't exist on !SMP or for IRQs without
        # a handler.
        return Path("/sys/devices/system/cpu/online").read_text()


class TestIrq(LinuxKernelTestCase):
    def test_for_each_irq_desc(self):
        self.assertCountEqual(
            [irq for irq, _ in for_each_irq_desc(self.prog)],
            [int(path.name) for path in Path("/sys/kernel/irq").iterdir()],
        )

    def test_irq_desc_affinity(self):
        for path in Path("/proc/irq").iterdir():
            if not path.is_dir():
                continue
            irq = int(path.name)
            self.assertCountEqual(
                list(for_each_cpu(irq_desc_affinity_mask(irq_to_desc(self.prog, irq)))),
                parse_range_list(proc_irq_smp_affinity_list(path)),
            )
            return
        self.skipTest("IRQ not found")

    def test_irq_desc_action_names(self):
        # Try to test an interrupt with one action and one with multiple actions.
        single = None
        multiple = None
        for path in Path("/sys/kernel/irq").iterdir():
            expected = (path / "actions").read_bytes().rstrip(b"\n")
            if not expected:
                continue
            irq = int(path.name)

            if b"," in expected:
                multiple = irq, expected
            else:
                single = irq, expected
            if single is not None and multiple is not None:
                break

        with self.subTest("single"):
            if single is None:
                self.skipTest("IRQ with one action not found")
            irq, expected = single
            self.assertEqual(
                b",".join(irq_desc_action_names(irq_to_desc(self.prog, irq))), expected
            )

        with self.subTest("multiple"):
            if multiple is None:
                self.skipTest("IRQ with multiple actions not found")
            irq, expected = multiple
            self.assertEqual(
                b",".join(irq_desc_action_names(irq_to_desc(self.prog, irq))), expected
            )

    def test_irq_desc_chip_name(self):
        for path in Path("/sys/kernel/irq").iterdir():
            expected = (path / "chip_name").read_bytes().rstrip(b"\n")
            if not expected:
                continue
            irq = int(path.name)
            self.assertEqual(irq_desc_chip_name(irq_to_desc(self.prog, irq)), expected)
            return
        self.skipTest("IRQ with chip name not found")

    def test_irq_desc_kstat_cpu(self):
        cpu = min(possible_cpus())
        for path in Path("/sys/kernel/irq").iterdir():
            irq = int(path.name)
            expected = int((path / "per_cpu_count").read_text().partition(",")[0])
            # Prefer a non-zero count if we can find one.
            if expected:
                break
        self.assertAlmostEqual(
            irq_desc_kstat_cpu(irq_to_desc(self.prog, irq), cpu), expected, delta=1000
        )

    @unittest.skipUnless(NORMALIZED_MACHINE_NAME == "x86_64", "machine is not x86_64")
    def test_gate_desc_func(self):
        self.assertIn(
            "int3", self.prog.symbol(gate_desc_func(self.prog["idt_table"][3])).name
        )
