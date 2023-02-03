# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from contextlib import redirect_stdout
import io

from drgn.helpers.common.memory import identify_address
from drgn.helpers.common.stack import print_annotated_stack
from drgn.helpers.linux.mm import pfn_to_virt
from tests.linux_kernel import (
    HAVE_FULL_MM_SUPPORT,
    LinuxKernelTestCase,
    fork_and_sigwait,
    skip_unless_have_full_mm_support,
    skip_unless_have_test_kmod,
)


class TestIdentifyAddress(LinuxKernelTestCase):
    def test_identify_symbol(self):
        symbol = self.prog.symbol("__schedule")

        self.assertIn(
            identify_address(self.prog, symbol.address),
            ("symbol: __sched_text_start+0x0", "function symbol: __schedule+0x0"),
        )

        self.assertEqual(
            identify_address(self.prog, symbol.address + 1),
            "function symbol: __schedule+0x1",
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_slab_cache(self):
        for size in ("small", "big"):
            with self.subTest(size=size):
                objects = self.prog[f"drgn_test_{size}_slab_objects"]

                if self.prog["drgn_test_slob"]:
                    for obj in objects:
                        self.assertIsNone(identify_address(obj))
                else:
                    for obj in objects:
                        self.assertEqual(
                            identify_address(obj),
                            f"slab object: drgn_test_{size}+0x0",
                        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_unrecognized(self):
        start_addr = (pfn_to_virt(self.prog["min_low_pfn"])).value_()
        end_addr = (pfn_to_virt(self.prog["max_pfn"]) + self.prog["PAGE_SIZE"]).value_()

        self.assertIsNone(identify_address(self.prog, start_addr - 1))
        self.assertIsNone(identify_address(self.prog, end_addr))
        self.assertIsNone(identify_address(self.prog, self.prog["drgn_test_va"]))


class TestPrintAnnotatedStack(LinuxKernelTestCase):
    @skip_unless_have_test_kmod
    def test_print_annotated_stack(self):
        with fork_and_sigwait() as pid:
            trace = self.prog.stack_trace(pid)

            f = io.StringIO()
            with redirect_stdout(f):
                print_annotated_stack(trace)

            printed_trace = f.getvalue()

            if HAVE_FULL_MM_SUPPORT and not self.prog["drgn_test_slob"]:
                self.assertIn("slab object: task_struct", printed_trace)
            self.assertIn("[function symbol: schedule", printed_trace)
            self.assertIn("schedule at ", printed_trace)
