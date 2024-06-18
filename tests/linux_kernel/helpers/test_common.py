# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from contextlib import redirect_stdout
import io

from drgn import sizeof
from drgn.helpers.common.memory import identify_address, print_annotated_memory
from drgn.helpers.common.stack import print_annotated_stack
from drgn.helpers.linux.mm import pfn_to_virt
from tests.linux_kernel import (
    HAVE_FULL_MM_SUPPORT,
    LinuxKernelTestCase,
    fork_and_stop,
    skip_unless_have_full_mm_support,
    skip_unless_have_stack_tracing,
    skip_unless_have_test_kmod,
)


class TestIdentifyAddress(LinuxKernelTestCase):
    @skip_unless_have_test_kmod
    def test_identify_symbol(self):
        symbol = self.prog.symbol("drgn_test_function")

        self.assertEqual(
            identify_address(self.prog, symbol.address),
            "function symbol: drgn_test_function+0x0",
        )

        self.assertEqual(
            identify_address(self.prog, symbol.address + 1),
            "function symbol: drgn_test_function+0x1",
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

    @skip_unless_have_test_kmod
    def test_identify_vmap(self):
        self.assertTrue(
            identify_address(self.prog["drgn_test_vmalloc_va"]).startswith("vmap: 0x")
        )

    @skip_unless_have_test_kmod
    def test_identify_vmap_stack(self):
        if not self.prog["drgn_test_vmap_stack_enabled"]:
            self.skipTest("kernel does not use vmap stacks (CONFIG_VMAP_STACK)")
        self.assertEqual(
            identify_address(
                self.prog, self.prog["drgn_test_kthread"].stack.value_() + 1234
            ),
            f"vmap stack: {self.prog['drgn_test_kthread'].pid.value_()} (drgn_test_kthre) +0x4d2",
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_unrecognized(self):
        start_addr = (pfn_to_virt(self.prog["min_low_pfn"])).value_()
        end_addr = (pfn_to_virt(self.prog["max_pfn"]) + self.prog["PAGE_SIZE"]).value_()

        # On s390x, the start address is 0, and identify_address() doesn't
        # allow a negative address.
        if start_addr > 0:
            self.assertIsNone(identify_address(self.prog, start_addr - 1))
        self.assertIsNone(identify_address(self.prog, end_addr))
        self.assertIsNone(identify_address(self.prog, self.prog["drgn_test_va"]))


class TestPrintAnnotatedMemory(LinuxKernelTestCase):
    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_print_annotated_memory(self):
        f = io.StringIO()
        with redirect_stdout(f):
            print_annotated_memory(
                self.prog,
                self.prog["drgn_test_small_slab_objects"].address_,
                sizeof(self.prog["drgn_test_small_slab_objects"]),
            )
        self.assertIn("slab object: drgn_test_small+0x0", f.getvalue())


class TestPrintAnnotatedStack(LinuxKernelTestCase):
    @skip_unless_have_stack_tracing
    @skip_unless_have_test_kmod
    def test_print_annotated_stack(self):
        with fork_and_stop() as pid:
            trace = self.prog.stack_trace(pid)

            f = io.StringIO()
            with redirect_stdout(f):
                print_annotated_stack(trace)

            printed_trace = f.getvalue()

            if HAVE_FULL_MM_SUPPORT and not self.prog["drgn_test_slob"]:
                self.assertIn("slab object: task_struct", printed_trace)
            self.assertIn("[function symbol: schedule", printed_trace)
            self.assertIn("schedule at ", printed_trace)
