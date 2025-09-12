# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from contextlib import redirect_stdout
import io

from _drgn_util.platform import NORMALIZED_MACHINE_NAME
from drgn import offsetof, sizeof
from drgn.helpers.common.memory import (
    IdentifiedSymbol,
    identify_address,
    identify_address_all,
    print_annotated_memory,
)
from drgn.helpers.common.stack import print_annotated_stack, print_registers
from drgn.helpers.linux.common import (
    IdentifiedSlabObject,
    IdentifiedTaskStack,
    IdentifiedTaskStruct,
    IdentifiedVmap,
)
from drgn.helpers.linux.mm import pfn_to_virt
from drgn.helpers.linux.sched import idle_task
from tests.linux_kernel import (
    HAVE_FULL_MM_SUPPORT,
    LinuxKernelTestCase,
    online_cpus,
    skip_if_slob,
    skip_unless_have_full_mm_support,
    skip_unless_have_stack_tracing,
    skip_unless_have_test_kmod,
)


class TestIdentifyAddress(LinuxKernelTestCase):
    @skip_unless_have_test_kmod
    def test_identify_symbol(self):
        symbol = self.prog.symbol("drgn_test_function")

        identified = list(identify_address_all(self.prog, symbol.address))
        self.assertIsInstance(identified[0], IdentifiedSymbol)
        self.assertEqual(str(identified[0]), "function symbol: drgn_test_function+0x0")
        # Module symbols are also vmapped.
        self.assertIsInstance(identified[1], IdentifiedVmap)
        self.assertEqual(len(identified), 2)

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
                        if size == "small":
                            self.assertEqual(
                                identify_address(obj), "unknown slab object"
                            )
                        else:
                            self.assertIsNone(identify_address(obj))
                else:
                    for obj in objects:
                        self.assertEqual(
                            identify_address(obj),
                            f"slab object: drgn_test_{size}+0x0",
                        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    @skip_if_slob
    def test_identify_task(self):
        identified = list(identify_address_all(self.prog["drgn_test_kthread"]))
        self.assertIsInstance(identified[0], IdentifiedTaskStruct)
        self.assertEqual(identified[0].task, self.prog["drgn_test_kthread"])
        self.assertEqual(
            str(identified[0]),
            f"task: {self.prog['drgn_test_kthread'].pid.value_()} (drgn_test_kthre)",
        )
        self.assertIsInstance(identified[1], IdentifiedSlabObject)
        self.assertEqual(len(identified), 2)

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    @skip_if_slob
    def test_identify_task_member(self):
        pid_offset = offsetof(self.prog.type("struct task_struct"), "pid")
        self.assertEqual(
            identify_address(self.prog, self.prog["drgn_test_kthread"].pid.address_),
            f"task: {self.prog['drgn_test_kthread'].pid.value_()} (drgn_test_kthre) +{hex(pid_offset)}",
        )

    def test_identify_idle_task_0(self):
        identified = list(identify_address_all(self.prog["init_task"].address_of_()))
        self.assertIsInstance(identified[0], IdentifiedTaskStruct)
        self.assertEqual(identified[0].task, idle_task(self.prog, 0))
        self.assertIsInstance(identified[1], IdentifiedSymbol)
        self.assertGreaterEqual(len(identified), 2)

    @skip_unless_have_full_mm_support
    @skip_if_slob
    def test_identify_idle_task_1(self):
        for cpu in online_cpus():
            if cpu > 0:
                break
        else:
            self.skipTest("online CPU > 0 not found")

        task = idle_task(self.prog, cpu)
        identified = list(identify_address_all(task))
        self.assertIsInstance(identified[0], IdentifiedTaskStruct)
        self.assertEqual(identified[0].task, task)
        self.assertIsInstance(identified[1], IdentifiedSlabObject)
        self.assertEqual(len(identified), 2)

    @skip_unless_have_test_kmod
    def test_identify_vmap(self):
        for cache in (None, {}):
            with self.subTest("uncached" if cache is None else "cached"):
                self.assertTrue(
                    identify_address(
                        self.prog["drgn_test_vmalloc_va"], cache=cache
                    ).startswith("vmap: 0x")
                )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_task_stack(self):
        if self.prog["drgn_test_slob"] and self.prog["drgn_test_slab_stack_enabled"]:
            self.skipTest("test does not support SLOB")

        for cached in (False, True):
            with self.subTest("cached" if cached else "uncached"):
                identified = list(
                    identify_address_all(
                        self.prog,
                        self.prog["drgn_test_kthread"].stack.value_() + 1234,
                        cache={} if cached else None,
                    )
                )
                self.assertIsInstance(identified[0], IdentifiedTaskStack)
                self.assertEqual(
                    str(identified[0]),
                    f"task stack: {self.prog['drgn_test_kthread'].pid.value_()} (drgn_test_kthre) +0x4d2",
                )
                if self.prog["drgn_test_vmap_stack_enabled"]:
                    self.assertIsInstance(identified[1], IdentifiedVmap)
                    self.assertEqual(len(identified), 2)
                elif self.prog["drgn_test_slab_stack_enabled"]:
                    self.assertIsInstance(identified[1], IdentifiedSlabObject)
                    self.assertEqual(len(identified), 2)
                else:
                    self.assertEqual(len(identified), 1)

    @skip_unless_have_full_mm_support
    def test_identify_idle_task_0_stack(self):
        identified = list(identify_address_all(self.prog["init_task"].stack))
        self.assertIsInstance(identified[0], IdentifiedTaskStack)
        self.assertEqual(identified[0].task, idle_task(self.prog, 0))
        # s390x between Linux kernel commits ce3dc447493f ("s390: add support
        # for virtually mapped kernel stacks") (in v4.20) and 944c78376a39
        # ("s390: use init_thread_union aka initial stack for the first
        # process") (in v6.4) allocates init_task.stack.
        if NORMALIZED_MACHINE_NAME == "s390x":
            if self.prog["drgn_test_vmap_stack_enabled"]:
                self.assertIsInstance(identified[1], (IdentifiedSymbol, IdentifiedVmap))
                self.assertEqual(len(identified), 2)
            elif self.prog["drgn_test_slab_stack_enabled"]:
                self.assertIsInstance(
                    identified[1], (IdentifiedSymbol, IdentifiedSlabObject)
                )
                self.assertEqual(len(identified), 2)
            elif len(identified) > 1:
                self.assertIsInstance(identified[1], IdentifiedSymbol)
                self.assertEqual(len(identified), 2)
        else:
            self.assertIsInstance(identified[1], IdentifiedSymbol)
            self.assertGreaterEqual(len(identified), 2)

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_idle_task_1_stack(self):
        if self.prog["drgn_test_slob"] and self.prog["drgn_test_slab_stack_enabled"]:
            self.skipTest("test does not support SLOB")

        for cpu in online_cpus():
            if cpu > 0:
                break
        else:
            self.skipTest("online CPU > 0 not found")

        task = idle_task(self.prog, cpu)

        for cached in (False, True):
            with self.subTest("cached" if cached else "uncached"):
                identified = list(
                    identify_address_all(task.stack, cache={} if cached else None)
                )
                self.assertIsInstance(identified[0], IdentifiedTaskStack)
                self.assertEqual(identified[0].task, task)
                if self.prog["drgn_test_vmap_stack_enabled"]:
                    self.assertIsInstance(identified[1], IdentifiedVmap)
                    self.assertEqual(len(identified), 2)
                elif self.prog["drgn_test_slab_stack_enabled"]:
                    self.assertIsInstance(identified[1], IdentifiedSlabObject)
                    self.assertEqual(len(identified), 2)
                else:
                    self.assertEqual(len(identified), 1)

    @skip_unless_have_test_kmod
    def test_identify_page(self):
        self.assertEqual(
            identify_address(self.prog["drgn_test_page"]),
            f"page: pfn {self.prog['drgn_test_pfn'].value_()}",
        )
        mapping_offset = offsetof(self.prog.type("struct page"), "mapping")
        self.assertEqual(
            identify_address(self.prog["drgn_test_page"].mapping.address_of_()),
            f"page: pfn {self.prog['drgn_test_pfn'].value_()} +{hex(mapping_offset)}",
        )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_unrecognized(self):
        start_addr = (pfn_to_virt(self.prog["min_low_pfn"])).value_()
        # On s390x, the start address is 0, and identify_address() doesn't
        # allow a negative address.
        if start_addr > 0:
            self.assertIsNone(identify_address(self.prog, start_addr - 1))
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
        # For CONFIG_SLOB, we cannot find slab objects. However,
        # print_annotated_memory() should still function with no error. So we
        # don't skip the test here: just skip the assertion.
        if not self.prog["drgn_test_slob"]:
            self.assertIn("slab object: drgn_test_small+0x0", f.getvalue())


class TestPrintAnnotatedStack(LinuxKernelTestCase):
    @skip_unless_have_stack_tracing
    @skip_unless_have_test_kmod
    def test_print_annotated_stack(self):
        trace = self.prog.stack_trace(self.prog["drgn_test_kthread"])

        f = io.StringIO()
        with redirect_stdout(f):
            print_annotated_stack(trace)

        printed_trace = f.getvalue()

        if HAVE_FULL_MM_SUPPORT and not self.prog["drgn_test_slob"]:
            self.assertIn("slab object: drgn_test_small", printed_trace)
        self.assertIn("[function symbol: schedule", printed_trace)
        self.assertIn("schedule at ", printed_trace)


class TestPrintRegisters(LinuxKernelTestCase):
    @skip_unless_have_stack_tracing
    @skip_unless_have_test_kmod
    def test_print_registers(self):
        trace = self.prog.stack_trace(self.prog["drgn_test_kthread_pt_regs"])
        # This is mostly a smoke test: we don't have any well-known registers,
        # and we don't have any specific guarantees about the availability of
        # registers. We can't even assert that all registers are present as hex
        # strings in the output, because some may be printed in decimal, and
        # others may be broken down into smaller fields.
        f = io.StringIO()
        with redirect_stdout(f):
            print_registers(self.prog, trace[0].registers())
