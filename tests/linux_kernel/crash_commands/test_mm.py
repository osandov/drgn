# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import mmap
import re

from drgn.helpers.linux.mm import PageUsage
from drgn.helpers.linux.slab import SlabTotalUsage
from tests.linux_kernel import skip_unless_have_test_disk, skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase
from tests.linux_kernel.helpers.test_swap import tmp_swaps


class TestBtop(CrashCommandTestCase):
    def test_single(self):
        addr = mmap.PAGESIZE * 2
        cmd = self.check_crash_command(f"btop {addr:x}")
        self.assertEqual(cmd.stdout, f"{addr:x}: 2\n")
        self.assertEqual(cmd.drgn_option.globals["phys_addr"], addr)
        self.assertEqual(cmd.drgn_option.globals["pfn"], 2)

    def test_multiple(self):
        addr1 = mmap.PAGESIZE * 2
        addr2 = mmap.PAGESIZE * 10
        cmd = self.check_crash_command(f"btop {addr1:x} {addr2:x}")
        self.assertEqual(cmd.stdout, f"{addr1:x}: 2\n{addr2:x}: a\n")
        self.assertRegex(cmd.drgn_option.stdout, r"\bfor\b.*\bin\b")
        self.assertEqual(cmd.drgn_option.globals["phys_addr"], addr2)
        self.assertEqual(cmd.drgn_option.globals["pfn"], 10)


class TestPtob(CrashCommandTestCase):
    def test_single(self):
        addr = mmap.PAGESIZE * 2
        cmd = self.check_crash_command("ptob 2")
        self.assertEqual(cmd.stdout, f"2: {addr:x}\n")
        self.assertEqual(cmd.drgn_option.globals["pfn"], 2)
        self.assertEqual(cmd.drgn_option.globals["phys_addr"], addr)

    def test_multiple(self):
        addr1 = mmap.PAGESIZE * 2
        addr2 = mmap.PAGESIZE * 10
        cmd = self.check_crash_command("ptob 2 10")
        self.assertEqual(cmd.stdout, f"2: {addr1:x}\na: {addr2:x}\n")
        self.assertRegex(cmd.drgn_option.stdout, r"\bfor\b.*\bin\b")
        self.assertEqual(cmd.drgn_option.globals["pfn"], 10)
        self.assertEqual(cmd.drgn_option.globals["phys_addr"], addr2)


class TestKmem(CrashCommandTestCase):
    def test_i(self):
        cmd = self.check_crash_command("kmem -i")
        for label in (
            "TOTAL MEM",
            "FREE",
            "USED",
            "BUFFERS",
            "CACHED",
            "SLAB",
            "TOTAL HUGE",
            "HUGE FREE",
            "TOTAL SWAP",
            "SWAP USED",
            "SWAP FREE",
            "COMMIT LIMIT",
            "COMMITTED",
        ):
            self.assertRegex(label, rf"(?m)^{label}\b")
        for variable in (
            "total_mem",
            "free",
            "used",
            "buffers",
            "cached",
            "commit_limit",
            "committed",
        ):
            self.assertIsInstance(cmd.drgn_option.globals[variable], int)
        self.assertIsInstance(cmd.drgn_option.globals["slab_usage"], SlabTotalUsage)
        for variable in (
            "hugetlb_usage",
            "swap_usage",
        ):
            self.assertIsInstance(cmd.drgn_option.globals[variable], PageUsage)

    @skip_unless_have_test_kmod
    def test_v(self):
        cmd = self.check_crash_command("kmem -v")
        self.assertIn(f"{self.prog['drgn_test_vmalloc_va'].value_():x}", cmd.stdout)
        self.assertIn("for_each_vmap_area(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["va"].type_.type_name(), "struct vmap_area *"
        )
        self.assertEqual(
            cmd.drgn_option.globals["vm"].type_.type_name(), "struct vm_struct *"
        )
        for variable in ("start", "end", "size"):
            self.assertIn(variable, cmd.drgn_option.globals)


class TestSwap(CrashCommandTestCase):
    @skip_unless_have_test_disk
    def test_swap(self):
        with tmp_swaps() as swaps:
            cmd = self.check_crash_command("swap")
            for path, is_file in swaps:
                type = "FILE" if is_file else "PARTITION"
                self.assertRegex(cmd.stdout, f"{type} .* {re.escape(str(path))}")
        self.assertEqual(
            cmd.drgn_option.globals["si"].type_.type_name(), "struct swap_info_struct *"
        )
        self.assertIn("pages", cmd.drgn_option.globals)
        self.assertIn("used_pages", cmd.drgn_option.globals)
        self.assertIn("priority", cmd.drgn_option.globals)
        self.assertIsInstance(cmd.drgn_option.globals["path"], bytes)
