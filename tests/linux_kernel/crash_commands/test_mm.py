# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright (c) 2025, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import mmap
import os
import re

from drgn import Object
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.mm import TaskRss, phys_to_virt
from drgn.helpers.linux.percpu import per_cpu_ptr
from tests.linux_kernel import skip_unless_have_test_disk
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


class TestPtov(CrashCommandTestCase):
    def test_phy_to_virt(self):
        """Test physical address to virtual address conversion."""
        phys_addr = 0x123
        virt_addr = phys_to_virt(self.prog, phys_addr)
        virt_addr_int = virt_addr.value_()

        cmd = self.check_crash_command(f"ptov {hex(phys_addr)}")
        self.assertRegex(cmd.stdout, r"(?m)^\s*VIRTUAL\s+PHYSICAL")
        self.assertRegex(cmd.stdout, rf"(?m)^\s*{virt_addr_int:016x}\s+{phys_addr:x}")

    def test_per_cpu_offset_single_cpu(self):
        """Test per-CPU offset conversion for a single CPU."""
        offset = 0x100
        cpu = 0
        ptr = Object(self.prog, "unsigned long", offset)
        virt_ptr = per_cpu_ptr(ptr, cpu)
        virt_int = virt_ptr.value_()

        cmd = self.check_crash_command(f"ptov {hex(offset)}:{cpu}")
        self.assertRegex(cmd.stdout, rf"(?m)^\s*PER-CPU OFFSET:\s+{offset:x}")
        self.assertRegex(cmd.stdout, r"(?m)^\s*CPU\s+VIRTUAL")
        self.assertRegex(cmd.stdout, rf"(?m)^\s*\[{cpu}\]\s+{virt_int:016x}")

    def test_per_cpu_offset_all_cpus(self):
        """Test per-CPU offset conversion for all CPUs."""
        offset = 0x200
        cmd = self.check_crash_command(f"ptov {hex(offset)}:a")

        self.assertRegex(cmd.stdout, rf"(?m)^\s*PER-CPU OFFSET:\s+{offset:x}")
        self.assertRegex(cmd.stdout, r"(?m)^\s*CPU\s+VIRTUAL")

        ptr = Object(self.prog, "unsigned long", offset)
        for cpu in for_each_online_cpu(self.prog):
            virt = per_cpu_ptr(ptr, cpu)
            self.assertRegex(cmd.stdout, rf"(?m)^\s*\[{cpu}\]\s+{virt.value_():016x}")

    def test_per_cpu_offset_cpu_list(self):
        """Test per-CPU offset conversion for a CPU list."""
        offset = 0x300
        cpus = sorted(os.sched_getaffinity(0))
        cmd = self.check_crash_command(f"ptov {hex(offset)}:{','.join(map(str, cpus))}")

        self.assertRegex(cmd.stdout, rf"(?m)^\s*PER-CPU OFFSET:\s+{offset:x}")
        self.assertRegex(cmd.stdout, r"(?m)^\s*CPU\s+VIRTUAL")

        ptr = Object(self.prog, "unsigned long", offset)
        for cpu in cpus:
            virt = per_cpu_ptr(ptr, cpu)
            self.assertRegex(cmd.stdout, rf"(?m)^\s*\[{cpu}\]\s+{virt.value_():016x}")

    def test_invalid_address(self):
        """Test invalid physical address input."""
        with self.assertRaises(Exception) as cm:
            self.check_crash_command("ptov invalid_address")
        msg = str(cm.exception).lower()
        self.assertTrue(
            "invalid literal" in msg or "base 16" in msg,
            f"Unexpected error message: {msg}",
        )

    def test_invalid_cpu_spec(self):
        """Test invalid per-CPU specifier."""
        offset = 0x400
        with self.assertRaises(Exception) as cm:
            self.check_crash_command(f"ptov {hex(offset)}:invalid")
        msg = str(cm.exception).lower()
        self.assertIn("invalid cpuspec", msg, f"Unexpected error message: {msg}")


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


class TestVm(CrashCommandTestCase):
    def _test_common(self, cmd):
        self.assertRegex(
            cmd.stdout,
            r"\bMM\s+PGD\s+RSS\s+TOTAL_VM(?:\s+[0-9a-f]+){2}(?:\s+[0-9]+k){2}\b",
        )
        self.assertRegex(
            cmd.stdout, r"\bVMA\s+START\s+END\s+FLAGS\s+FILE(?:\s+[0-9a-f]+){4}"
        )
        self.assertRegex(cmd.stdout, r"\bVMA(?s:.)*/")  # Check for any file path.

    def _test_drgn_option_common(self, cmd):
        for variable in (
            "pid",
            "task",
            "command",
            "mm",
            "pgd",
            "vma",
            "start",
            "end",
            "flags",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIsInstance(cmd.drgn_option.globals["cpu"], int)
        self.assertIsInstance(cmd.drgn_option.globals["rss"], TaskRss)
        self.assertIsInstance(cmd.drgn_option.globals["file"], str)

    def test_no_args(self):
        self.run_crash_command("set -p")

        cmd = self.check_crash_command("vm")
        self.assertIn(f"PID: {os.getpid()}", cmd.stdout)
        self._test_common(cmd)

        self._test_drgn_option_common(cmd)

    def test_tasks(self):
        cmd = self.check_crash_command(f"vm 1 {os.getpid()}")
        foreach_cmd = self.check_crash_command(
            f"foreach 1 {os.getpid()} vm", mode="capture"
        )

        for c in (cmd, foreach_cmd):
            self.assertIn("PID: 1", c.stdout)
            self.assertIn(f"PID: {os.getpid()}", c.stdout)
            self._test_common(c)

        self._test_drgn_option_common(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_kernel_thread(self):
        cmd = self.check_crash_command("vm 2")

        self.assertRegex(cmd.stdout, r"\bMM\s+PGD\s+RSS\s+TOTAL_VM\s+0\s+0\s+0k\s+0k\b")
        self.assertNotIn("VMA", cmd.stdout)

        self.assertFalse(cmd.drgn_option.globals["mm"])
