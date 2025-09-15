# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import mmap
import os
from pathlib import Path
import re
import unittest

from drgn.helpers.linux.mm import PageUsage
from drgn.helpers.linux.slab import SlabTotalUsage
from tests.linux_kernel import (
    possible_cpus,
    skip_unless_have_test_disk,
    skip_unless_have_test_kmod,
)
from tests.linux_kernel.crash_commands import CrashCommandTestCase
from tests.linux_kernel.helpers.test_slab import fallback_slab_cache_names
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


skip_unless_kmem_s_supported = unittest.skipUnless(
    # Good enough approximation for kmem -s support.
    Path("/proc/slabinfo").exists(),
    "kmem -s requires CONFIG_SLUB_DEBUG/!CONFIG_SLOB",
)


class TestKmem(CrashCommandTestCase):
    def test_f(self):
        cmd = self.check_crash_command("kmem -f")

        expected = set(
            re.findall(
                r"^Node\s+([0-9]+)\s*,\s*zone\s+(\w+)",
                Path("/proc/zoneinfo").read_text(),
                flags=re.MULTILINE,
            )
        )
        actual = set()
        header = 0
        for line in cmd.stdout.splitlines():
            if header == 0:
                match = re.match(r"(NODE\s+)?ZONE", line)
                if match:
                    header = 2 if match.group(1) else 1
            else:
                if header == 1:
                    actual.add(("0", re.match(r"\s*[0-9]+\s+(\w+)", line).group(1)))
                else:
                    actual.add(re.match(r"\s*([0-9]+)\s+[0-9]+\s+(\w+)", line).groups())
                header = 0
        # Since Linux kernel commit b2bd8598195f ("mm, vmstat: print
        # non-populated zones in zoneinfo") (in v4.12), these should be equal,
        # but before that, /proc/zoneinfo doesn't include all zones.
        self.assertGreaterEqual(actual, expected)
        self.assertRegex(cmd.stdout, r"nr_free_pages: [0-9]+")

        for variable in (
            "zone",
            "name",
            "size",
            "free",
            "mem_map",
            "start_paddr",
            "start_pfn",
            "order",
            "block_size",
            "migrate_type",
            "blocks",
            "pages",
        ):
            self.assertIn(variable, cmd.drgn_option.globals)
        for variable in (
            "expected_free_pages",
            "actual_free_pages",
        ):
            self.assertIsInstance(cmd.drgn_option.globals[variable], int)

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

    def test_o(self):
        cmd = self.check_crash_command("kmem -o")
        for cpu in possible_cpus():
            self.assertRegex(cmd.stdout, rf"CPU {cpu}:\s*[0-9a-f]+")
        self.assertIn("for_each_possible_cpu(", cmd.drgn_option.stdout)
        self.assertIn("per_cpu_ptr(", cmd.drgn_option.stdout)
        self.assertIn("offset", cmd.drgn_option.globals)

    def test_h(self):
        cmd = self.check_crash_command("kmem -h")
        try:
            names = os.listdir("/sys/kernel/mm/hugepages")
        except FileNotFoundError:
            names = []
        for name in names:
            self.assertIn(name, cmd.stdout)
        self.assertIn("for_each_hstate(", cmd.drgn_option.stdout)
        if names:
            self.assertEqual(
                cmd.drgn_option.globals["hstate"].type_.type_name(), "struct hstate *"
            )
            for variable in ("size", "free", "total", "name"):
                self.assertIn(variable, cmd.drgn_option.globals)

    def _test_s_common(self, cmd):
        self.assertEqual(
            cmd.drgn_option.globals["cache"].type_.type_name(), "struct kmem_cache *"
        )
        for variable in (
            "objsize",
            "usage",
            "allocated",
            "total",
            "slabs",
            "ssize",
            "name",
        ):
            self.assertIn(variable, cmd.drgn_option.globals)

    @skip_unless_kmem_s_supported
    def test_s(self):
        cmd = self.check_crash_command("kmem -s")

        for name in fallback_slab_cache_names(self.prog):
            self.assertRegex(cmd.stdout, rf"\b{re.escape(name.decode())}\b")

        self.assertIn("for_each_slab_cache(", cmd.drgn_option.stdout)
        self._test_s_common(cmd)

    @skip_unless_kmem_s_supported
    def test_s_match_one(self):
        names = sorted(name.decode() for name in fallback_slab_cache_names(self.prog))
        cmd = self.check_crash_command(f"kmem -s {names[0]}")

        self.assertRegex(cmd.stdout, rf"\b{re.escape(names[0])}\b")
        self.assertNotRegex(cmd.stdout, rf"\b{re.escape(names[1])}\b")

        self.assertIn('find_slab_cache("', cmd.drgn_option.stdout)
        self._test_s_common(cmd)

    @skip_unless_kmem_s_supported
    def test_s_match_multiple(self):
        names = sorted(name.decode() for name in fallback_slab_cache_names(self.prog))
        cmd = self.check_crash_command(f"kmem -s {' '.join(names)}")

        for name in names:
            self.assertRegex(cmd.stdout, rf"\b{re.escape(name)}\b")

        self.assertIn("find_slab_cache(search_name)", cmd.drgn_option.stdout)
        self._test_s_common(cmd)

    @skip_unless_kmem_s_supported
    def test_s_ignore_one(self):
        ignore = min(fallback_slab_cache_names(self.prog)).decode()
        cmd = self.check_crash_command(f"kmem -s -I {ignore}")

        self.assertRegex(cmd.stdout, rf"\[IGNORED\].*\b{re.escape(ignore)}\b")

        self.assertIn("for_each_slab_cache(", cmd.drgn_option.stdout)
        self.assertRegex(cmd.drgn_option.stdout, rf"== .*\b{re.escape(ignore)}\b")
        self._test_s_common(cmd)

    @skip_unless_kmem_s_supported
    def test_s_ignore_multiple(self):
        names = sorted(name.decode() for name in fallback_slab_cache_names(self.prog))
        cmd = self.check_crash_command(f"kmem -s -I {','.join(names)}")

        for name in names:
            self.assertRegex(cmd.stdout, rf"\[IGNORED\].*\b{re.escape(name)}\b")

        self.assertIn("for_each_slab_cache(", cmd.drgn_option.stdout)
        self.assertIn(" in ignore:", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["cache"].type_.type_name(), "struct kmem_cache *"
        )

    @skip_unless_kmem_s_supported
    def test_s_match_and_ignore(self):
        names = sorted(name.decode() for name in fallback_slab_cache_names(self.prog))
        cmd = self.check_crash_command(f"kmem -s {names[0]} -I {names[0]}")

        self.assertRegex(cmd.stdout, rf"\[IGNORED\].*\b{re.escape(names[0])}\b")
        self.assertNotRegex(cmd.stdout, rf"\b{re.escape(names[1])}\b")

        self.assertIn("find_slab_cache(", cmd.drgn_option.stdout)
        self.assertRegex(cmd.drgn_option.stdout, rf"== .*\b{re.escape(names[0])}\b")
        self.assertEqual(
            cmd.drgn_option.globals["cache"].type_.type_name(), "struct kmem_cache *"
        )


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
