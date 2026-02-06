# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from pathlib import Path
import re
import tempfile

from drgn import Object
from drgn.commands import CommandArgumentError
from drgn.commands.crash import CRASH_COMMAND_NAMESPACE
from drgn.helpers.linux.mm import PageUsage
from drgn.helpers.linux.slab import SlabTotalUsage
from tests import with_default_prog
from tests.linux_kernel import (
    HAVE_FULL_MM_SUPPORT,
    possible_cpus,
    skip_unless_have_full_mm_support,
    skip_unless_have_test_kmod,
)
from tests.linux_kernel.crash_commands import CrashCommandTestCase
from tests.linux_kernel.helpers.test_slab import fallback_slab_cache_names
from util import KernelVersion

# Good enough approximation for full kmem -s support.
have_full_kmem_s_support = Path("/proc/slabinfo").exists()


class TestKmem(CrashCommandTestCase):
    def _test_free_common(self, flag):
        cmd = self.check_crash_command(f"kmem -{flag}")
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
            "num_blocks",
            "num_pages",
        ):
            self.assertIn(variable, cmd.drgn_option.globals)
        for variable in (
            "expected_free_pages",
            "actual_free_pages",
        ):
            self.assertIsInstance(cmd.drgn_option.globals[variable], int)
        if flag == "F":
            self.assertRegex(cmd.stdout, r"(?m)^[0-9a-f]+$")
            self.assertIsInstance(cmd.drgn_option.globals["page"], Object)

    def test_f(self):
        self._test_free_common("f")

    def test_F(self):
        self._test_free_common("F")

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

    def test_V(self):
        cmd = self.check_crash_command("kmem -V")
        labels = ["VM_ZONE_STAT", "VM_NODE_STAT"]
        vmstat_contents = Path("/proc/vmstat").read_text()
        # Before Linux kernel commit 3a321d2a3dde ("mm: change the call sites
        # of numa statistics items") (in v4.14), NUMA events are zone
        # statistics.
        if KernelVersion(os.uname().release) >= KernelVersion("4.14") and re.search(
            r"^numa_hit\b", vmstat_contents, flags=re.M
        ):
            labels.append(r"VM_NUMA_(EVENT|STAT)")
        if re.search(r"^pgmajfault\b", vmstat_contents, flags=re.M):
            labels.append("VM_EVENT_STATES")
        for label in labels:
            self.assertRegex(cmd.stdout, rf"(?m)^{label}:")

        for helper in (
            "global_zone_page_state",
            "global_node_page_state",
            "global_numa_event_state",
            "global_vm_event_state",
        ):
            self.assertIn(helper, cmd.drgn_option.stdout)
        for variable in ("name", "item", "value"):
            self.assertIn(variable, cmd.drgn_option.globals)

    @skip_unless_have_test_kmod
    def test_n(self):
        cmd = self.check_crash_command("kmem -n")

        expected = set(
            re.findall(
                r"^Node\s+([0-9]+)\s*,\s*zone\s+(\w+)",
                Path("/proc/zoneinfo").read_text(),
                flags=re.MULTILINE,
            )
        )
        actual = set()
        state = None
        for line in cmd.stdout.splitlines():
            if state is None:
                if re.match(r"\s*NODE\b", line):
                    state = "found_node_header"
            elif state == "found_node_header":
                match = re.match(r"\s*([0-9]+)", line)
                if match:
                    node = match.group(1)
                    state = "found_node"
                else:
                    state = None
            elif state == "found_node":
                if re.match(r"\s*ZONE\b", line):
                    state = "found_zone_header"
            elif state == "found_zone_header":
                match = re.match(r"\s*[0-9]+\s*(\w+)", line)
                if match:
                    actual.add((node, match.group(1)))
                else:
                    state = None
        # Since Linux kernel commit b2bd8598195f ("mm, vmstat: print
        # non-populated zones in zoneinfo") (in v4.12), these should be equal,
        # but before that, /proc/zoneinfo doesn't include all zones.
        self.assertGreaterEqual(actual, expected)

        for variable in (
            "node",
            "pgdat",
            "size",
            "start_pfn",
            "mem_map",
            "start_paddr",
            "zone",
            "zone_name",
            "zone_size",
            "zone_start_pfn",
            "zone_mem_map",
            "zone_start_paddr",
        ):
            self.assertIn(variable, cmd.drgn_option.globals)

        # Memory hotplug depends on SPARSEMEM, so this check is close enough
        # for both.
        if Path("/sys/bus/memory").exists():
            expected_section = (
                str(self.prog["drgn_test_section_nr"].value_()),
                f'{self.prog["drgn_test_mem_section"].value_():x}',
            )
            found_section_header = False
            found_section = False
            for line in cmd.stdout.splitlines():
                if found_section_header:
                    match = re.match(r"\s*([0-9]+)\s+([0-9a-f]+)", line)
                    if not match:
                        break
                    if match.groups() == expected_section:
                        found_section = True
                        break
                elif re.match(r"\s*NR\s+SECTION", line):
                    found_section_header = True
            self.assertTrue(found_section)

            expected = os.listdir("/sys/bus/memory/devices")
            actual = []
            found_memory_block_header = False
            for line in cmd.stdout.splitlines():
                if found_memory_block_header:
                    match = re.match(r"\s*[0-9a-f]+\s+(\S+)", line)
                    if not match:
                        break
                    actual.append(match.group(1))
                elif re.match(r"\s*MEMORY_BLOCK\b", line):
                    found_memory_block_header = True
            self.assertCountEqual(actual, expected)

            for variable in (
                "nr",
                "section",
                "coded_mem_map",
                "state",
                "pfn",
                "block_size",
                "mem",
                "name",
                "start_section_no",
                "physical_start",
                "physical_end",
                "node",
            ):
                self.assertIn(variable, cmd.drgn_option.globals)

    def test_z(self):
        cmd = self.check_crash_command("kmem -z")

        expected = set(
            re.findall(
                r"^Node\s+([0-9]+)\s*,\s*zone\s+(\w+)",
                Path("/proc/zoneinfo").read_text(),
                flags=re.MULTILINE,
            )
        )
        actual = set(
            re.findall(
                r'^NODE: ([0-9]+).*NAME: "([^"]+)"',
                cmd.stdout,
                flags=re.MULTILINE,
            )
        )
        # Since Linux kernel commit b2bd8598195f ("mm, vmstat: print
        # non-populated zones in zoneinfo") (in v4.12), these should be equal,
        # but before that, /proc/zoneinfo doesn't include all zones.
        self.assertGreaterEqual(actual, expected)

        for variable in (
            "node",
            "zone",
            "size",
            "present",
            "min_watermark",
            "low_watermark",
            "high_watermark",
            "stat_name",
            "stat_item",
            "stat_value",
        ):
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

    # For kmem -p and kmem -m, printing every page is too slow. Just get the
    # first few.
    @skip_unless_have_full_mm_support
    def test_p(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            CRASH_COMMAND_NAMESPACE.run(self.prog, f"kmem -p | head > {path}")
            for line in path.read_text().splitlines()[1:]:
                self.assertRegex(
                    line,
                    # PAGE
                    r"^[0-9a-f]+\s+"
                    # PHYSICAL
                    r"[0-9a-f]+\s+"
                    # MAPPING
                    r"[0-9a-f]+\s+"
                    # INDEX
                    r"[0-9a-f]+\s+"
                    # CNT
                    r"-?[0-9]+\s+"
                    # FLAGS
                    r"[0-9a-f]+( [\w,]+)?$",
                )

        drgn_option = self.run_crash_command_drgn_option("kmem -p", mode="capture")
        drgn_option_globals = {"prog": self.prog}
        with with_default_prog(self.prog):
            exec(drgn_option.stdout + "\n    break", drgn_option_globals)
        for variable in ("physical", "mapping", "index", "cnt", "flags"):
            self.assertIsInstance(drgn_option_globals[variable], Object)
        self.assertIsInstance(drgn_option_globals["decoded_flags"], str)

    @skip_unless_have_full_mm_support
    def test_m(self):
        members = "mapping,private,_refcount,lru,flags"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            CRASH_COMMAND_NAMESPACE.run(self.prog, f"kmem -m {members} | head > {path}")
            for line in path.read_text().splitlines()[1:]:
                self.assertRegex(
                    line,
                    # PAGE
                    r"^[0-9a-f]+\s+"
                    # mapping
                    r"[0-9a-f]+\s+"
                    # private
                    r"-?[0-9]+\s+"
                    # _refcount
                    r"-?[0-9]+\s+"
                    # lru
                    r"[0-9a-f]+,[0-9a-f]+\s+"
                    # flags
                    r"[0-9a-f]+$",
                )

        drgn_option = self.run_crash_command_drgn_option(
            f"kmem -m {members}", mode="capture"
        )
        drgn_option_globals = {"prog": self.prog}
        with with_default_prog(self.prog):
            exec(drgn_option.stdout + "\n    break", drgn_option_globals)
        for variable in ("mapping", "private", "_refcount", "lru", "flags"):
            self.assertIsInstance(drgn_option_globals[variable], Object)

    def check_kmem_s(self, options, check_common=True):
        cmd = self.check_crash_command("kmem -s " + options)
        self.assertEqual(
            cmd.drgn_option.globals["cache"].type_.type_name(), "struct kmem_cache *"
        )
        if check_common:
            for variable in (
                "objsize",
                "name",
            ):
                self.assertIn(variable, cmd.drgn_option.globals)
            if have_full_kmem_s_support:
                for variable in (
                    "usage",
                    "allocated",
                    "total",
                    "slabs",
                    "ssize",
                    "name",
                ):
                    self.assertIn(variable, cmd.drgn_option.globals)
        return cmd

    def test_s(self):
        cmd = self.check_kmem_s("")

        for name in fallback_slab_cache_names(self.prog):
            if have_full_kmem_s_support:
                self.assertRegex(cmd.stdout, rf"[0-9]+k\s+{re.escape(name.decode())}\b")
            else:
                self.assertRegex(cmd.stdout, rf"\b{re.escape(name.decode())}\b")

        self.assertIn("for_each_slab_cache(", cmd.drgn_option.stdout)

    def test_s_match_one(self):
        names = sorted(name.decode() for name in fallback_slab_cache_names(self.prog))
        cmd = self.check_kmem_s(names[0])

        if have_full_kmem_s_support:
            self.assertRegex(cmd.stdout, rf"[0-9]+k\s+{re.escape(names[0])}\b")
        else:
            self.assertRegex(cmd.stdout, rf"\b{re.escape(names[0])}\b")
        self.assertNotRegex(cmd.stdout, rf"\b{re.escape(names[1])}\b")

        self.assertIn('find_slab_cache("', cmd.drgn_option.stdout)

    def test_s_match_multiple(self):
        names = sorted(name.decode() for name in fallback_slab_cache_names(self.prog))
        cmd = self.check_kmem_s(" ".join(names))

        for name in names:
            if have_full_kmem_s_support:
                self.assertRegex(cmd.stdout, rf"[0-9]+k\s+{re.escape(name)}\b")
            else:
                self.assertRegex(cmd.stdout, rf"\b{re.escape(name)}\b")

        self.assertIn("find_slab_cache(search_name)", cmd.drgn_option.stdout)

    def test_s_ignore_one(self):
        ignore = min(fallback_slab_cache_names(self.prog)).decode()
        cmd = self.check_kmem_s(f"-I {ignore}")

        self.assertRegex(cmd.stdout, rf"\[IGNORED\].*\b{re.escape(ignore)}\b")

        self.assertIn("for_each_slab_cache(", cmd.drgn_option.stdout)
        self.assertRegex(cmd.drgn_option.stdout, rf"== .*\b{re.escape(ignore)}\b")

    def test_s_ignore_multiple(self):
        names = sorted(name.decode() for name in fallback_slab_cache_names(self.prog))
        cmd = self.check_kmem_s(f"-I {','.join(names)}", check_common=False)

        for name in names:
            self.assertRegex(cmd.stdout, rf"\[IGNORED\].*\b{re.escape(name)}\b")

        self.assertIn("for_each_slab_cache(", cmd.drgn_option.stdout)
        self.assertIn(" in ignore:", cmd.drgn_option.stdout)

    def test_s_match_and_ignore(self):
        names = sorted(name.decode() for name in fallback_slab_cache_names(self.prog))
        cmd = self.check_kmem_s(f"{names[0]} -I {names[0]}", check_common=False)

        self.assertRegex(cmd.stdout, rf"\[IGNORED\].*\b{re.escape(names[0])}\b")
        self.assertNotRegex(cmd.stdout, rf"\b{re.escape(names[1])}\b")

        self.assertIn("find_slab_cache(", cmd.drgn_option.stdout)
        self.assertRegex(cmd.drgn_option.stdout, rf"== .*\b{re.escape(names[0])}\b")

    def test_g_value(self):
        value = (1 << self.prog["PG_locked"].value_()) | (
            1 << self.prog["PG_uptodate"].value_()
        )
        cmd = self.check_crash_command(f"kmem -g {value:x}")
        self.assertIn("FLAGS:", cmd.stdout)
        self.assertIn("PG_locked", cmd.stdout)
        self.assertIn("PG_uptodate", cmd.stdout)
        self.assertNotIn("PG_dirty", cmd.stdout)
        self.assertIn("decode_page_flags_value", cmd.drgn_option.stdout)
        self.assertIn("PG_locked", cmd.drgn_option.globals["flags"])

    def test_g_no_value(self):
        cmd = self.check_crash_command("kmem -g")
        self.assertIn("PG_uptodate", cmd.stdout)
        self.assertIn(".enumerators", cmd.drgn_option.stdout)
        for variable in ("name", "bit", "value"):
            self.assertIn(variable, cmd.drgn_option.globals)

    @skip_unless_have_test_kmod
    def test_identify_symbol(self):
        address = self.prog.symbol("drgn_test_function").address
        cmd = self.run_crash_command(f"kmem {address:x}")
        self.assertRegex(
            cmd.stdout, rf"(?m)^{address:x} \(.\) drgn_test_function \[drgn_test\]$"
        )

    @skip_unless_have_test_kmod
    def test_identify_symbol_offset(self):
        symbol = self.prog.symbol("drgn_test_function")
        address = symbol.address + symbol.size - 1
        cmd = self.run_crash_command(f"kmem {address:x}")
        self.assertRegex(
            cmd.stdout,
            rf"(?m)^{address:x} \(.\) drgn_test_function\+{symbol.size - 1} \[drgn_test\]$",
        )

    def test_identify_task(self):
        cmd = self.check_crash_command(f"kmem {self.prog['init_task'].address_:x}")
        self.assertRegex(cmd.stdout, r'(?m)^COMMAND: "swapper')
        self.assertIn("identify_address", cmd.drgn_option.globals)
        self.assertTrue(cmd.drgn_option.globals["identified"])

    def test_identify_task_stack(self):
        cmd = self.run_crash_command(f"kmem {self.prog['init_task'].stack.value_():x}")
        self.assertRegex(cmd.stdout, r'(?m)^COMMAND: "swapper')

    @skip_unless_have_test_kmod
    def test_identify_vmalloc(self):
        address = self.prog["drgn_test_vmalloc_va"].value_()
        for option in ("", " -v"):
            with self.subTest(option=option):
                cmd = self.run_crash_command(f"kmem{option} {address:x}")
                self.assertIn("VMAP_AREA", cmd.stdout)
                self.assertIn(f"{address:x}", cmd.stdout)
                page_address = f"{self.prog['drgn_test_vmalloc_page'].value_():x}"
                if HAVE_FULL_MM_SUPPORT:
                    if option:
                        self.assertNotIn(page_address, cmd.stdout)
                    else:
                        self.assertIn(page_address, cmd.stdout)

    @skip_unless_have_test_kmod
    def test_identify_not_vmalloc(self):
        address = self.prog["drgn_test_small_slab_objects"][0].value_()
        cmd = self.run_crash_command(f"kmem -v {address:x}")
        self.assertIn("address is not allocated in vmalloc subsystem", cmd.stdout)
        self.assertNotIn("SLAB", cmd.stdout)

    @skip_unless_have_test_kmod
    def test_identify_page(self):
        address = self.prog["drgn_test_page"].value_()
        for option in ("", " -p"):
            with self.subTest(option=option):
                cmd = self.run_crash_command(f"kmem{option} {address + 1:x}")
                self.assertIn("PAGE", cmd.stdout)
                self.assertIn(f"{address:x}", cmd.stdout)

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_slab(self):
        address = self.prog["drgn_test_small_slab_objects"][0].value_()
        for option in ("", " -s"):
            with self.subTest(option=option):
                cmd = self.run_crash_command(f"kmem{option} {address + 1:x}")
                if self.prog["drgn_test_slob"]:
                    self.assertIn(
                        f"kmem: address is from SLOB: {address + 1:x}", cmd.stdout
                    )
                else:
                    self.assertIn("drgn_test_small", cmd.stdout)
                    self.assertIn(f"[{address:x}]", cmd.stdout)

    @skip_unless_have_test_kmod
    def test_identify_not_slab(self):
        address = self.prog["drgn_test_vmalloc_va"].value_()
        cmd = self.run_crash_command(f"kmem -s {address:x}")
        self.assertIn("address is not allocated in slab subsystem", cmd.stdout)
        self.assertNotIn("VMAP_AREA", cmd.stdout)

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_slab_with_names(self):
        address = self.prog["drgn_test_small_slab_objects"][0].value_()
        cmd = self.run_crash_command(f"kmem -s drgn_test_big {address + 1:x}")
        self.assertIn("ignoring pre-selected slab caches for address", cmd.stdout)
        if self.prog["drgn_test_slob"]:
            self.assertIn(f"kmem: address is from SLOB: {address + 1:x}", cmd.stdout)
        else:
            self.assertIn("drgn_test_small", cmd.stdout)
            self.assertIn(f"[{address:x}]", cmd.stdout)

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_slab_ignored(self):
        address = self.prog["drgn_test_small_slab_objects"][0].value_()
        cmd = self.run_crash_command(f"kmem -s -I drgn_test_small {address + 1:x}")
        if self.prog["drgn_test_slob"]:
            self.assertIn(f"kmem: address is from SLOB: {address + 1:x}", cmd.stdout)
        else:
            self.assertIn("drgn_test_small", cmd.stdout)
            self.assertIn("[IGNORED]", cmd.stdout)
            self.assertNotIn(f"[{address:x}]", cmd.stdout)

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_identify_multiple(self):
        slab_address = self.prog["drgn_test_small_slab_objects"][0].value_()
        vmalloc_address = self.prog["drgn_test_vmalloc_va"].value_()
        cmd = self.check_crash_command(f"kmem {vmalloc_address:x} {slab_address:x}")

        self.assertIn("VMAP_AREA", cmd.stdout)
        self.assertIn(f"{vmalloc_address:x}", cmd.stdout)

        if not self.prog["drgn_test_slob"]:
            self.assertIn("drgn_test_small", cmd.stdout)
            self.assertIn(f"[{slab_address:x}]", cmd.stdout)

        self.assertIn("identify_address", cmd.drgn_option.globals)
        self.assertTrue(cmd.drgn_option.globals["identified"])

    def test_no_arguments(self):
        self.assertRaises(CommandArgumentError, self.run_crash_command, "kmem")
