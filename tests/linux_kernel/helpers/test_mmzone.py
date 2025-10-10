# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import functools
import re
import unittest.mock

from drgn import NULL, Object, ObjectNotFoundError
import drgn.helpers.linux.mmzone
from drgn.helpers.linux.mmzone import (
    NODE_DATA,
    _section_flags,
    decode_section_flags,
    for_each_online_pgdat,
    for_each_present_section,
    high_wmark_pages,
    low_wmark_pages,
    min_wmark_pages,
    nr_to_section,
    pfn_to_section,
    pfn_to_section_nr,
    section_decode_mem_map,
    section_mem_map_addr,
    section_nr_to_pfn,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


def skip_unless_sparsemem(f):
    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        if "mem_section" not in self.prog:
            self.skipTest("kernel does not use SPARSEMEM")

    return wrapper


class TestMmzone(LinuxKernelTestCase):
    @skip_unless_have_test_kmod
    def test_NODE_DATA(self):
        self.assertEqual(
            NODE_DATA(self.prog["drgn_test_nid"]), self.prog["drgn_test_pgdat"]
        )

    @skip_unless_have_test_kmod
    def test_for_each_online_pgdat(self):
        self.assertEqual(
            next(for_each_online_pgdat(self.prog)), self.prog["drgn_test_pgdat"]
        )

    def test_wmark_pages(self):
        pgdat = next(for_each_online_pgdat(self.prog))
        nid = pgdat.node_id.value_()
        zone = pgdat.node_zones + 0
        zone_name = zone.name.string_().decode()
        expected = {}
        with open("/proc/zoneinfo", "r") as f:
            found_zone = False
            for line in f:
                match = re.match(r"Node ([0-9]+), zone\s+(\w+)", line)
                if match:
                    if found_zone:
                        break
                    elif int(match.group(1)) == nid and match.group(2) == zone_name:
                        found_zone = True
                elif found_zone:
                    match = re.match(r"\s*(min|low|high)\s+([0-9]+)", line)
                    if match:
                        expected[match.group(1)] = int(match.group(2))
            else:
                self.fail("zone not found")

        self.assertEqual(min_wmark_pages(zone), expected["min"])
        self.assertEqual(low_wmark_pages(zone), expected["low"])
        self.assertEqual(high_wmark_pages(zone), expected["high"])

    @skip_unless_have_test_kmod
    @skip_unless_sparsemem
    def test_nr_to_section(self):
        self.assertEqual(
            nr_to_section(self.prog["drgn_test_section_nr"]),
            self.prog["drgn_test_mem_section"],
        )

    @skip_unless_sparsemem
    def test_nr_to_section_out_of_bounds(self):
        self.assertEqual(
            nr_to_section(Object(self.prog, "unsigned long", -1)),
            NULL(self.prog, "struct mem_section *"),
        )

    @skip_unless_have_test_kmod
    @skip_unless_sparsemem
    def test_pfn_to_section_nr(self):
        self.assertEqual(
            pfn_to_section_nr(self.prog["drgn_test_pfn"]),
            self.prog["drgn_test_section_nr"],
        )

    @skip_unless_have_test_kmod
    @skip_unless_sparsemem
    def test_section_nr_to_pfn(self):
        self.assertEqual(
            section_nr_to_pfn(self.prog["drgn_test_section_nr"]),
            self.prog["drgn_test_section_pfn"],
        )

    @skip_unless_have_test_kmod
    @skip_unless_sparsemem
    def test_pfn_to_section(self):
        self.assertEqual(
            pfn_to_section(self.prog["drgn_test_pfn"]),
            self.prog["drgn_test_mem_section"],
        )

    @skip_unless_have_test_kmod
    @skip_unless_sparsemem
    def test_section_mem_map_addr(self):
        self.assertEqual(
            section_mem_map_addr(self.prog["drgn_test_mem_section"]),
            self.prog["drgn_test_section_mem_map"],
        )

    @skip_unless_have_test_kmod
    @skip_unless_sparsemem
    def test_section_decode_mem_map(self):
        self.assertEqual(
            section_decode_mem_map(self.prog["drgn_test_mem_section"]),
            self.prog["drgn_test_section_decoded_mem_map"],
        )

    @skip_unless_have_test_kmod
    @skip_unless_sparsemem
    def test_section_flags(self):
        flags = _section_flags(self.prog)
        for name in (
            "SECTION_MARKED_PRESENT",
            "SECTION_HAS_MEM_MAP",
            "SECTION_IS_ONLINE",
            "SECTION_IS_EARLY",
            "SECTION_TAINT_ZONE_DEVICE",
        ):
            with self.subTest(flag=name):
                try:
                    expected = self.prog["drgn_test_" + name].value_()
                except ObjectNotFoundError:
                    self.skipTest(f"{name} is not defined")
                self.assertEqual(flags[name], expected)

    @skip_unless_have_test_kmod
    @skip_unless_sparsemem
    def test_section_flag_getters(self):
        # These helpers are tricky to test because a typical VM setup will only
        # have sections with all of these flags set. So, we create fake
        # mem_section structures in the test kmod and check those. But that
        # means we have to monkey patch nr_to_section() to test the
        # foo_section_nr() helpers.
        prev_section = self.prog["drgn_test_valid_section"]
        for name in (
            "present_section",
            "valid_section",
            "online_section",
            "early_section",
        ):
            with self.subTest(helper=name):
                try:
                    section = self.prog["drgn_test_" + name]
                except ObjectNotFoundError:
                    self.skipTest(f"{name} is not defined")

                try:
                    helper = getattr(drgn.helpers.linux.mmzone, name)
                    self.assertTrue(helper(section))
                    self.assertFalse(helper(prev_section))
                    self.assertFalse(helper(NULL(self.prog, "struct mem_section *")))

                    nr_helper = getattr(drgn.helpers.linux.mmzone, name + "_nr")
                    with unittest.mock.patch(
                        "drgn.helpers.linux.mmzone.nr_to_section"
                    ) as mock_nr_to_section:
                        mock_nr_to_section.return_value = section
                        self.assertTrue(nr_helper(self.prog, 0))
                        mock_nr_to_section.return_value = prev_section
                        self.assertFalse(nr_helper(self.prog, 0))
                finally:
                    prev_section = section

    @skip_unless_have_test_kmod
    @skip_unless_sparsemem
    def test_decode_section_flags(self):
        self.assertIn(
            "SECTION_MARKED_PRESENT",
            decode_section_flags(self.prog["drgn_test_mem_section"]).split("|"),
        )

    @skip_unless_have_test_kmod
    @skip_unless_sparsemem
    def test_for_each_present_section(self):
        present_sections = self.prog["drgn_test_present_sections"]
        self.assertEqual(
            list(for_each_present_section(self.prog)),
            [
                (present_sections[i].nr.value_(), present_sections[i].section.read_())
                for i in range(self.prog["drgn_test_num_present_sections"])
            ],
        )
