# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from collections import defaultdict
from pathlib import Path

from drgn import NULL
from drgn.helpers.linux.mm import pfn_to_virt
from drgn.helpers.linux.slab import (
    find_containing_slab_cache,
    find_slab_cache,
    for_each_slab_cache,
    get_slab_cache_aliases,
    slab_cache_for_each_allocated_object,
    slab_cache_is_merged,
    slab_object_info,
)
from tests.linux_kernel import (
    LinuxKernelTestCase,
    skip_unless_have_full_mm_support,
    skip_unless_have_test_kmod,
)

SLAB_SYSFS_PATH = Path("/sys/kernel/slab")


def get_proc_slabinfo_names():
    with open("/proc/slabinfo", "rb") as f:
        # Skip the version and header.
        f.readline()
        f.readline()
        return [line.split()[0] for line in f]


def fallback_slab_cache_names(prog):
    # SLOB does not provide /proc/slabinfo. It is also disabled for SLUB if
    # CONFIG_SLUB_DEBUG=n. Before Linux kernel commit 5b36577109be ("mm:
    # slabinfo: remove CONFIG_SLABINFO") (in v4.15), it could also be disabled
    # for SLAB. So, pick a few slab caches which we know exist to test against.
    # In case they were merged into other caches, get their names from the
    # structs rather than just returning the names.
    return {
        prog["dentry_cache"].name.string_(),
        prog["mm_cachep"].name.string_(),
        prog["uid_cachep"].name.string_(),
    }


class TestSlab(LinuxKernelTestCase):
    def _slab_cache_aliases(self):
        if not SLAB_SYSFS_PATH.exists():
            self.skipTest(f"{str(SLAB_SYSFS_PATH)} does not exist")
        aliases = defaultdict(list)
        for child in SLAB_SYSFS_PATH.iterdir():
            if not child.name.startswith(":"):
                aliases[child.stat().st_ino].append(child.name)
        return aliases

    def test_slab_cache_is_merged_false(self):
        for aliases in self._slab_cache_aliases().values():
            if len(aliases) == 1:
                break
        else:
            self.skipTest("no unmerged slab caches")
        self.assertFalse(slab_cache_is_merged(find_slab_cache(self.prog, aliases[0])))

    def test_slab_cache_is_merged_true(self):
        for aliases in self._slab_cache_aliases().values():
            if len(aliases) > 1:
                break
        else:
            self.skipTest("no merged slab caches")
        for alias in aliases:
            slab_cache = find_slab_cache(self.prog, alias)
            if slab_cache is not None:
                break
        else:
            self.fail("couldn't find slab cache")
        self.assertTrue(slab_cache_is_merged(slab_cache))

    def test_get_slab_cache_aliases(self):
        if not SLAB_SYSFS_PATH.exists():
            # A SLOB or SLAB kernel, or one without SYSFS. Test that the
            # helper fails as expected.
            self.assertRaisesRegex(
                LookupError, "CONFIG_SYSFS", get_slab_cache_aliases, self.prog
            )
            return
        # Otherwise, the helper should work, test functionality.
        alias_to_name = get_slab_cache_aliases(self.prog)
        for aliases in self._slab_cache_aliases().values():
            # Alias groups of size 1 are either non-mergeable slabs, or
            # mergeable slabs which haven't actually been merged. Either way,
            # they should not be present in the dictionary.
            if len(aliases) == 1:
                self.assertNotIn(aliases[0], alias_to_name)
                continue

            # Find out which cache in the group is target -- it won't be
            # included in the alias dict.
            for alias in aliases:
                if alias not in alias_to_name:
                    target_alias = alias
                    aliases.remove(alias)
                    break
            else:
                self.fail("could not find target slab cache name")

            # All aliases should map to the same name
            for alias in aliases:
                self.assertEqual(alias_to_name[alias], target_alias)
            self.assertNotIn(target_alias, alias_to_name)

    def test_for_each_slab_cache(self):
        try:
            slab_cache_names = get_proc_slabinfo_names()
        except FileNotFoundError:
            # The found names should be a superset of the fallback names.
            self.assertGreaterEqual(
                {s.name.string_() for s in for_each_slab_cache(self.prog)},
                fallback_slab_cache_names(self.prog),
            )
        else:
            self.assertCountEqual(
                [s.name.string_() for s in for_each_slab_cache(self.prog)],
                slab_cache_names,
            )

    def test_find_slab_cache(self):
        try:
            slab_cache_names = get_proc_slabinfo_names()
        except FileNotFoundError:
            slab_cache_names = fallback_slab_cache_names(self.prog)
        for name in slab_cache_names:
            slab = find_slab_cache(self.prog, name)
            self.assertEqual(name, slab.name.string_())

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_slab_cache_for_each_allocated_object(self):
        for size in ("small", "big"):
            with self.subTest(size=size):
                cache = self.prog[f"drgn_test_{size}_kmem_cache"]
                objects = self.prog[f"drgn_test_{size}_slab_objects"]
                if self.prog["drgn_test_slob"]:
                    with self.assertRaisesRegex(ValueError, "SLOB is not supported"):
                        next(
                            slab_cache_for_each_allocated_object(
                                cache, f"struct drgn_test_{size}_slab_object"
                            )
                        )
                else:
                    self.assertEqual(
                        sorted(
                            slab_cache_for_each_allocated_object(
                                cache, f"struct drgn_test_{size}_slab_object"
                            ),
                            key=lambda obj: obj.value.value_(),
                        ),
                        list(objects),
                    )

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_slab_object_info(self):
        for size in ("small", "big"):
            with self.subTest(size=size):
                cache = self.prog[f"drgn_test_{size}_kmem_cache"]
                objects = self.prog[f"drgn_test_{size}_slab_objects"]
                if self.prog["drgn_test_slob"]:
                    self.assertIsNone(slab_object_info(objects[0]))
                else:
                    info = slab_object_info(objects[0])
                    self.assertEqual(info.slab_cache, cache)
                    self.assertEqual(info.address, objects[0].value_())
                    self.assertTrue(info.allocated)

                    info = slab_object_info(objects[0].value.address_of_())
                    self.assertEqual(info.slab_cache, cache)
                    self.assertEqual(info.address, objects[0].value_())
                    self.assertTrue(info.allocated)

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_find_containing_slab_cache(self):
        for size in ("small", "big"):
            with self.subTest(size=size):
                cache = self.prog[f"drgn_test_{size}_kmem_cache"]
                if self.prog["drgn_test_slob"]:
                    cache = NULL(self.prog, "struct kmem_cache *")
                objects = self.prog[f"drgn_test_{size}_slab_objects"]
                for obj in objects:
                    self.assertEqual(
                        find_containing_slab_cache(self.prog, obj.value_()), cache
                    )
                    self.assertEqual(find_containing_slab_cache(obj), cache)

    @skip_unless_have_full_mm_support
    @skip_unless_have_test_kmod
    def test_find_containing_slab_cache_invalid(self):
        start_addr = pfn_to_virt(self.prog["min_low_pfn"])
        end_addr = pfn_to_virt(self.prog["max_pfn"]) + self.prog["PAGE_SIZE"]

        self.assertEqual(
            find_containing_slab_cache(self.prog, start_addr - 1),
            NULL(self.prog, "struct kmem_cache *"),
        )
        self.assertEqual(
            find_containing_slab_cache(self.prog, end_addr),
            NULL(self.prog, "struct kmem_cache *"),
        )

        self.assertEqual(
            find_containing_slab_cache(self.prog, self.prog.symbol("jiffies").address),
            NULL(self.prog, "struct kmem_cache *"),
        )

        self.assertEqual(
            find_containing_slab_cache(self.prog, self.prog["drgn_test_va"]),
            NULL(self.prog, "struct kmem_cache *"),
        )
