# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from drgn.helpers.linux.slab import find_slab_cache, for_each_slab_cache
from tests.linux_kernel import LinuxKernelTestCase


def get_proc_slabinfo_names():
    with open("/proc/slabinfo", "rb") as f:
        # Skip the version and header.
        f.readline()
        f.readline()
        return [line.split()[0] for line in f]


class TestSlab(LinuxKernelTestCase):
    def test_for_each_slab_cache(self):
        self.assertCountEqual(
            get_proc_slabinfo_names(),
            [s.name.string_() for s in for_each_slab_cache(self.prog)],
        )

    def test_find_slab_cache(self):
        for name in get_proc_slabinfo_names():
            slab = find_slab_cache(self.prog, name)
            self.assertEqual(name, slab.name.string_())
