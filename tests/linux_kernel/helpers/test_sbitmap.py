# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.sbitmap import sbitmap_for_each_set
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestSbitmap(LinuxKernelTestCase):
    def test_sbitmap_for_each_set(self):
        self.assertEqual(
            list(sbitmap_for_each_set(self.prog["drgn_test_sbitmap"].address_of_())),
            [13, 23, 24, 99],
        )
