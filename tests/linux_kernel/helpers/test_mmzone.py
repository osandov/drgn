# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.mmzone import NODE_DATA, for_each_online_pgdat
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


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
