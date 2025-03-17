# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import Object
from drgn.helpers.linux.kthread import kthread_data
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestKthread(LinuxKernelTestCase):
    # There's no good way to test to_kthread() directly, but it gets tested
    # indirectly through kthread_data().
    def test_kthread_data(self):
        self.assertIdentical(
            kthread_data(self.prog["drgn_test_kthread"]),
            Object(self.prog, "void *", 0xB0BA000),
        )
