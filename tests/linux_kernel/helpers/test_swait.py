# Copyright (c) 2026, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.swait import swait_active, swait_for_each_task
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestSimpleWaitqueue(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.swaitq = cls.prog["drgn_test_swaitq"].address_of_()
        cls.empty_swaitq = cls.prog["drgn_test_empty_swaitq"].address_of_()

    def test_swait_active(self):
        self.assertTrue(swait_active(self.swaitq))
        self.assertFalse(swait_active(self.empty_swaitq))

    def test_swait_for_each_task(self):
        self.assertEqual(list(swait_for_each_task(self.empty_swaitq)), [])
        self.assertEqual(
            list(swait_for_each_task(self.swaitq)),
            [self.prog["drgn_test_swaitq_kthread"]],
        )
