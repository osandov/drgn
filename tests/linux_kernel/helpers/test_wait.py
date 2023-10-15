# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.wait import waitqueue_active, waitqueue_for_each_task
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestWaitqueue(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        cls.waitq = cls.prog["drgn_test_waitq"].address_of_()
        cls.empty_waitq = cls.prog["drgn_test_empty_waitq"].address_of_()

    def test_waitqueue_active(self):
        self.assertTrue(waitqueue_active(self.waitq))
        self.assertFalse(waitqueue_active(self.empty_waitq))

    def test_waitqueue_for_each_task(self):
        self.assertEqual(list(waitqueue_for_each_task(self.empty_waitq)), [])
        self.assertEqual(
            list(waitqueue_for_each_task(self.waitq)),
            [self.prog["drgn_test_waitq_kthread"]],
        )
