# Copyright (c) 2026, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.completion import completion_done, completion_for_each_task
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestCompletion(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.completion = cls.prog["drgn_test_completion"].address_of_()
        cls.done_completion = cls.prog["drgn_test_done_completion"].address_of_()

    def test_completion_done(self):
        self.assertFalse(completion_done(self.completion))
        self.assertTrue(completion_done(self.done_completion))

    def test_completion_for_each_task(self):
        self.assertEqual(list(completion_for_each_task(self.done_completion)), [])
        self.assertEqual(
            list(completion_for_each_task(self.completion)),
            [self.prog["drgn_test_completion_kthread"]],
        )
