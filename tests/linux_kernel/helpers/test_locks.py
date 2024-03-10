# Copyright (c) 2024, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import NULL
from drgn.helpers.linux.locks import (
    mutex_for_each_waiter_task,
    mutex_is_locked,
    mutex_owner,
    semaphore_for_each_waiter_task,
    semaphore_is_locked,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestMutex(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        cls.locked_mutex = cls.prog["drgn_test_locked_mutex"].address_of_()
        cls.unlocked_mutex = cls.prog["drgn_test_unlocked_mutex"].address_of_()

    def test_mutex_owner(self):
        self.assertEqual(
            mutex_owner(self.locked_mutex), self.prog["drgn_test_mutex_owner_kthread"]
        )
        self.assertEqual(
            mutex_owner(self.unlocked_mutex), NULL(self.prog, "struct task_struct *")
        )

    def test_mutex_is_locked(self):
        self.assertTrue(mutex_is_locked(self.locked_mutex))
        self.assertFalse(mutex_is_locked(self.unlocked_mutex))

    def test_for_each_mutex_waiter_task(self):
        self.assertEqual(list(mutex_for_each_waiter_task(self.unlocked_mutex)), [])
        self.assertEqual(
            list(mutex_for_each_waiter_task(self.locked_mutex)),
            [self.prog["drgn_test_mutex_waiter_kthread"]],
        )


@skip_unless_have_test_kmod
class TestSemaphore(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        cls.locked_semaphore = cls.prog["drgn_test_locked_semaphore"].address_of_()
        cls.unlocked_semaphore = cls.prog["drgn_test_unlocked_semaphore"].address_of_()

    def test_semaphore_is_locked(self):
        self.assertTrue(semaphore_is_locked(self.locked_semaphore))
        self.assertFalse(semaphore_is_locked(self.unlocked_semaphore))

    def test_semaphore_for_each_waiter_task(self):
        self.assertEqual(
            list(semaphore_for_each_waiter_task(self.unlocked_semaphore)), []
        )
        self.assertEqual(
            list(semaphore_for_each_waiter_task(self.locked_semaphore)),
            [self.prog["drgn_test_semaphore_waiter_kthread"]],
        )
