# Copyright (c) 2024, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import NULL
from drgn.helpers.linux.locks import (
    get_rwsem_owner,
    get_rwsem_waiter_type,
    is_rwsem_reader_owned,
    is_rwsem_writer_owned,
    mutex_for_each_waiter_task,
    mutex_is_locked,
    mutex_owner,
    rwsem_for_each_waiter,
    rwsem_for_each_waiter_task,
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


@skip_unless_have_test_kmod
class TestRwsemaphore(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        cls.read_locked_rwsemaphore = cls.prog[
            "drgn_test_read_locked_rwsemaphore"
        ].address_of_()
        cls.write_locked_rwsemaphore = cls.prog[
            "drgn_test_write_locked_rwsemaphore"
        ].address_of_()
        cls.unlocked_rwsemaphore = cls.prog[
            "drgn_test_unlocked_rwsemaphore"
        ].address_of_()

    def test_is_rwsem_writer_owned(self):
        self.assertTrue(is_rwsem_writer_owned(self.write_locked_rwsemaphore))
        self.assertFalse(is_rwsem_writer_owned(self.read_locked_rwsemaphore))
        self.assertFalse(is_rwsem_writer_owned(self.unlocked_rwsemaphore))

    def test_is_rwsem_reader_owned(self):
        self.assertTrue(is_rwsem_reader_owned(self.read_locked_rwsemaphore))
        self.assertFalse(is_rwsem_reader_owned(self.write_locked_rwsemaphore))
        self.assertFalse(is_rwsem_reader_owned(self.unlocked_rwsemaphore))

    def test_get_rwsem_owner(self):
        self.assertEqual(
            get_rwsem_owner(self.write_locked_rwsemaphore),
            self.prog["drgn_test_rwsemaphore_write_owner_kthread"],
        )
        self.assertEqual(
            get_rwsem_owner(self.read_locked_rwsemaphore),
            NULL(self.prog, "struct task_struct *"),
        )
        self.assertEqual(
            get_rwsem_owner(self.unlocked_rwsemaphore),
            NULL(self.prog, "struct task_struct *"),
        )

    def test_get_rwsem_waiter_type(self):
        for waiter in rwsem_for_each_waiter(self.read_locked_rwsemaphore):
            self.assertEqual(get_rwsem_waiter_type(waiter), "down_write")
        for waiter in rwsem_for_each_waiter(self.write_locked_rwsemaphore):
            self.assertEqual(get_rwsem_waiter_type(waiter), "down_read")

    def test_rwsem_for_each_waiter_task(self):
        self.assertEqual(
            list(rwsem_for_each_waiter_task(self.unlocked_rwsemaphore)), []
        )
        self.assertEqual(
            list(rwsem_for_each_waiter_task(self.read_locked_rwsemaphore)),
            [self.prog["drgn_test_rwsemaphore_write_waiter_kthread"]],
        )
        self.assertEqual(
            list(rwsem_for_each_waiter_task(self.write_locked_rwsemaphore)),
            [self.prog["drgn_test_rwsemaphore_read_waiter_kthread"]],
        )
