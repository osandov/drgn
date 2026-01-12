# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import unittest

from drgn import NULL
from drgn.helpers.linux.locking import (
    RwsemLocked,
    mutex_owner,
    rwsem_locked,
    rwsem_owner,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod
from util import KernelVersion


@skip_unless_have_test_kmod
class TestLocking(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.kthread = cls.prog["drgn_test_locking_kthread"].read_()

    @unittest.skipIf(
        KernelVersion(os.uname().release) < KernelVersion("4.10")
        and "SMP" not in os.uname().version,
        "mutex_owner() is not supported on Linux < 4.10 !SMP",
    )
    def test_mutex_owner(self):
        self.assertEqual(
            mutex_owner(self.prog["drgn_test_mutex_locked"].address_of_()),
            self.kthread,
        )
        self.assertEqual(
            mutex_owner(self.prog["drgn_test_mutex_unlocked"].address_of_()),
            NULL(self.prog, "struct task_struct *"),
        )

    @unittest.skipIf(
        KernelVersion(os.uname().release) < KernelVersion("5.3")
        and "SMP" not in os.uname().version,
        "rwsem_locked() is not supported on Linux < 5.3 !SMP",
    )
    def test_rwsem_locked(self):
        self.assertEqual(
            rwsem_locked(self.prog["drgn_test_rwsem_read_locked"].address_of_()),
            RwsemLocked.READ_LOCKED,
        )
        self.assertEqual(
            rwsem_locked(self.prog["drgn_test_rwsem_write_locked"].address_of_()),
            RwsemLocked.WRITE_LOCKED,
        )
        self.assertEqual(
            rwsem_locked(
                self.prog["drgn_test_rwsem_previously_read_locked"].address_of_()
            ),
            RwsemLocked.UNLOCKED,
        )
        self.assertEqual(
            rwsem_locked(
                self.prog["drgn_test_rwsem_previously_write_locked"].address_of_()
            ),
            RwsemLocked.UNLOCKED,
        )
        self.assertEqual(
            rwsem_locked(self.prog["drgn_test_rwsem_never_locked"].address_of_()),
            RwsemLocked.UNLOCKED,
        )
        self.assertEqual(
            rwsem_locked(self.prog["drgn_test_rwsem_writer_waiting"].address_of_()),
            RwsemLocked.READ_LOCKED,
        )

    @unittest.skipIf(
        KernelVersion(os.uname().release) < KernelVersion("5.3")
        and "SMP" not in os.uname().version,
        "rwsem_owner() is not supported on Linux < 5.3 !SMP",
    )
    def test_rwsem_owner(self):
        if KernelVersion(os.uname().release) >= KernelVersion("4.20"):
            self.assertEqual(
                rwsem_owner(self.prog["drgn_test_rwsem_read_locked"].address_of_()),
                self.kthread,
            )
            self.assertEqual(
                rwsem_owner(self.prog["drgn_test_rwsem_writer_waiting"].address_of_()),
                self.kthread,
            )
        else:
            self.assertEqual(
                rwsem_owner(self.prog["drgn_test_rwsem_read_locked"].address_of_()),
                NULL(self.prog, "struct task_struct *"),
            )
            self.assertEqual(
                rwsem_owner(self.prog["drgn_test_rwsem_writer_waiting"].address_of_()),
                NULL(self.prog, "struct task_struct *"),
            )
        self.assertEqual(
            rwsem_owner(self.prog["drgn_test_rwsem_write_locked"].address_of_()),
            self.kthread,
        )
        self.assertEqual(
            rwsem_owner(
                self.prog["drgn_test_rwsem_previously_write_locked"].address_of_()
            ),
            NULL(self.prog, "struct task_struct *"),
        )
        self.assertEqual(
            rwsem_owner(self.prog["drgn_test_rwsem_never_locked"].address_of_()),
            NULL(self.prog, "struct task_struct *"),
        )
