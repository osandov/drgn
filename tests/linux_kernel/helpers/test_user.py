# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os

from drgn.helpers.linux.user import find_user, for_each_user
from tests.linux_kernel import LinuxKernelTestCase, fork_and_stop


class TestUser(LinuxKernelTestCase):
    # Try a few UIDs in case the the hash function changes in the future.
    UIDS = frozenset({0, 430, 1000, 65537})

    def test_find_user(self):
        for uid in self.UIDS:
            with fork_and_stop(os.setuid, uid):
                found_uid = find_user(self.prog, uid).uid.val.value_()
            self.assertEqual(found_uid, uid)

    def test_for_each_user(self):
        with contextlib.ExitStack() as stack:
            for uid in self.UIDS:
                stack.enter_context(fork_and_stop(os.setuid, uid))
            found_uids = {user.uid.val.value_() for user in for_each_user(self.prog)}
        self.assertTrue(self.UIDS.issubset(found_uids))
