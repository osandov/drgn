# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import functools
import os
import signal

from drgn.helpers.linux.user import find_user, for_each_user
from tests.helpers.linux import (
    LinuxHelperTestCase,
    fork_and_pause,
    proc_state,
    wait_until,
)


class TestUser(LinuxHelperTestCase):
    # Try a few UIDs in case the the hash function changes in the future.
    UIDS = frozenset({0, 430, 1000, 65537})

    def test_find_user(self):
        for uid in self.UIDS:
            pid = fork_and_pause(functools.partial(os.setuid, uid))
            try:
                wait_until(lambda: proc_state(pid) == "S")
                found_uid = find_user(self.prog, uid).uid.val.value_()
            finally:
                os.kill(pid, signal.SIGKILL)
            self.assertEqual(found_uid, uid)

    def test_for_each_user(self):
        pids = []
        try:
            for uid in self.UIDS:
                pid = fork_and_pause(functools.partial(os.setuid, uid))
                wait_until(lambda: proc_state(pid) == "S")
                pids.append(pid)
            found_uids = {user.uid.val.value_() for user in for_each_user(self.prog)}
        finally:
            for pid in pids:
                os.kill(pid, signal.SIGKILL)
        self.assertTrue(self.UIDS.issubset(found_uids))
