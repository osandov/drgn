# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import os.path

from drgn import Program
from tests import TestCase
from tests.resources import get_resource


class TestLive(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prog = Program()
        cls.prog.set_pid(os.getpid())

    def test_threads(self):
        tids = [thread.tid for thread in self.prog.threads()]
        self.assertIn(os.getpid(), tids)
        for tid in tids:
            self.assertEqual(self.prog.thread(tid).tid, tid)

    def test_thread_not_found(self):
        self.assertRaises(LookupError, self.prog.thread, 1)

    def test_main_thread(self):
        self.assertEqual(self.prog.main_thread().tid, os.getpid())

    def test_crashed_thread(self):
        self.assertRaisesRegex(
            ValueError,
            "crashed thread is only defined for core dumps",
            self.prog.crashed_thread,
        )


class TestCoreDump(TestCase):
    TIDS = (
        2265413,
        2265414,
        2265415,
        2265416,
        2265417,
        2265418,
        2265419,
        2265420,
        2265421,
        2265422,
        2265423,
        2265424,
        2265425,
    )

    MAIN_TID = 2265413
    CRASHED_TID = 2265419

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.prog = Program()
        cls.prog.set_core_dump(get_resource("multithreaded.core"))

    def test_threads(self):
        self.assertSequenceEqual(
            sorted(thread.tid for thread in self.prog.threads()),
            self.TIDS,
        )

    def test_thread(self):
        for tid in self.TIDS:
            self.assertEqual(self.prog.thread(tid).tid, tid)

    def test_thread_not_found(self):
        self.assertRaises(LookupError, self.prog.thread, 99)

    def test_main_thread(self):
        self.assertEqual(self.prog.main_thread().tid, self.MAIN_TID)

    def test_crashed_thread(self):
        self.assertEqual(self.prog.crashed_thread().tid, self.CRASHED_TID)
