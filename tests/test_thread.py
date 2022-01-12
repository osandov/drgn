# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import os.path
import subprocess
import tempfile
import unittest

from drgn import Program
from tests import TestCase


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

    CRASHED_TID = 2265419

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with tempfile.NamedTemporaryFile() as core_dump_file:
            try:
                subprocess.check_call(
                    [
                        "zstd",
                        "--quiet",
                        "--decompress",
                        "--stdout",
                        "tests/sample.coredump.zst",
                    ],
                    stdout=core_dump_file,
                )
            except FileNotFoundError:
                raise unittest.SkipTest("zstd not found")
            cls.prog = Program()
            cls.prog.set_core_dump(core_dump_file.name)

    def test_threads(self):
        self.assertSequenceEqual(
            sorted(thread.tid for thread in self.prog.threads()),
            self.TIDS,
        )

    def test_thread(self):
        for tid in self.TIDS:
            self.assertEqual(self.prog.thread(tid).tid, tid)
        self.assertRaises(LookupError, self.prog.thread, 99)

    def test_crashed_thread(self):
        self.assertEqual(self.prog.crashed_thread().tid, self.CRASHED_TID)
