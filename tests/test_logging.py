# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import logging
import sys
import unittest

from drgn import Program
from tests import TestCase


# Test that our monkey patch to sync the log level between the logging module
# and libdrgn works.
class TestLogging(TestCase):
    def test_set_level_before(self):
        logger = logging.getLogger("drgn")
        with self.assertLogs(logger, "DEBUG") as cm:
            prog = Program()
            prog._log(0, "foo")
        self.assertIn("DEBUG:drgn:foo", cm.output)

    @unittest.skipIf(
        sys.version_info < (3, 7), "syncing log level only works since Python 3.7"
    )
    def test_set_level_after(self):
        prog = Program()
        logger = logging.getLogger("drgn")
        with self.assertLogs(logger, "DEBUG") as cm:
            prog._log(0, "bar")
        self.assertIn("DEBUG:drgn:bar", cm.output)
