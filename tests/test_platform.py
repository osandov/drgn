# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import itertools
import unittest

from drgn import Architecture, Platform, PlatformFlags


class TestPlatform(unittest.TestCase):
    def test_default_flags(self):
        Platform(Architecture.X86_64)
        self.assertRaises(ValueError, Platform, Architecture.UNKNOWN)

    def test_registers(self):
        self.assertIn(
            "rax",
            itertools.chain.from_iterable(
                reg.names for reg in Platform(Architecture.X86_64).registers
            ),
        )
        self.assertEqual(Platform(Architecture.UNKNOWN, PlatformFlags(0)).registers, ())
