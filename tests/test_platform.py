# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later
import itertools

from drgn import Architecture, Platform, PlatformFlags
from tests import TestCase


class TestPlatform(TestCase):
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
