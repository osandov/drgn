# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
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

    def test_register(self):
        self.assertIn("rax", Platform(Architecture.X86_64).register("rax").names)

    def test_register_size(self):
        self.assertEqual(Platform(Architecture.X86_64).register("rax").size, 8)

    def test_register_bad_name(self):
        self.assertRaises(TypeError, Platform(Architecture.X86_64).register, None)
        self.assertRaises(TypeError, Platform(Architecture.X86_64).register, b"foo")
        self.assertRaises(TypeError, Platform(Architecture.X86_64).register, 1)

    def test_unknown_register(self):
        self.assertRaises(LookupError, Platform(Architecture.X86_64).register, "foo")

    def test_register_unknown_architecture(self):
        self.assertRaises(
            LookupError,
            Platform(Architecture.UNKNOWN, PlatformFlags(0)).register,
            "rax",
        )
