# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from drgn import Program, TypeEnumerator
from drgn.helpers import decode_enum_type_flags, decode_flags
from tests import MOCK_PLATFORM, TestCase


class TestDecodeFlags(TestCase):
    FLAGS_BIT_NUMBERS = (("BOLD", 0), ("ITALIC", 1), ("UNDERLINE", 2))
    FLAGS_VALUES = tuple(
        (name, 1 << bit_number) for name, bit_number in FLAGS_BIT_NUMBERS
    )

    def assertDecodeFlags(self, value, expected):
        self.assertEqual(decode_flags(value, self.FLAGS_BIT_NUMBERS), expected)
        self.assertEqual(decode_flags(value, self.FLAGS_VALUES, False), expected)

    def test_one(self):
        self.assertDecodeFlags(1, "BOLD")
        self.assertDecodeFlags(2, "ITALIC")
        self.assertDecodeFlags(4, "UNDERLINE")

    def test_multiple(self):
        self.assertDecodeFlags(3, "BOLD|ITALIC")
        self.assertDecodeFlags(5, "BOLD|UNDERLINE")
        self.assertDecodeFlags(6, "ITALIC|UNDERLINE")
        self.assertDecodeFlags(7, "BOLD|ITALIC|UNDERLINE")

    def test_all_unknown(self):
        self.assertDecodeFlags(8, "0x8")

    def test_some_unknown(self):
        self.assertDecodeFlags(9, "BOLD|0x8")

    def test_alias(self):
        self.assertEqual(
            decode_flags(2, (("SMALL", 0), ("BIG", 1), ("LARGE", 1))), "BIG|LARGE"
        )
        self.assertEqual(
            decode_flags(2, (("SMALL", 1), ("BIG", 2), ("LARGE", 2)), False),
            "BIG|LARGE",
        )

    def test_zero(self):
        self.assertDecodeFlags(0, "0")

    def test_decode_enum_type_flags(self):
        prog = Program(MOCK_PLATFORM)

        for bit_numbers, flags in (
            (True, self.FLAGS_BIT_NUMBERS),
            (False, self.FLAGS_VALUES),
        ):
            with self.subTest(bit_numbers=bit_numbers):
                type = prog.enum_type(
                    None,
                    prog.int_type("int", 4, True),
                    [TypeEnumerator(*flag) for flag in flags],
                )
                self.assertEqual(
                    decode_enum_type_flags(4, type, bit_numbers), "UNDERLINE"
                )
                self.assertEqual(
                    decode_enum_type_flags(27, type, bit_numbers), "BOLD|ITALIC|0x18"
                )

    def test_decode_enum_type_flags_incomplete(self):
        self.assertRaisesRegex(
            TypeError,
            "incomplete",
            decode_enum_type_flags,
            2,
            Program().enum_type(None),
        )
