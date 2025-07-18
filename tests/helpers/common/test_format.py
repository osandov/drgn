# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import io

from drgn import Program, TypeEnumerator
from drgn.helpers.common.format import (
    CellFormat,
    decode_enum_type_flags,
    decode_flags,
    number_in_binary_units,
    print_table,
)
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


class TestNumberInBinaryUnits(TestCase):
    def test_zero(self):
        self.assertEqual(number_in_binary_units(0), "0")

    def test_small(self):
        self.assertEqual(number_in_binary_units(100), "100")
        self.assertEqual(number_in_binary_units(1023), "1023")

    def test_small_negative(self):
        self.assertEqual(number_in_binary_units(-100), "-100")
        self.assertEqual(number_in_binary_units(-1023), "-1023")

    def test_integer(self):
        self.assertEqual(number_in_binary_units(1024), "1K")
        self.assertEqual(number_in_binary_units(1024**2), "1M")
        self.assertEqual(number_in_binary_units(1024**3), "1G")
        self.assertEqual(number_in_binary_units(1024**4), "1T")
        self.assertEqual(number_in_binary_units(1024**5), "1P")
        self.assertEqual(number_in_binary_units(1024**6), "1E")
        self.assertEqual(number_in_binary_units(1024**7), "1Z")
        self.assertEqual(number_in_binary_units(1024**8), "1Y")

    def test_negative_integer(self):
        self.assertEqual(number_in_binary_units(-1024), "-1K")
        self.assertEqual(number_in_binary_units(-(1024**2)), "-1M")
        self.assertEqual(number_in_binary_units(-(1024**3)), "-1G")
        self.assertEqual(number_in_binary_units(-(1024**4)), "-1T")
        self.assertEqual(number_in_binary_units(-(1024**5)), "-1P")
        self.assertEqual(number_in_binary_units(-(1024**6)), "-1E")
        self.assertEqual(number_in_binary_units(-(1024**7)), "-1Z")
        self.assertEqual(number_in_binary_units(-(1024**8)), "-1Y")

    def test_almost_integer(self):
        self.assertEqual(number_in_binary_units(1025), "1.0K")
        self.assertEqual(number_in_binary_units(1024**4 + 1), "1.0T")

    def test_precision(self):
        n = 1088
        self.assertEqual(number_in_binary_units(n, precision=0), "1K")
        self.assertEqual(number_in_binary_units(n, precision=1), "1.1K")
        self.assertEqual(number_in_binary_units(n, precision=2), "1.06K")

    def test_huge(self):
        self.assertEqual(number_in_binary_units(1024**8 * 1.5), "1.5Y")
        self.assertEqual(number_in_binary_units(1024**10), "1048576Y")


class TestPrintTable(TestCase):
    def assert_print_table(self, rows, expected, **kwargs):
        f = io.StringIO()
        print_table(rows, file=f)
        self.assertEqual(f.getvalue(), expected)

    def test_empty(self):
        self.assert_print_table([], "")

    def test_one_row(self):
        self.assert_print_table([["abc", "de", "fghi"]], "abc  de  fghi\n")

    def test_align(self):
        self.assert_print_table(
            [[2, 2000, 4], [13, 3, 19]],
            """\
 2  2000   4
13     3  19
""",
        )

    def test_empty_cell(self):
        self.assert_print_table(
            [[2, 2000, 4], ["", 3, 13, 19]],
            """\
2  2000   4
      3  13  19
""",
        )

    def test_cell_format(self):
        self.assert_print_table(
            [
                ["DECIMAL", "HEXADECIMAL"],
                [CellFormat(10, "<"), CellFormat(10, "<x")],
            ],
            """\
DECIMAL  HEXADECIMAL
10       a
""",
        )
