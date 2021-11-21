# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from drgn import Object
from drgn.helpers.linux.bitops import for_each_clear_bit, for_each_set_bit, test_bit
from tests import MockProgramTestCase


class TestBitOps(MockProgramTestCase):
    BITMAP = [0xB351BC986648A680, 0x80DDB6615A80BC63]
    # fmt: off
    SET_BITS = [
        7, 9, 10, 13, 15, 19, 22, 25, 26, 29, 30, 35, 36, 39, 42, 43, 44, 45,
        47, 48, 52, 54, 56, 57, 60, 61, 63, 64, 65, 69, 70, 74, 75, 76, 77, 79,
        87, 89, 91, 92, 94, 96, 101, 102, 105, 106, 108, 109, 111, 112, 114,
        115, 116, 118, 119, 127,
    ]
    CLEAR_BITS = [
        0, 1, 2, 3, 4, 5, 6, 8, 11, 12, 14, 16, 17, 18, 20, 21, 23, 24, 27, 28,
        31, 32, 33, 34, 37, 38, 40, 41, 46, 49, 50, 51, 53, 55, 58, 59, 62, 66,
        67, 68, 71, 72, 73, 78, 80, 81, 82, 83, 84, 85, 86, 88, 90, 93, 95, 97,
        98, 99, 100, 103, 104, 107, 110, 113, 117, 120, 121, 122, 123, 124,
        125, 126,
    ]
    # fmt: on

    def test_for_each_set_bit(self):
        bitmap = Object(self.prog, "unsigned long [2]", self.BITMAP)
        self.assertEqual(list(for_each_set_bit(bitmap, 128)), self.SET_BITS)
        self.assertEqual(
            list(for_each_set_bit(bitmap, 101)),
            [bit for bit in self.SET_BITS if bit < 101],
        )

    def test_for_each_clear_bit(self):
        bitmap = Object(self.prog, "unsigned long [2]", self.BITMAP)
        self.assertEqual(list(for_each_clear_bit(bitmap, 128)), self.CLEAR_BITS)
        self.assertEqual(
            list(for_each_clear_bit(bitmap, 100)),
            [bit for bit in self.CLEAR_BITS if bit < 100],
        )

    def test_test_bit(self):
        bitmap = Object(self.prog, "unsigned long [2]", self.BITMAP)
        for bit in self.SET_BITS:
            self.assertTrue(test_bit(bit, bitmap))
        for bit in self.CLEAR_BITS:
            self.assertFalse(test_bit(bit, bitmap))
