# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from tests.libdrgn import deserialize_bits, serialize_bits

VALUE = 12345678912345678989


def py_serialize_bits(value, bit_offset, bit_size, little_endian):
    bits = bit_offset + bit_size
    size = (bits + 7) // 8
    if little_endian:
        tmp = value << bit_offset
    else:
        tmp = value << -bits % 8
    # Buffer with unused bits set to zero.
    buf0 = tmp.to_bytes(size, "little" if little_endian else "big")

    # Buffer with unused bits set to one.
    buf1 = bytearray(buf0)
    if little_endian:
        # bit_offset least significant bits.
        buf1[0] |= (1 << bit_offset) - 1
        # 8 - (bit_offset + bit_size) % 8 most significant bits.
        buf1[-1] |= (0xFF00 >> -bits % 8) & 0xFF
    else:
        # bit_offset most significant bits.
        buf1[0] |= (0xFF00 >> bit_offset) & 0xFF
        # 8 - (bit_offset + bit_size) % 8 least significant bits.
        buf1[-1] |= (1 << -bits % 8) - 1

    return buf0, buf1


class TestSerialize(unittest.TestCase):
    def test_deserialize(self):
        for bit_size in range(1, 65):
            expected = VALUE & ((1 << bit_size) - 1)
            for bit_offset in range(8):
                for little_endian in [True, False]:
                    for buf in py_serialize_bits(
                        expected, bit_offset, bit_size, little_endian
                    ):
                        value = deserialize_bits(
                            buf, bit_offset, bit_size, little_endian
                        )
                        self.assertEqual(value, expected)

    def test_serialize(self):
        for bit_size in range(1, 65):
            value = VALUE & ((1 << bit_size) - 1)
            for bit_offset in range(8):
                for little_endian in [True, False]:
                    expected0, expected1 = py_serialize_bits(
                        value, bit_offset, bit_size, little_endian
                    )
                    buf = bytearray(len(expected0))
                    serialize_bits(buf, bit_offset, value, bit_size, little_endian)
                    self.assertEqual(buf, expected0)

                    buf = bytearray([0xFF] * len(expected1))
                    serialize_bits(buf, bit_offset, value, bit_size, little_endian)
                    self.assertEqual(buf, expected1)
