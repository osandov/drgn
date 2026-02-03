# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import unittest

import drgn
from drgn import (
    Architecture,
    Object,
    Platform,
    Program,
    search_memory,
    search_memory_regex,
    search_memory_u32,
    search_memory_u64,
    search_memory_word,
)
from tests import (
    MOCK_32BIT_BIG_ENDIAN_PLATFORM,
    MOCK_32BIT_PLATFORM,
    MOCK_BIG_ENDIAN_PLATFORM,
    MOCK_PLATFORM,
    IntWrapper,
    MockMemorySegment,
    TestCase,
    add_mock_memory_segments,
    with_default_prog,
)


def mock_search_memory_program(*segments, platform=MOCK_PLATFORM):
    prog = Program(platform)
    add_mock_memory_segments(prog, segments)
    return prog


class TestSearchMemoryBytes(TestCase):
    def test_one_match(self):
        prog = mock_search_memory_program(MockMemorySegment(b"abcdef", 0x1000))
        self.assertEqual(list(prog.search_memory(b"cde")), [0x1002])

    def test_haystack_embedded_null(self):
        prog = mock_search_memory_program(MockMemorySegment(b"a\0bcdef\0g", 0x1000))
        self.assertEqual(list(prog.search_memory(b"cde")), [0x1003])

    def test_needle_embedded_null(self):
        prog = mock_search_memory_program(MockMemorySegment(b"ab\0c\0d", 0x1000))
        self.assertEqual(list(prog.search_memory(b"b\0c")), [0x1001])

    def test_multiple_matches(self):
        prog = mock_search_memory_program(MockMemorySegment(b"abcd abcz", 0x1000))
        self.assertEqual(list(prog.search_memory(b"abc")), [0x1000, 0x1005])

    def test_non_overlapping(self):
        prog = mock_search_memory_program(MockMemorySegment(b"aaaa", 0x1000))
        self.assertEqual(list(prog.search_memory(b"aa")), [0x1000, 0x1002])

    def test_address_range(self):
        prog = mock_search_memory_program(MockMemorySegment(b"aaaa", 0x1000))

        self.assertEqual(
            list(prog.search_memory(b"aa").set_address_range(0x1000, 0x1003)),
            [0x1000, 0x1002],
        )

        self.assertEqual(
            list(prog.search_memory(b"aa").set_address_range(0x1001)), [0x1001]
        )

        self.assertEqual(
            list(prog.search_memory(b"aa").set_address_range(0x1000, 0x1000)), []
        )

    def test_address_range_reuse(self):
        prog = mock_search_memory_program(MockMemorySegment(b"aaaa", 0x1000))

        it = prog.search_memory(b"aa")

        it.set_address_range(0x1000, 0x1003)
        self.assertEqual(list(it), [0x1000, 0x1002])

        it.set_address_range(0x1001)
        self.assertEqual(list(it), [0x1001])

        it.set_address_range(0x1000, 0x1000)
        self.assertEqual(list(it), [])

    def test_invalid_address_range(self):
        self.assertRaises(
            ValueError,
            mock_search_memory_program().search_memory(b"foo").set_address_range,
            0x1000,
            0xFFF,
        )

    def test_cross_boundary(self):
        prog = mock_search_memory_program(MockMemorySegment(b"foo bar", 0x3FFFFFFA))
        self.assertEqual(list(prog.search_memory(b"bar")), [0x3FFFFFFE])

    def test_gap(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"abcdefgh", 0x1000),
            MockMemorySegment(b"zcdevwxy", 0x1104),
        )
        self.assertEqual(list(prog.search_memory(b"cde")), [0x1002, 0x1105])

    def test_at_max_address(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"aaaa", 0xFFFFFFFFFFFFFFFC)
        )
        self.assertEqual(
            list(prog.search_memory(b"aa")), [0xFFFFFFFFFFFFFFFC, 0xFFFFFFFFFFFFFFFE]
        )

    def test_one_byte_at_max_address(self):
        prog = mock_search_memory_program(MockMemorySegment(b"a", 0xFFFFFFFFFFFFFFFF))
        self.assertEqual(list(prog.search_memory(b"a")), [0xFFFFFFFFFFFFFFFF])

    def test_at_max_address_32_bit(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"aaaa", 0xFFFFFFFC),
            platform=MOCK_32BIT_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory(b"aa")), [0xFFFFFFFC, 0xFFFFFFFE])

    def test_one_byte_at_max_address_32_bit(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"a", 0xFFFFFFFF),
            platform=MOCK_32BIT_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory(b"a")), [0xFFFFFFFF])

    def test_alignment(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"aaaaaaaa", 0xFFC),
        )
        self.assertEqual(
            list(prog.search_memory(b"aa", alignment=8)),
            [0x1000],
        )

    def test_alignment_at_max_address(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"a" * 12, 0xFFFFFFFFFFFFFFF4),
        )
        self.assertEqual(
            list(prog.search_memory(b"aa", alignment=8)),
            [0xFFFFFFFFFFFFFFF8],
        )

    def test_u32(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "little") for i in range(1, 4)]), 0x1000
            ),
        )
        self.assertEqual(
            list(prog.search_memory((2).to_bytes(4, "little"), alignment=4)), [0x1004]
        )

    def test_u32_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "big") for i in range(1, 4)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(
            list(prog.search_memory((2).to_bytes(4, "big"), alignment=4)), [0x1004]
        )

    def test_u64(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "little") for i in range(1, 4)]), 0x1000
            ),
        )
        self.assertEqual(
            list(prog.search_memory((2).to_bytes(8, "little"), alignment=8)), [0x1008]
        )

    def test_u64_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "big") for i in range(1, 4)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(
            list(prog.search_memory((2).to_bytes(8, "big"), alignment=8)), [0x1008]
        )

    def test_no_segments(self):
        prog = mock_search_memory_program()
        self.assertEqual(list(prog.search_memory(b"foo")), [])

    def test_empty(self):
        with self.assertRaisesRegex(ValueError, "needle cannot be empty"):
            next(mock_search_memory_program().search_memory(b""))

    def test_invalid_alignment(self):
        with self.assertRaisesRegex(ValueError, "alignment must be power of 2"):
            next(mock_search_memory_program().search_memory(b"foo", alignment=3))

    def test_invalid_needle_type(self):
        self.assertRaises(TypeError, mock_search_memory_program().search_memory, {})

    def test_default_program(self):
        with with_default_prog(
            mock_search_memory_program(MockMemorySegment(b"abcdef", 0x1000))
        ):
            self.assertEqual(list(search_memory(b"cde")), [0x1002])


class TestSearchMemoryStr(TestCase):
    def test_valid_utf8(self):
        prog = mock_search_memory_program(MockMemorySegment(b"abcdef", 0x1000))
        self.assertEqual(list(prog.search_memory("cde")), [0x1002])

    def test_haystack_embedded_null(self):
        prog = mock_search_memory_program(MockMemorySegment(b"a\0bcdef\0g", 0x1000))
        self.assertEqual(list(prog.search_memory("cde")), [0x1003])

    def test_needle_embedded_null(self):
        prog = mock_search_memory_program(MockMemorySegment(b"ab\0c\0d", 0x1000))
        self.assertEqual(list(prog.search_memory("b\0c")), [0x1001])

    def test_invalid_utf8(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"\xc3\x28abcdef\xa0\xa1", 0x1000)
        )
        self.assertEqual(list(prog.search_memory("cde")), [0x1004])

    def test_empty(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            next(mock_search_memory_program().search_memory(""))

    def test_alignment(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"aaaaaaaa", 0xFFC),
        )
        self.assertEqual(
            list(prog.search_memory("aa", alignment=8)),
            [0x1000],
        )

    def test_invalid_alignment(self):
        with self.assertRaisesRegex(ValueError, "alignment"):
            next(mock_search_memory_program().search_memory("foo", alignment=3))

    def test_default_program(self):
        with with_default_prog(
            mock_search_memory_program(MockMemorySegment(b"abcdef", 0x1000))
        ):
            self.assertEqual(list(search_memory("cde")), [0x1002])


class TestSearchMemoryInt(TestCase):
    def test_64_bit(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00",
                0x1000,
            ),
        )
        self.assertEqual(list(prog.search_memory(2)), [0x1008])

    def test_64_bit_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x02",
                0x1000,
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory(2)), [0x1008])

    def test_32_bit(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00",
                0x1000,
            ),
            platform=MOCK_32BIT_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory(2)), [0x1000, 0x1004, 0x1008])

    def test_32_bit_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x02",
                0x1000,
            ),
            platform=MOCK_32BIT_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory(2)), [0x1000, 0x1004, 0x100C])

    def test_index(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "little") for i in range(1, 4)]), 0x1000
            ),
        )
        self.assertEqual(list(prog.search_memory(IntWrapper(2))), [0x1008])

    def test_invalid_alignment(self):
        with self.assertRaisesRegex(TypeError, "alignment"):
            next(mock_search_memory_program().search_memory(0, alignment=3))

    def test_default_program(self):
        with with_default_prog(
            mock_search_memory_program(
                MockMemorySegment(
                    b"\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00",
                    0x1000,
                ),
            )
        ):
            self.assertEqual(list(search_memory(2)), [0x1008])


# Note that these tests use actual architectures so that they have alignment
# information.
class TestSearchMemoryObject(TestCase):
    def test_u32(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "little") for i in range(1, 4)]), 0x1000
            ),
            platform=Platform(Architecture.X86_64),
        )
        self.assertEqual(list(prog.search_memory(Object(prog, "int", 2))), [0x1004])

    def test_u32_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "big") for i in range(1, 4)]), 0x1000
            ),
            platform=Platform(Architecture.S390X),
        )
        self.assertEqual(list(prog.search_memory(Object(prog, "int", 2))), [0x1004])

    def test_u64(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "little") for i in range(1, 4)]), 0x1000
            ),
            platform=Platform(Architecture.X86_64),
        )
        self.assertEqual(list(prog.search_memory(Object(prog, "long", 2))), [0x1008])

    def test_u64_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "big") for i in range(1, 4)]), 0x1000
            ),
            platform=Platform(Architecture.S390X),
        )
        self.assertEqual(list(prog.search_memory(Object(prog, "long", 2))), [0x1008])

    def test_small_object(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"\x01\x02\x03\x04", 0x1000),
            platform=Platform(Architecture.X86_64),
        )
        self.assertEqual(list(prog.search_memory(Object(prog, "char", 2))), [0x1001])

    def test_large_object(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "little") for i in range(1, 9)]), 0x1000
            ),
            platform=Platform(Architecture.X86_64),
        )
        self.assertEqual(
            list(prog.search_memory(Object(prog, "long [4]", [2, 3, 4, 5]))), [0x1008]
        )

    def test_alignment(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"\x02\x00\x00\x00" * 7, 0xFFC),
            platform=Platform(Architecture.X86_64),
        )
        self.assertEqual(
            list(prog.search_memory(Object(prog, "long long [3]", [0x200000002] * 3))),
            [0x1000],
        )

        prog = mock_search_memory_program(
            MockMemorySegment(b"\x02\x00\x00\x00" * 7, 0xFFC),
            platform=Platform(Architecture.I386),
        )
        self.assertEqual(
            list(prog.search_memory(Object(prog, "long long [3]", [0x200000002] * 3))),
            [0xFFC],
        )

    def test_empty(self):
        prog = mock_search_memory_program(platform=Platform(Architecture.X86_64))
        with self.assertRaisesRegex(ValueError, "size 0"):
            prog.search_memory(Object(prog, "int [0]", address=0x1000))

    def test_invalid_alignment(self):
        prog = mock_search_memory_program(platform=Platform(Architecture.X86_64))
        with self.assertRaisesRegex(TypeError, "alignment"):
            next(prog.search_memory(Object(prog, "int", 0), alignment=3))

    def test_default_program(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "little") for i in range(1, 4)]), 0x1000
            ),
            platform=Platform(Architecture.X86_64),
        )
        self.assertEqual(list(search_memory(Object(prog, "int", 2))), [0x1004])

    def test_out_of_range(self):
        with self.assertRaises(OverflowError):
            next(
                mock_search_memory_program(platform=MOCK_32BIT_PLATFORM).search_memory(
                    2**32
                )
            )
        self.assertEqual(list(mock_search_memory_program().search_memory(2**32)), [])
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory(2**64))


class TestSearchMemoryUint(TestCase):
    def test_one_u16(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(2, "little") for i in range(1, 4)]), 0x1000
            ),
        )
        self.assertEqual(list(prog.search_memory_u16(2)), [(0x1002, 2)])

    def test_one_u16_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(2, "big") for i in range(1, 4)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory_u16(2)), [(0x1002, 2)])

    def test_one_u32(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "little") for i in range(1, 4)]), 0x1000
            ),
        )
        self.assertEqual(list(prog.search_memory_u32(2)), [(0x1004, 2)])

    def test_one_u32_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "big") for i in range(1, 4)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory_u32(2)), [(0x1004, 2)])

    def test_one_u64(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "little") for i in range(1, 4)]), 0x1000
            ),
        )
        self.assertEqual(list(prog.search_memory_u64(2)), [(0x1008, 2)])

    def test_one_u64_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "big") for i in range(1, 4)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory_u64(2)), [(0x1008, 2)])

    def test_word_64_bit(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00",
                0x1000,
            ),
        )
        self.assertEqual(list(prog.search_memory_word(2)), [(0x1008, 2)])

    def test_word_32_bit(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"\x02\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00",
                0x1000,
            ),
            platform=MOCK_32BIT_PLATFORM,
        )
        self.assertEqual(
            list(prog.search_memory_word(2)), [(0x1000, 2), (0x1004, 2), (0x1008, 2)]
        )

    def test_multiple_u16(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(2, "little") for i in range(1, 5)]), 0x1000
            ),
        )
        self.assertEqual(list(prog.search_memory_u16(2, 4)), [(0x1002, 2), (0x1006, 4)])

    def test_multiple_u16_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(2, "big") for i in range(1, 5)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory_u16(2, 4)), [(0x1002, 2), (0x1006, 4)])

    def test_multiple_u32(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "little") for i in range(1, 5)]), 0x1000
            ),
        )
        self.assertEqual(list(prog.search_memory_u32(2, 4)), [(0x1004, 2), (0x100C, 4)])

    def test_multiple_u32_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "big") for i in range(1, 5)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory_u32(2, 4)), [(0x1004, 2), (0x100C, 4)])

    def test_multiple_u64(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "little") for i in range(1, 5)]), 0x1000
            ),
        )
        self.assertEqual(list(prog.search_memory_u64(2, 4)), [(0x1008, 2), (0x1018, 4)])

    def test_multiple_u64_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "big") for i in range(1, 5)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(list(prog.search_memory_u64(2, 4)), [(0x1008, 2), (0x1018, 4)])

    def test_ignore_mask_u32(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "little") for i in range(1, 7)]), 0x1000
            ),
        )
        self.assertEqual(
            list(prog.search_memory_u32(3, ignore_mask=0x5)),
            [(0x1004, 2), (0x1008, 3), (0x1014, 6)],
        )

    def test_ignore_mask_u32_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "big") for i in range(1, 7)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(
            list(prog.search_memory_u32(3, ignore_mask=0x5)),
            [(0x1004, 2), (0x1008, 3), (0x1014, 6)],
        )

    def test_ignore_mask_u64(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "little") for i in range(1, 7)]), 0x1000
            ),
        )
        self.assertEqual(
            list(prog.search_memory_u64(3, ignore_mask=0x5)),
            [(0x1008, 2), (0x1010, 3), (0x1028, 6)],
        )

    def test_ignore_mask_u64_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "big") for i in range(1, 7)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(
            list(prog.search_memory_u64(3, ignore_mask=0x5)),
            [(0x1008, 2), (0x1010, 3), (0x1028, 6)],
        )

    def test_u32_range(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "little") for i in range(1, 5)]), 0x1000
            ),
        )
        self.assertEqual(
            list(prog.search_memory_u32((2, 3))), [(0x1004, 2), (0x1008, 3)]
        )

    def test_u32_range_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(4, "big") for i in range(1, 5)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(
            list(prog.search_memory_u32((2, 3))), [(0x1004, 2), (0x1008, 3)]
        )

    def test_u64_range(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "little") for i in range(1, 5)]), 0x1000
            ),
        )
        self.assertEqual(
            list(prog.search_memory_u64((2, 3))), [(0x1008, 2), (0x1010, 3)]
        )

    def test_u64_range_big_endian(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "big") for i in range(1, 5)]), 0x1000
            ),
            platform=MOCK_BIG_ENDIAN_PLATFORM,
        )
        self.assertEqual(
            list(prog.search_memory_u64((2, 3))), [(0x1008, 2), (0x1010, 3)]
        )

    def test_combo(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"".join([i.to_bytes(8, "little") for i in range(1, 7)]), 0x1000
            ),
        )
        self.assertEqual(
            list(
                prog.search_memory_u64(
                    1, (2, 3), 6, (4, 4), (100, 200), ignore_mask=0x4
                )
            ),
            [
                (0x1000, 1),
                (0x1008, 2),
                (0x1010, 3),
                (0x1018, 4),
                (0x1020, 5),
                (0x1028, 6),
            ],
        )

    def test_index(self):
        prog = mock_search_memory_program(
            MockMemorySegment(
                b"\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00",
                0x1000,
            ),
        )
        self.assertEqual(
            list(
                prog.search_memory_u32(
                    IntWrapper(2),
                    (IntWrapper(4), IntWrapper(5)),
                    ignore_mask=IntWrapper(1),
                )
            ),
            [(0x1000, 3), (0x1008, 4)],
        )
        self.assertEqual(
            list(
                prog.search_memory_u64(
                    IntWrapper(2),
                    (IntWrapper(4), IntWrapper(5)),
                    ignore_mask=IntWrapper(1),
                )
            ),
            [(0x1000, 3), (0x1008, 4)],
        )
        self.assertEqual(
            list(
                prog.search_memory_word(
                    IntWrapper(2),
                    (IntWrapper(4), IntWrapper(5)),
                    ignore_mask=IntWrapper(1),
                )
            ),
            [(0x1000, 3), (0x1008, 4)],
        )

    def test_default_program(self):
        with with_default_prog(
            mock_search_memory_program(
                MockMemorySegment(
                    b"\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00",
                    0x1000,
                ),
            )
        ):
            self.assertEqual(
                list(search_memory_u32(2, (4, 5), ignore_mask=1)),
                [(0x1000, 3), (0x1008, 4)],
            )
            self.assertEqual(
                list(search_memory_u64(2, (4, 5), ignore_mask=1)),
                [(0x1000, 3), (0x1008, 4)],
            )
            self.assertEqual(
                list(search_memory_word(2, (4, 5), ignore_mask=1)),
                [(0x1000, 3), (0x1008, 4)],
            )

    def test_out_of_range(self):
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_u32(2**32))
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_u32((0, 2**32)))
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_u32((2**32, 0)))
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_u32(0, ignore_mask=2**32))
        with self.assertRaises((ValueError, OverflowError)):
            next(mock_search_memory_program().search_memory_u32(-1))

        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_u64(2**64))
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_u64((0, 2**64)))
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_u64((2**64, 0)))
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_u64(0, ignore_mask=2**64))
        with self.assertRaises((ValueError, OverflowError)):
            next(mock_search_memory_program().search_memory_u64(-1))

        with self.assertRaises(OverflowError):
            next(
                mock_search_memory_program(
                    platform=MOCK_32BIT_PLATFORM
                ).search_memory_word(2**32)
            )
        with self.assertRaises(OverflowError):
            next(
                mock_search_memory_program(
                    platform=MOCK_32BIT_PLATFORM
                ).search_memory_word((0, 2**32))
            )
        with self.assertRaises(OverflowError):
            next(
                mock_search_memory_program(
                    platform=MOCK_32BIT_PLATFORM
                ).search_memory_word((2**32, 0))
            )
        with self.assertRaises(OverflowError):
            next(
                mock_search_memory_program(
                    platform=MOCK_32BIT_PLATFORM
                ).search_memory_word(0, ignore_mask=2**32)
            )

        self.assertEqual(
            list(
                mock_search_memory_program().search_memory_word(
                    2**32, (2**33, 2**34), ignore_mask=2**35
                )
            ),
            [],
        )

        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_word(2**64))
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_word((0, 2**64)))
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_word((2**64, 0)))
        with self.assertRaises(OverflowError):
            next(mock_search_memory_program().search_memory_word(0, ignore_mask=2**64))


@unittest.skipUnless(drgn._with_pcre2, "built without pcre2 support")
class TestSearchMemoryRegex(TestCase):
    def test_fixed_size(self):
        prog = mock_search_memory_program(MockMemorySegment(b"foo bar", 0x1000))
        self.assertEqual(
            list(prog.search_memory_regex(rb"foo|bar")),
            [
                (0x1000, b"foo"),
                (0x1004, b"bar"),
            ],
        )

    def test_non_overlapping(self):
        prog = mock_search_memory_program(MockMemorySegment(b"abcd", 0x1000))
        self.assertEqual(
            list(prog.search_memory_regex(rb"[a-z]{1,2}")),
            [(0x1000, b"ab"), (0x1002, b"cd")],
        )

    def test_variable_size(self):
        prog = mock_search_memory_program(MockMemorySegment(b"caaaaat", 0x1000))
        self.assertEqual(
            list(prog.search_memory_regex(rb"a+")),
            [(0x1001, b"aaaaa")],
        )

    def test_gap(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"caaaaa", 0x1000), MockMemorySegment(b"aaaaat", 0x1008)
        )
        self.assertEqual(
            list(prog.search_memory_regex(rb"a+")),
            [(0x1001, b"aaaaa"), (0x1008, b"aaaaa")],
        )

    def test_all_empty(self):
        prog = mock_search_memory_program(MockMemorySegment(b"b", 0x1000))
        self.assertEqual(
            list(prog.search_memory_regex(rb"a*")),
            [
                (0x1000, b""),
                (0x1001, b""),
            ],
        )

    def test_empty_and_non_empty(self):
        prog = mock_search_memory_program(MockMemorySegment(b"b", 0x1000))
        self.assertEqual(
            list(prog.search_memory_regex(rb"|b")),
            [
                (0x1000, b""),
                (0x1000, b"b"),
                (0x1001, b""),
            ],
        )

    def test_empty_at_gap(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"b", 0x1000),
            MockMemorySegment(b"c", 0x1008),
        )
        self.assertEqual(
            list(prog.search_memory_regex(rb"a*")),
            [
                (0x1000, b""),
                (0x1001, b""),
                (0x1008, b""),
                (0x1009, b""),
            ],
        )

    def test_anchor_start(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"abc", 0x0), MockMemorySegment(b"abc", 0x1000)
        )
        self.assertEqual(
            list(prog.search_memory_regex(rb"^abc")),
            [(0x0, b"abc")],
        )

    def test_anchor_end(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"abc", 0xFFD),
            MockMemorySegment(b"abc", 0xFFFFFFFFFFFFFFFD),
        )
        self.assertEqual(
            list(prog.search_memory_regex(rb"abc$")),
            [(0xFFFFFFFFFFFFFFFD, b"abc")],
        )

    def test_cross_boundary_fixed_size(self):
        prog = mock_search_memory_program(MockMemorySegment(b"foo bar", 0x3FFFFFFE))
        self.assertEqual(
            list(prog.search_memory_regex(rb"foo|bar")),
            [
                (0x3FFFFFFE, b"foo"),
                (0x40000002, b"bar"),
            ],
        )

    def test_cross_boundary_multi_size(self):
        prog = mock_search_memory_program(MockMemorySegment(b"foo bar", 0x3FFFFFFE))
        self.assertEqual(
            list(prog.search_memory_regex(rb"foo|b")),
            [
                (0x3FFFFFFE, b"foo"),
                (0x40000002, b"b"),
            ],
        )

    def test_cross_boundary_variable_size(self):
        prog = mock_search_memory_program(MockMemorySegment(b"foo bar", 0x3FFFFFFE))
        self.assertEqual(
            list(prog.search_memory_regex(rb"fo*")),
            [(0x3FFFFFFE, b"foo")],
        )

    @unittest.skipUnless(drgn._with_pcre2_utf, "PCRE2 does not support UTF-8")
    def test_str_valid_utf8(self):
        # 'ñ' is \xc3\xb1 in UTF-8. '±' is \xc2\xb1 in UTF-8. A Unicode search
        # for the former shouldn't match the \xb1 byte in the latter.
        prog = mock_search_memory_program(MockMemorySegment("piñata±".encode(), 0x1000))
        self.assertEqual(
            list(prog.search_memory_regex(r"[a-zñ]+")), [(0x1000, "piñata")]
        )

    @unittest.skipUnless(drgn._with_pcre2_utf, "PCRE2 does not support UTF-8")
    def test_invalid_utf8(self):
        prog = mock_search_memory_program(
            MockMemorySegment(b"\xc3\x28abcdef\xa0\xa1", 0x1000)
        )
        self.assertEqual(
            list(prog.search_memory_regex(r"[a-z]+")), [(0x1002, "abcdef")]
        )

    def test_no_lookbehind(self):
        self.assertRaisesRegex(
            ValueError,
            "lookbehind",
            mock_search_memory_program().search_memory_regex,
            rb"(?<=foo)bar",
        )
        self.assertRaisesRegex(
            ValueError,
            "lookbehind",
            mock_search_memory_program().search_memory_regex,
            rb"(?<!foo)bar",
        )

    def test_default_program(self):
        with with_default_prog(
            mock_search_memory_program(MockMemorySegment(b"foo bar", 0x1000))
        ):
            self.assertEqual(
                list(search_memory_regex(rb"foo|bar")),
                [(0x1000, b"foo"), (0x1004, b"bar")],
            )
            if drgn._with_pcre2_utf:
                self.assertEqual(
                    list(search_memory_regex(r"foo|bar")),
                    [(0x1000, "foo"), (0x1004, "bar")],
                )
