# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import itertools
import os
import tempfile
import unittest.mock

from drgn import (
    Architecture,
    FaultError,
    FindObjectFlags,
    Object,
    Platform,
    PlatformFlags,
    Program,
    ProgramFlags,
    Qualifiers,
    TypeKind,
    host_platform,
)
from tests import (
    DEFAULT_LANGUAGE,
    MOCK_32BIT_PLATFORM,
    MOCK_PLATFORM,
    MockMemorySegment,
    MockObject,
    MockProgramTestCase,
    TestCase,
    mock_program,
)
from tests.elf import ET, PT
from tests.elfwriter import ElfSection, create_elf_file


def zero_memory_read(address, count, offset, physical):
    return bytes(count)


class TestProgram(unittest.TestCase):
    def test_set_pid(self):
        # Debug the running Python interpreter itself.
        prog = Program()
        self.assertIsNone(prog.platform)
        self.assertFalse(prog.flags & ProgramFlags.IS_LIVE)
        prog.set_pid(os.getpid())
        self.assertEqual(prog.platform, host_platform)
        self.assertTrue(prog.flags & ProgramFlags.IS_LIVE)
        data = b"hello, world!"
        buf = ctypes.create_string_buffer(data)
        self.assertEqual(prog.read(ctypes.addressof(buf), len(data)), data)
        self.assertRaisesRegex(
            ValueError,
            "program memory was already initialized",
            prog.set_pid,
            os.getpid(),
        )

    def test_lookup_error(self):
        prog = mock_program()
        self.assertRaisesRegex(
            LookupError, "^could not find constant 'foo'$", prog.constant, "foo"
        )
        self.assertRaisesRegex(
            LookupError,
            "^could not find constant 'foo' in 'foo.c'$",
            prog.constant,
            "foo",
            "foo.c",
        )
        self.assertRaisesRegex(
            LookupError, "^could not find function 'foo'$", prog.function, "foo"
        )
        self.assertRaisesRegex(
            LookupError,
            "^could not find function 'foo' in 'foo.c'$",
            prog.function,
            "foo",
            "foo.c",
        )
        self.assertRaisesRegex(LookupError, "^could not find 'foo'$", prog.type, "foo")
        self.assertRaisesRegex(
            LookupError, "^could not find 'foo' in 'foo.c'$", prog.type, "foo", "foo.c"
        )
        self.assertRaisesRegex(
            LookupError, "^could not find variable 'foo'$", prog.variable, "foo"
        )
        self.assertRaisesRegex(
            LookupError,
            "^could not find variable 'foo' in 'foo.c'$",
            prog.variable,
            "foo",
            "foo.c",
        )
        # prog[key] should raise KeyError instead of LookupError.
        self.assertRaises(KeyError, prog.__getitem__, "foo")
        # Even for non-strings.
        self.assertRaises(KeyError, prog.__getitem__, 9)

    def test_flags(self):
        self.assertIsInstance(mock_program().flags, ProgramFlags)

    def test_debug_info(self):
        Program().load_debug_info([])

    def test_language(self):
        self.assertEqual(Program().language, DEFAULT_LANGUAGE)


class TestMemory(TestCase):
    def test_simple_read(self):
        data = b"hello, world"
        prog = mock_program(segments=[MockMemorySegment(data, 0xFFFF0000, 0xA0)])
        self.assertEqual(prog.read(0xFFFF0000, len(data)), data)
        self.assertEqual(prog.read(0xA0, len(data), True), data)

    def test_read_unsigned(self):
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        for word_size in [8, 4]:
            for byteorder in ["little", "big"]:
                flags = PlatformFlags(0)
                if word_size == 8:
                    flags |= PlatformFlags.IS_64_BIT
                if byteorder == "little":
                    flags |= PlatformFlags.IS_LITTLE_ENDIAN
                prog = mock_program(
                    Platform(Architecture.UNKNOWN, flags),
                    segments=[MockMemorySegment(data, 0xFFFF0000, 0xA0)],
                )
                for size in [1, 2, 4, 8]:
                    read_fn = getattr(prog, f"read_u{8 * size}")
                    value = int.from_bytes(data[:size], byteorder)
                    self.assertEqual(read_fn(0xFFFF0000), value)
                    self.assertEqual(read_fn(0xA0, True), value)
                    if size == word_size:
                        self.assertEqual(prog.read_word(0xFFFF0000), value)
                        self.assertEqual(prog.read_word(0xA0, True), value)

        prog = mock_program(
            MOCK_32BIT_PLATFORM, segments=[MockMemorySegment(data, 0xFFFF0000, 0xA0)]
        )

    def test_bad_address(self):
        data = b"hello, world!"
        prog = mock_program(segments=[MockMemorySegment(data, 0xFFFF0000)])
        self.assertRaisesRegex(
            FaultError, "could not find memory segment", prog.read, 0xDEADBEEF, 4
        )
        self.assertRaisesRegex(
            FaultError, "could not find memory segment", prog.read, 0xFFFF0000, 4, True
        )

    def test_segment_overflow(self):
        data = b"hello, world!"
        prog = mock_program(segments=[MockMemorySegment(data, 0xFFFF0000)])
        self.assertRaisesRegex(
            FaultError,
            "could not find memory segment",
            prog.read,
            0xFFFF0000,
            len(data) + 1,
        )

    def test_adjacent_segments(self):
        data = b"hello, world!\0foobar"
        prog = mock_program(
            segments=[
                MockMemorySegment(data[:4], 0xFFFF0000),
                MockMemorySegment(data[4:14], 0xFFFF0004),
                MockMemorySegment(data[14:], 0xFFFFF000),
            ]
        )
        self.assertEqual(prog.read(0xFFFF0000, 14), data[:14])

    def test_overlap_same_address_smaller_size(self):
        # Existing segment: |_______|
        # New segment:      |___|
        prog = Program()
        segment1 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment2 = unittest.mock.Mock(side_effect=zero_memory_read)
        prog.add_memory_segment(0xFFFF0000, 128, segment1)
        prog.add_memory_segment(0xFFFF0000, 64, segment2)
        prog.read(0xFFFF0000, 128)
        segment1.assert_called_once_with(0xFFFF0040, 64, 64, False)
        segment2.assert_called_once_with(0xFFFF0000, 64, 0, False)

    def test_overlap_within_segment(self):
        # Existing segment: |_______|
        # New segment:        |___|
        prog = Program()
        segment1 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment2 = unittest.mock.Mock(side_effect=zero_memory_read)
        prog.add_memory_segment(0xFFFF0000, 128, segment1)
        prog.add_memory_segment(0xFFFF0020, 64, segment2)
        prog.read(0xFFFF0000, 128)
        segment1.assert_has_calls(
            [
                unittest.mock.call(0xFFFF0000, 32, 00, False),
                unittest.mock.call(0xFFFF0060, 32, 96, False),
            ]
        )
        segment2.assert_called_once_with(0xFFFF0020, 64, 0, False)

    def test_overlap_same_segment(self):
        # Existing segment: |_______|
        # New segment:      |_______|
        prog = Program()
        segment1 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment2 = unittest.mock.Mock(side_effect=zero_memory_read)
        prog.add_memory_segment(0xFFFF0000, 128, segment1)
        prog.add_memory_segment(0xFFFF0000, 128, segment2)
        prog.read(0xFFFF0000, 128)
        segment1.assert_not_called()
        segment2.assert_called_once_with(0xFFFF0000, 128, 0, False)

    def test_overlap_same_address_larger_size(self):
        # Existing segment: |___|
        # New segment:      |_______|
        prog = Program()
        segment1 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment2 = unittest.mock.Mock(side_effect=zero_memory_read)
        prog.add_memory_segment(0xFFFF0000, 64, segment1)
        prog.add_memory_segment(0xFFFF0000, 128, segment2)
        prog.read(0xFFFF0000, 128)
        segment1.assert_not_called()
        segment2.assert_called_once_with(0xFFFF0000, 128, 0, False)

    def test_overlap_segment_tail(self):
        # Existing segment: |_______|
        # New segment:          |_______|
        prog = Program()
        segment1 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment2 = unittest.mock.Mock(side_effect=zero_memory_read)
        prog.add_memory_segment(0xFFFF0000, 128, segment1)
        prog.add_memory_segment(0xFFFF0040, 128, segment2)
        prog.read(0xFFFF0000, 192)
        segment1.assert_called_once_with(0xFFFF0000, 64, 0, False)
        segment2.assert_called_once_with(0xFFFF0040, 128, 0, False)

    def test_overlap_subsume_after(self):
        # Existing segments:   |_|_|_|_|
        # New segment:       |_______|
        prog = Program()
        segment1 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment2 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment3 = unittest.mock.Mock(side_effect=zero_memory_read)
        prog.add_memory_segment(0xFFFF0020, 32, segment1)
        prog.add_memory_segment(0xFFFF0040, 32, segment1)
        prog.add_memory_segment(0xFFFF0060, 32, segment1)
        prog.add_memory_segment(0xFFFF0080, 64, segment2)
        prog.add_memory_segment(0xFFFF0000, 128, segment3)
        prog.read(0xFFFF0000, 192)
        segment1.assert_not_called()
        segment2.assert_called_once_with(0xFFFF0080, 64, 0, False)
        segment3.assert_called_once_with(0xFFFF0000, 128, 0, False)

    def test_overlap_segment_head(self):
        # Existing segment:     |_______|
        # New segment:      |_______|
        prog = Program()
        segment1 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment2 = unittest.mock.Mock(side_effect=zero_memory_read)
        prog.add_memory_segment(0xFFFF0040, 128, segment1)
        prog.add_memory_segment(0xFFFF0000, 128, segment2)
        prog.read(0xFFFF0000, 192)
        segment1.assert_called_once_with(0xFFFF0080, 64, 64, False)
        segment2.assert_called_once_with(0xFFFF0000, 128, 0, False)

    def test_overlap_segment_head_and_tail(self):
        # Existing segment: |_______||_______|
        # New segment:          |_______|
        prog = Program()
        segment1 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment2 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment3 = unittest.mock.Mock(side_effect=zero_memory_read)
        prog.add_memory_segment(0xFFFF0000, 128, segment1)
        prog.add_memory_segment(0xFFFF0080, 128, segment2)
        prog.add_memory_segment(0xFFFF0040, 128, segment3)
        prog.read(0xFFFF0000, 256)
        segment1.assert_called_once_with(0xFFFF0000, 64, 0, False)
        segment2.assert_called_once_with(0xFFFF00C0, 64, 64, False)
        segment3.assert_called_once_with(0xFFFF0040, 128, 0, False)

    def test_overlap_subsume_at_and_after(self):
        # Existing segments: |_|_|_|_|
        # New segment:       |_______|
        prog = Program()
        segment1 = unittest.mock.Mock(side_effect=zero_memory_read)
        segment2 = unittest.mock.Mock(side_effect=zero_memory_read)
        prog.add_memory_segment(0xFFFF0000, 32, segment1)
        prog.add_memory_segment(0xFFFF0020, 32, segment1)
        prog.add_memory_segment(0xFFFF0040, 32, segment1)
        prog.add_memory_segment(0xFFFF0060, 32, segment1)
        prog.add_memory_segment(0xFFFF0000, 128, segment2)
        prog.read(0xFFFF0000, 128)
        segment1.assert_not_called()
        segment2.assert_called_once_with(0xFFFF0000, 128, 0, False)

    def test_invalid_read_fn(self):
        prog = mock_program()

        self.assertRaises(TypeError, prog.add_memory_segment, 0xFFFF0000, 8, b"foo")

        prog.add_memory_segment(0xFFFF0000, 8, lambda: None)
        self.assertRaises(TypeError, prog.read, 0xFFFF0000, 8)

        prog.add_memory_segment(
            0xFFFF0000, 8, lambda address, count, offset, physical: None
        )
        self.assertRaises(TypeError, prog.read, 0xFFFF0000, 8)

        prog.add_memory_segment(
            0xFFFF0000, 8, lambda address, count, offset, physical: "asdf"
        )
        self.assertRaises(TypeError, prog.read, 0xFFFF0000, 8)

        prog.add_memory_segment(
            0xFFFF0000, 8, lambda address, count, offset, physical: b""
        )
        self.assertRaisesRegex(
            ValueError,
            r"memory read callback returned buffer of length 0 \(expected 8\)",
            prog.read,
            0xFFFF0000,
            8,
        )


class TestTypes(MockProgramTestCase):
    def test_invalid_finder(self):
        self.assertRaises(TypeError, self.prog.add_type_finder, "foo")

        self.prog.add_type_finder(lambda kind, name, filename: "foo")
        self.assertRaises(TypeError, self.prog.type, "int")

    def test_finder_different_program(self):
        def finder(kind, name, filename):
            if kind == TypeKind.TYPEDEF and name == "foo":
                prog = Program()
                return prog.typedef_type("foo", prog.void_type())
            else:
                return None

        self.prog.add_type_finder(finder)
        self.assertRaisesRegex(
            ValueError,
            "type find callback returned type from wrong program",
            self.prog.type,
            "foo",
        )

    def test_wrong_kind(self):
        self.prog.add_type_finder(lambda kind, name, filename: self.prog.void_type())
        self.assertRaises(TypeError, self.prog.type, "int")

    def test_not_found(self):
        self.assertRaises(LookupError, self.prog.type, "struct foo")
        self.prog.add_type_finder(lambda kind, name, filename: None)
        self.assertRaises(LookupError, self.prog.type, "struct foo")

    def test_default_primitive_types(self):
        def spellings(tokens, num_optional=0):
            for i in range(len(tokens) - num_optional, len(tokens) + 1):
                for perm in itertools.permutations(tokens[:i]):
                    yield " ".join(perm)

        for word_size in [8, 4]:
            prog = mock_program(
                MOCK_PLATFORM if word_size == 8 else MOCK_32BIT_PLATFORM
            )
            self.assertIdentical(prog.type("_Bool"), prog.bool_type("_Bool", 1))
            self.assertIdentical(prog.type("char"), prog.int_type("char", 1, True))
            for spelling in spellings(["signed", "char"]):
                self.assertIdentical(
                    prog.type(spelling), prog.int_type("signed char", 1, True)
                )
            for spelling in spellings(["unsigned", "char"]):
                self.assertIdentical(
                    prog.type(spelling), prog.int_type("unsigned char", 1, False)
                )
            for spelling in spellings(["short", "signed", "int"], 2):
                self.assertIdentical(
                    prog.type(spelling), prog.int_type("short", 2, True)
                )
            for spelling in spellings(["short", "unsigned", "int"], 1):
                self.assertIdentical(
                    prog.type(spelling), prog.int_type("unsigned short", 2, False)
                )
            for spelling in spellings(["int", "signed"], 1):
                self.assertIdentical(prog.type(spelling), prog.int_type("int", 4, True))
            for spelling in spellings(["unsigned", "int"]):
                self.assertIdentical(
                    prog.type(spelling), prog.int_type("unsigned int", 4, False)
                )
            for spelling in spellings(["long", "signed", "int"], 2):
                self.assertIdentical(
                    prog.type(spelling), prog.int_type("long", word_size, True)
                )
            for spelling in spellings(["long", "unsigned", "int"], 1):
                self.assertIdentical(
                    prog.type(spelling),
                    prog.int_type("unsigned long", word_size, False),
                )
            for spelling in spellings(["long", "long", "signed", "int"], 2):
                self.assertIdentical(
                    prog.type(spelling), prog.int_type("long long", 8, True)
                )
            for spelling in spellings(["long", "long", "unsigned", "int"], 1):
                self.assertIdentical(
                    prog.type(spelling), prog.int_type("unsigned long long", 8, False)
                )
            self.assertIdentical(prog.type("float"), prog.float_type("float", 4))
            self.assertIdentical(prog.type("double"), prog.float_type("double", 8))
            for spelling in spellings(["long", "double"]):
                self.assertIdentical(
                    prog.type(spelling), prog.float_type("long double", 16)
                )
            self.assertIdentical(
                prog.type("size_t"),
                prog.typedef_type(
                    "size_t", prog.int_type("unsigned long", word_size, False)
                ),
            )
            self.assertIdentical(
                prog.type("ptrdiff_t"),
                prog.typedef_type("ptrdiff_t", prog.int_type("long", word_size, True)),
            )

    def test_primitive_type(self):
        self.types.append(self.prog.int_type("long", 4, True))
        self.assertIdentical(
            self.prog.type("long"), self.prog.int_type("long", 4, True)
        )

    def test_primitive_type_invalid(self):
        # unsigned long with signed=True isn't valid, so it should be ignored.
        self.types.append(self.prog.int_type("unsigned long", 4, True))
        self.assertIdentical(
            self.prog.type("unsigned long"),
            self.prog.int_type("unsigned long", 8, False),
        )

    def test_size_t_and_ptrdiff_t(self):
        # 64-bit architecture with 4-byte long/unsigned long.
        types = []
        prog = mock_program(types=types)
        types.append(prog.int_type("long", 4, True))
        types.append(prog.int_type("unsigned long", 4, False))
        self.assertIdentical(
            prog.type("size_t"),
            prog.typedef_type("size_t", prog.type("unsigned long long")),
        )
        self.assertIdentical(
            prog.type("ptrdiff_t"),
            prog.typedef_type("ptrdiff_t", prog.type("long long")),
        )

        # 32-bit architecture with 8-byte long/unsigned long.
        types = []
        prog = mock_program(MOCK_32BIT_PLATFORM, types=types)
        types.append(prog.int_type("long", 8, True))
        types.append(prog.int_type("unsigned long", 8, False))
        self.assertIdentical(
            prog.type("size_t"), prog.typedef_type("size_t", prog.type("unsigned int"))
        )
        self.assertIdentical(
            prog.type("ptrdiff_t"), prog.typedef_type("ptrdiff_t", prog.type("int"))
        )

        # Nonsense sizes.
        types = []
        prog = mock_program(types=types)
        types.append(prog.int_type("int", 1, True))
        types.append(prog.int_type("unsigned int", 1, False))
        types.append(prog.int_type("long", 1, True))
        types.append(prog.int_type("unsigned long", 1, False))
        types.append(prog.int_type("long long", 2, True))
        types.append(prog.int_type("unsigned long long", 2, False))
        self.assertRaisesRegex(
            ValueError, "no suitable integer type for size_t", prog.type, "size_t"
        )
        self.assertRaisesRegex(
            ValueError, "no suitable integer type for ptrdiff_t", prog.type, "ptrdiff_t"
        )

    def test_tagged_type(self):
        self.types.append(self.point_type)
        self.types.append(self.option_type)
        self.types.append(self.color_type)
        self.assertIdentical(self.prog.type("struct point"), self.point_type)
        self.assertIdentical(self.prog.type("union option"), self.option_type)
        self.assertIdentical(self.prog.type("enum color"), self.color_type)

    def test_typedef(self):
        self.types.append(self.pid_type)
        self.assertIdentical(self.prog.type("pid_t"), self.pid_type)

    def test_pointer(self):
        self.assertIdentical(
            self.prog.type("int *"),
            self.prog.pointer_type(self.prog.int_type("int", 4, True)),
        )

    def test_pointer_to_const(self):
        self.assertIdentical(
            self.prog.type("const int *"),
            self.prog.pointer_type(
                self.prog.int_type("int", 4, True, qualifiers=Qualifiers.CONST)
            ),
        )

    def test_const_pointer(self):
        self.assertIdentical(
            self.prog.type("int * const"),
            self.prog.pointer_type(
                self.prog.int_type("int", 4, True), qualifiers=Qualifiers.CONST
            ),
        )

    def test_pointer_to_pointer(self):
        self.assertIdentical(
            self.prog.type("int **"),
            self.prog.pointer_type(
                self.prog.pointer_type(self.prog.int_type("int", 4, True))
            ),
        )
        self.assertIdentical(self.prog.type("int *((*))"), self.prog.type("int **"))

    def test_pointer_to_const_pointer(self):
        self.assertIdentical(
            self.prog.type("int * const *"),
            self.prog.pointer_type(
                self.prog.pointer_type(
                    self.prog.int_type("int", 4, True), qualifiers=Qualifiers.CONST
                )
            ),
        )

    def test_array(self):
        self.assertIdentical(
            self.prog.type("int [20]"),
            self.prog.array_type(self.prog.int_type("int", 4, True), 20),
        )

    def test_array_hexadecimal(self):
        self.assertIdentical(
            self.prog.type("int [0x20]"),
            self.prog.array_type(self.prog.int_type("int", 4, True), 32),
        )

    def test_array_octal(self):
        self.assertIdentical(
            self.prog.type("int [020]"),
            self.prog.array_type(self.prog.int_type("int", 4, True), 16),
        )

    def test_incomplete_array(self):
        self.assertIdentical(
            self.prog.type("int []"),
            self.prog.array_type(self.prog.int_type("int", 4, True)),
        )

    def test_array_two_dimensional(self):
        self.assertIdentical(
            self.prog.type("int [2][3]"),
            self.prog.array_type(
                self.prog.array_type(self.prog.int_type("int", 4, True), 3), 2
            ),
        )

    def test_array_three_dimensional(self):
        self.assertIdentical(
            self.prog.type("int [2][3][4]"),
            self.prog.array_type(
                self.prog.array_type(
                    self.prog.array_type(self.prog.int_type("int", 4, True), 4), 3
                ),
                2,
            ),
        )

    def test_array_of_pointers(self):
        self.assertIdentical(
            self.prog.type("int *[2][3]"),
            self.prog.array_type(
                self.prog.array_type(
                    self.prog.pointer_type(self.prog.int_type("int", 4, True)), 3
                ),
                2,
            ),
        )

    def test_pointer_to_array(self):
        self.assertIdentical(
            self.prog.type("int (*)[2]"),
            self.prog.pointer_type(
                self.prog.array_type(self.prog.int_type("int", 4, True), 2)
            ),
        )

    def test_pointer_to_two_dimensional_array(self):
        self.assertIdentical(
            self.prog.type("int (*)[2][3]"),
            self.prog.pointer_type(
                self.prog.array_type(
                    self.prog.array_type(self.prog.int_type("int", 4, True), 3), 2
                )
            ),
        )

    def test_pointer_to_pointer_to_array(self):
        self.assertIdentical(
            self.prog.type("int (**)[2]"),
            self.prog.pointer_type(
                self.prog.pointer_type(
                    self.prog.array_type(self.prog.int_type("int", 4, True), 2)
                )
            ),
        )

    def test_pointer_to_array_of_pointers(self):
        self.assertIdentical(
            self.prog.type("int *(*)[2]"),
            self.prog.pointer_type(
                self.prog.array_type(
                    self.prog.pointer_type(self.prog.int_type("int", 4, True)), 2
                )
            ),
        )
        self.assertIdentical(
            self.prog.type("int *((*)[2])"), self.prog.type("int *(*)[2]")
        )

    def test_array_of_pointers_to_array(self):
        self.assertIdentical(
            self.prog.type("int (*[2])[3]"),
            self.prog.array_type(
                self.prog.pointer_type(
                    self.prog.array_type(self.prog.int_type("int", 4, True), 3)
                ),
                2,
            ),
        )


class TestObjects(MockProgramTestCase):
    def test_invalid_finder(self):
        self.assertRaises(TypeError, self.prog.add_object_finder, "foo")

        self.prog.add_object_finder(lambda prog, name, flags, filename: "foo")
        self.assertRaises(TypeError, self.prog.object, "foo")

    def test_not_found(self):
        self.assertRaises(LookupError, self.prog.object, "foo")
        self.prog.add_object_finder(lambda prog, name, flags, filename: None)
        self.assertRaises(LookupError, self.prog.object, "foo")
        self.assertFalse("foo" in self.prog)

    def test_constant(self):
        self.objects.append(
            MockObject("PAGE_SIZE", self.prog.int_type("int", 4, True), value=4096)
        )
        self.assertIdentical(
            self.prog["PAGE_SIZE"],
            Object(self.prog, self.prog.int_type("int", 4, True), value=4096),
        )
        self.assertIdentical(
            self.prog.object("PAGE_SIZE", FindObjectFlags.CONSTANT),
            self.prog["PAGE_SIZE"],
        )
        self.assertTrue("PAGE_SIZE" in self.prog)

    def test_function(self):
        self.objects.append(
            MockObject(
                "func",
                self.prog.function_type(self.prog.void_type(), (), False),
                address=0xFFFF0000,
            )
        )
        self.assertIdentical(
            self.prog["func"],
            Object(
                self.prog,
                self.prog.function_type(self.prog.void_type(), (), False),
                address=0xFFFF0000,
            ),
        )
        self.assertIdentical(
            self.prog.object("func", FindObjectFlags.FUNCTION), self.prog["func"]
        )
        self.assertTrue("func" in self.prog)

    def test_variable(self):
        self.objects.append(
            MockObject(
                "counter", self.prog.int_type("int", 4, True), address=0xFFFF0000
            )
        )
        self.assertIdentical(
            self.prog["counter"],
            Object(self.prog, self.prog.int_type("int", 4, True), address=0xFFFF0000),
        )
        self.assertIdentical(
            self.prog.object("counter", FindObjectFlags.VARIABLE), self.prog["counter"]
        )
        self.assertTrue("counter" in self.prog)


class TestCoreDump(TestCase):
    def test_not_core_dump(self):
        prog = Program()
        self.assertRaisesRegex(
            ValueError, "not an ELF core file", prog.set_core_dump, "/dev/null"
        )
        with tempfile.NamedTemporaryFile() as f:
            f.write(create_elf_file(ET.EXEC, []))
            f.flush()
            self.assertRaisesRegex(
                ValueError, "not an ELF core file", prog.set_core_dump, f.name
            )

    def test_twice(self):
        prog = Program()
        with tempfile.NamedTemporaryFile() as f:
            f.write(create_elf_file(ET.CORE, []))
            f.flush()
            prog.set_core_dump(f.name)
            self.assertRaisesRegex(
                ValueError,
                "program memory was already initialized",
                prog.set_core_dump,
                f.name,
            )

    def test_simple(self):
        data = b"hello, world"
        prog = Program()
        with tempfile.NamedTemporaryFile() as f:
            f.write(
                create_elf_file(
                    ET.CORE, [ElfSection(p_type=PT.LOAD, vaddr=0xFFFF0000, data=data)]
                )
            )
            f.flush()
            prog.set_core_dump(f.name)
        self.assertEqual(prog.read(0xFFFF0000, len(data)), data)
        self.assertRaises(FaultError, prog.read, 0x0, len(data), physical=True)

    def test_physical(self):
        data = b"hello, world"
        prog = Program()
        with tempfile.NamedTemporaryFile() as f:
            f.write(
                create_elf_file(
                    ET.CORE,
                    [
                        ElfSection(
                            p_type=PT.LOAD, vaddr=0xFFFF0000, paddr=0xA0, data=data
                        ),
                    ],
                )
            )
            f.flush()
            prog.set_core_dump(f.name)
        self.assertEqual(prog.read(0xFFFF0000, len(data)), data)
        self.assertEqual(prog.read(0xA0, len(data), physical=True), data)

    def test_zero_fill(self):
        data = b"hello, world"
        prog = Program()
        with tempfile.NamedTemporaryFile() as f:
            f.write(
                create_elf_file(
                    ET.CORE,
                    [
                        ElfSection(
                            p_type=PT.LOAD,
                            vaddr=0xFFFF0000,
                            data=data,
                            memsz=len(data) + 4,
                        ),
                    ],
                )
            )
            f.flush()
            prog.set_core_dump(f.name)
        self.assertEqual(prog.read(0xFFFF0000, len(data) + 4), data + bytes(4))
