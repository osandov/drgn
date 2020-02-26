import ctypes
import itertools
import os
import tempfile
import unittest
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
    array_type,
    bool_type,
    float_type,
    function_type,
    host_platform,
    int_type,
    pointer_type,
    typedef_type,
    void_type,
)
from tests import (
    DEFAULT_LANGUAGE,
    MOCK_32BIT_PLATFORM,
    MOCK_PLATFORM,
    MockMemorySegment,
    MockObject,
    ObjectTestCase,
    color_type,
    mock_program,
    option_type,
    pid_type,
    point_type,
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
        self.assertRaisesRegex(
            LookupError, "^could not find 'typedef foo'$", prog.type, "foo"
        )
        self.assertRaisesRegex(
            LookupError,
            "^could not find 'typedef foo' in 'foo.c'$",
            prog.type,
            "foo",
            "foo.c",
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

    def test_pointer_type(self):
        prog = mock_program()
        self.assertEqual(prog.pointer_type(prog.type("int")), prog.type("int *"))
        self.assertEqual(prog.pointer_type("int"), prog.type("int *"))
        self.assertEqual(
            prog.pointer_type(prog.type("int"), Qualifiers.CONST),
            prog.type("int * const"),
        )

    def test_debug_info(self):
        Program().load_debug_info([])

    def test_language(self):
        self.assertEqual(Program().language, DEFAULT_LANGUAGE)


class TestMemory(unittest.TestCase):
    def test_simple_read(self):
        data = b"hello, world"
        prog = mock_program(segments=[MockMemorySegment(data, 0xFFFF0000, 0xA0),])
        self.assertEqual(prog.read(0xFFFF0000, len(data)), data)
        self.assertEqual(prog.read(0xA0, len(data), True), data)

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
            "memory read callback returned buffer of length 0 \(expected 8\)",
            prog.read,
            0xFFFF0000,
            8,
        )


class TestTypes(unittest.TestCase):
    def test_invalid_finder(self):
        self.assertRaises(TypeError, mock_program().add_type_finder, "foo")

        prog = mock_program()
        prog.add_type_finder(lambda kind, name, filename: "foo")
        self.assertRaises(TypeError, prog.type, "int")

    def test_wrong_kind(self):
        prog = mock_program()
        prog.add_type_finder(lambda kind, name, filename: void_type())
        self.assertRaises(TypeError, prog.type, "int")

    def test_not_found(self):
        prog = mock_program()
        self.assertRaises(LookupError, prog.type, "struct foo")
        prog.add_type_finder(lambda kind, name, filename: None)
        self.assertRaises(LookupError, prog.type, "struct foo")

    def test_default_primitive_types(self):
        def spellings(tokens, num_optional=0):
            for i in range(len(tokens) - num_optional, len(tokens) + 1):
                for perm in itertools.permutations(tokens[:i]):
                    yield " ".join(perm)

        for word_size in [8, 4]:
            prog = mock_program(
                MOCK_PLATFORM if word_size == 8 else MOCK_32BIT_PLATFORM
            )
            self.assertEqual(prog.type("_Bool"), bool_type("_Bool", 1))
            self.assertEqual(prog.type("char"), int_type("char", 1, True))
            for spelling in spellings(["signed", "char"]):
                self.assertEqual(prog.type(spelling), int_type("signed char", 1, True))
            for spelling in spellings(["unsigned", "char"]):
                self.assertEqual(
                    prog.type(spelling), int_type("unsigned char", 1, False)
                )
            for spelling in spellings(["short", "signed", "int"], 2):
                self.assertEqual(prog.type(spelling), int_type("short", 2, True))
            for spelling in spellings(["short", "unsigned", "int"], 1):
                self.assertEqual(
                    prog.type(spelling), int_type("unsigned short", 2, False)
                )
            for spelling in spellings(["int", "signed"], 1):
                self.assertEqual(prog.type(spelling), int_type("int", 4, True))
            for spelling in spellings(["unsigned", "int"]):
                self.assertEqual(
                    prog.type(spelling), int_type("unsigned int", 4, False)
                )
            for spelling in spellings(["long", "signed", "int"], 2):
                self.assertEqual(prog.type(spelling), int_type("long", word_size, True))
            for spelling in spellings(["long", "unsigned", "int"], 1):
                self.assertEqual(
                    prog.type(spelling), int_type("unsigned long", word_size, False)
                )
            for spelling in spellings(["long", "long", "signed", "int"], 2):
                self.assertEqual(prog.type(spelling), int_type("long long", 8, True))
            for spelling in spellings(["long", "long", "unsigned", "int"], 1):
                self.assertEqual(
                    prog.type(spelling), int_type("unsigned long long", 8, False)
                )
            self.assertEqual(prog.type("float"), float_type("float", 4))
            self.assertEqual(prog.type("double"), float_type("double", 8))
            for spelling in spellings(["long", "double"]):
                self.assertEqual(prog.type(spelling), float_type("long double", 16))
            self.assertEqual(
                prog.type("size_t"),
                typedef_type("size_t", int_type("unsigned long", word_size, False)),
            )
            self.assertEqual(
                prog.type("ptrdiff_t"),
                typedef_type("ptrdiff_t", int_type("long", word_size, True)),
            )

    def test_primitive_type(self):
        prog = mock_program(
            types=[int_type("long", 4, True), int_type("unsigned long", 4, True),]
        )
        self.assertEqual(prog.type("long"), int_type("long", 4, True))
        # unsigned long with signed=True isn't valid, so it should be ignored.
        self.assertEqual(
            prog.type("unsigned long"), int_type("unsigned long", 8, False)
        )

    def test_size_t_and_ptrdiff_t(self):
        # 64-bit architecture with 4-byte long/unsigned long.
        prog = mock_program(
            types=[int_type("long", 4, True), int_type("unsigned long", 4, False),]
        )
        self.assertEqual(
            prog.type("size_t"), typedef_type("size_t", prog.type("unsigned long long"))
        )
        self.assertEqual(
            prog.type("ptrdiff_t"), typedef_type("ptrdiff_t", prog.type("long long"))
        )

        # 32-bit architecture with 8-byte long/unsigned long.
        prog = mock_program(
            MOCK_32BIT_PLATFORM,
            types=[int_type("long", 8, True), int_type("unsigned long", 8, False),],
        )
        self.assertEqual(
            prog.type("size_t"), typedef_type("size_t", prog.type("unsigned int"))
        )
        self.assertEqual(
            prog.type("ptrdiff_t"), typedef_type("ptrdiff_t", prog.type("int"))
        )

        # Nonsense sizes.
        prog = mock_program(
            types=[
                int_type("int", 1, True),
                int_type("unsigned int", 1, False),
                int_type("long", 1, True),
                int_type("unsigned long", 1, False),
                int_type("long long", 2, True),
                int_type("unsigned long long", 2, False),
            ]
        )
        self.assertRaisesRegex(
            ValueError, "no suitable integer type for size_t", prog.type, "size_t"
        )
        self.assertRaisesRegex(
            ValueError, "no suitable integer type for ptrdiff_t", prog.type, "ptrdiff_t"
        )

    def test_tagged_type(self):
        prog = mock_program(types=[point_type, option_type, color_type])
        self.assertEqual(prog.type("struct point"), point_type)
        self.assertEqual(prog.type("union option"), option_type)
        self.assertEqual(prog.type("enum color"), color_type)

    def test_typedef(self):
        prog = mock_program(types=[pid_type])
        self.assertEqual(prog.type("pid_t"), pid_type)

    def test_pointer(self):
        prog = mock_program()
        self.assertEqual(prog.type("int *"), pointer_type(8, int_type("int", 4, True)))
        self.assertEqual(
            prog.type("const int *"),
            pointer_type(8, int_type("int", 4, True, Qualifiers.CONST)),
        )
        self.assertEqual(
            prog.type("int * const"),
            pointer_type(8, int_type("int", 4, True), Qualifiers.CONST),
        )
        self.assertEqual(
            prog.type("int **"),
            pointer_type(8, pointer_type(8, int_type("int", 4, True))),
        )
        self.assertEqual(
            prog.type("int *((*))"),
            pointer_type(8, pointer_type(8, int_type("int", 4, True))),
        )
        self.assertEqual(
            prog.type("int * const *"),
            pointer_type(
                8, pointer_type(8, int_type("int", 4, True), Qualifiers.CONST)
            ),
        )

    def test_array(self):
        prog = mock_program()
        self.assertEqual(
            prog.type("int []"), array_type(None, int_type("int", 4, True))
        )
        self.assertEqual(
            prog.type("int [20]"), array_type(20, int_type("int", 4, True))
        )
        self.assertEqual(
            prog.type("int [0x20]"), array_type(32, int_type("int", 4, True))
        )
        self.assertEqual(
            prog.type("int [020]"), array_type(16, int_type("int", 4, True))
        )
        self.assertEqual(
            prog.type("int [2][3]"),
            array_type(2, array_type(3, int_type("int", 4, True))),
        )
        self.assertEqual(
            prog.type("int [2][3][4]"),
            array_type(2, array_type(3, array_type(4, int_type("int", 4, True)))),
        )

    def test_array_of_pointers(self):
        prog = mock_program()
        self.assertEqual(
            prog.type("int *[2][3]"),
            array_type(2, array_type(3, pointer_type(8, int_type("int", 4, True)))),
        )

    def test_pointer_to_array(self):
        prog = mock_program()
        self.assertEqual(
            prog.type("int (*)[2]"),
            pointer_type(8, array_type(2, int_type("int", 4, True))),
        )
        self.assertEqual(
            prog.type("int (*)[2][3]"),
            pointer_type(8, array_type(2, array_type(3, int_type("int", 4, True)))),
        )

    def test_pointer_to_pointer_to_array(self):
        prog = mock_program()
        self.assertEqual(
            prog.type("int (**)[2]"),
            pointer_type(8, pointer_type(8, array_type(2, int_type("int", 4, True)))),
        )

    def test_pointer_to_array_of_pointers(self):
        prog = mock_program()
        self.assertEqual(
            prog.type("int *(*)[2]"),
            pointer_type(8, array_type(2, pointer_type(8, int_type("int", 4, True)))),
        )
        self.assertEqual(
            prog.type("int *((*)[2])"),
            pointer_type(8, array_type(2, pointer_type(8, int_type("int", 4, True)))),
        )

    def test_array_of_pointers_to_array(self):
        prog = mock_program()
        self.assertEqual(
            prog.type("int (*[2])[3]"),
            array_type(2, pointer_type(8, array_type(3, int_type("int", 4, True)))),
        )


class TestObjects(ObjectTestCase):
    def test_invalid_finder(self):
        self.assertRaises(TypeError, mock_program().add_object_finder, "foo")

        prog = mock_program()
        prog.add_object_finder(lambda prog, name, flags, filename: "foo")
        self.assertRaises(TypeError, prog.object, "foo")

    def test_not_found(self):
        prog = mock_program()
        self.assertRaises(LookupError, prog.object, "foo")
        prog.add_object_finder(lambda prog, name, flags, filename: None)
        self.assertRaises(LookupError, prog.object, "foo")
        self.assertFalse("foo" in prog)

    def test_constant(self):
        mock_obj = MockObject("PAGE_SIZE", int_type("int", 4, True), value=4096)
        prog = mock_program(objects=[mock_obj])
        self.assertEqual(
            prog["PAGE_SIZE"], Object(prog, int_type("int", 4, True), value=4096)
        )
        self.assertEqual(
            prog.object("PAGE_SIZE", FindObjectFlags.CONSTANT), prog["PAGE_SIZE"]
        )
        self.assertTrue("PAGE_SIZE" in prog)

    def test_function(self):
        mock_obj = MockObject(
            "func", function_type(void_type(), (), False), address=0xFFFF0000
        )
        prog = mock_program(objects=[mock_obj])
        self.assertEqual(
            prog["func"],
            Object(prog, function_type(void_type(), (), False), address=0xFFFF0000),
        )
        self.assertEqual(prog.object("func", FindObjectFlags.FUNCTION), prog["func"])
        self.assertTrue("func" in prog)

    def test_variable(self):
        mock_obj = MockObject("counter", int_type("int", 4, True), address=0xFFFF0000)
        prog = mock_program(objects=[mock_obj])
        self.assertEqual(
            prog["counter"], Object(prog, int_type("int", 4, True), address=0xFFFF0000)
        )
        self.assertEqual(
            prog.object("counter", FindObjectFlags.VARIABLE), prog["counter"]
        )
        self.assertTrue("counter" in prog)


class TestCoreDump(unittest.TestCase):
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
                    ET.CORE, [ElfSection(p_type=PT.LOAD, vaddr=0xFFFF0000, data=data,),]
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
                            p_type=PT.LOAD, vaddr=0xFFFF0000, paddr=0xA0, data=data,
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
