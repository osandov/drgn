from collections import OrderedDict
import ctypes
import os.path
import struct
import subprocess
import sys
import tempfile
import unittest

from drgn.dwarfindex import DwarfIndex
from drgn.dwarf import DW_TAG
from drgn.type import (
    ArrayType,
    BitFieldType,
    BoolType,
    EnumType,
    FloatType,
    IntType,
    PointerType,
    StructType,
    TypedefType,
    TypeFactory,
    UnionType,
    VoidType,
)


point_type = StructType('point', 8, [
    ('x', 0, lambda: IntType('int', 4, True)),
    ('y', 4, lambda: IntType('int', 4, True)),
])
anonymous_point_type = StructType(None, 8, [
    ('x', 0, lambda: IntType('int', 4, True)),
    ('y', 4, lambda: IntType('int', 4, True)),
])
const_anonymous_point_type = StructType(None, 8, [
    ('x', 0, lambda: IntType('int', 4, True)),
    ('y', 4, lambda: IntType('int', 4, True)),
], {'const'})
line_segment_type = StructType('line_segment', 16, [
    ('a', 0, lambda: point_type),
    ('b', 8, lambda: point_type),
])
pointer_size = ctypes.sizeof(ctypes.c_void_p)


class TestType(unittest.TestCase):
    def test_void(self):
        type_ = VoidType()
        self.assertEqual(str(type_), 'void')
        self.assertRaises(ValueError, type_.sizeof)
        self.assertRaises(ValueError, type_.read, b'')
        self.assertRaises(ValueError, type_.format, b'')

    def test_int(self):
        type_ = IntType('int', 4, True)
        self.assertEqual(str(type_), 'int')
        self.assertEqual(type_.sizeof(), 4)
        buffer = (99).to_bytes(4, sys.byteorder)
        self.assertEqual(type_.read(buffer), 99)
        self.assertEqual(type_.format(buffer), '(int)99')
        self.assertEqual(type_.format(buffer, cast=False), '99')
        buffer = b'\0\0' + (-1).to_bytes(4, sys.byteorder, signed=True)
        self.assertEqual(type_.read(buffer, 2), -1)
        self.assertRaises(ValueError, type_.read, buffer, 3)

        type_ = IntType('unsigned long', 8, False)
        buffer = b'\0' + (99).to_bytes(8, sys.byteorder)
        self.assertEqual(type_.read(buffer, 1), 99)
        buffer = b'\xff\xff\xff' + (0xffffffffffffffff).to_bytes(8, sys.byteorder)
        self.assertEqual(type_.read(buffer, 3), 0xffffffffffffffff)

    def test_float(self):
        type_ = FloatType('double', 8)
        self.assertEqual(str(type_), 'double')
        self.assertEqual(type_.sizeof(), 8)
        buffer = struct.pack('d', 3.14)
        self.assertEqual(type_.read(buffer), 3.14)
        self.assertEqual(type_.read(b'\0' + buffer, 1), 3.14)
        self.assertRaises(ValueError, type_.read, buffer, 1)

        type_ = FloatType('float', 4)
        buffer = struct.pack('f', 1.5)
        self.assertEqual(type_.read(buffer), 1.5)
        self.assertEqual(type_.read(b'\0\0\0' + buffer, 3), 1.5)
        self.assertRaises(ValueError, type_.read, b'')

    def test_bool(self):
        type_ = BoolType('_Bool', 1)
        self.assertEqual(str(type_), '_Bool')
        self.assertEqual(type_.sizeof(), 1)
        self.assertEqual(type_.read(b'\0'), 0)
        self.assertEqual(type_.format(b'\0'), '(_Bool)0')
        self.assertEqual(type_.read(b'\0\x01', 1), 1)
        self.assertEqual(type_.format(b'\x01'), '(_Bool)1')
        self.assertRaises(ValueError, type_.read, b'')
        self.assertRaises(ValueError, type_.read, b'\0', 1)

    def test_qualifiers(self):
        type_ = IntType('int', 4, True, {'const'})
        self.assertEqual(str(type_), 'const int')
        self.assertEqual(type_.sizeof(), 4)
        self.assertEqual(type_.read(b'\0\0\0\0'), 0)

        type_.qualifiers.add('volatile')
        self.assertEqual(str(type_), 'const volatile int')
        self.assertEqual(type_.sizeof(), 4)

    def test_typedef(self):
        type_ = TypedefType('INT', IntType('int', 4, True))
        self.assertEqual(str(type_), 'typedef int INT')
        self.assertEqual(type_.sizeof(), 4)
        self.assertEqual(type_.read(b'\0\0\0\0'), 0)
        self.assertEqual(type_.format(b'\0\0\0\0'), '(INT)0')

        type_ = TypedefType('string', PointerType(pointer_size, IntType('char', 1, True)))
        self.assertEqual(str(type_), 'typedef char *string')
        self.assertEqual(type_.sizeof(), pointer_size)

        type_ = TypedefType('CINT', IntType('int', 4, True, {'const'}))
        self.assertEqual(str(type_), 'typedef const int CINT')
        self.assertEqual(type_.sizeof(), 4)
        self.assertEqual(type_.read(b'\0\0\0\0'), 0)

        type_ = TypedefType('INT', IntType('int', 4, True), {'const'})
        self.assertEqual(str(type_), 'const typedef int INT')
        self.assertEqual(type_.sizeof(), 4)
        self.assertEqual(type_.read(b'\0\0\0\0'), 0)

    def test_struct(self):
        self.assertEqual(str(point_type), """\
struct point {
	int x;
	int y;
}""")
        self.assertEqual(point_type.sizeof(), 8)
        self.assertEqual(point_type.members(), ['x', 'y'])
        self.assertEqual(point_type.offsetof('x'), 0)
        self.assertEqual(point_type.offsetof('y'), 4)
        self.assertEqual(point_type.typeof('x'), IntType('int', 4, True))
        self.assertEqual(point_type.typeof('y'), IntType('int', 4, True))
        buffer = ((99).to_bytes(4, sys.byteorder, signed=True) +
                  (-1).to_bytes(4, sys.byteorder, signed=True))
        self.assertEqual(point_type.read(buffer), OrderedDict([
            ('x', 99),
            ('y', -1),
        ]))
        self.assertEqual(point_type.read(b'\0' + buffer, 1), OrderedDict([
            ('x', 99),
            ('y', -1),
        ]))
        self.assertEqual(point_type.format(b'\0' + buffer, 1), """\
(struct point){
	.x = (int)99,
	.y = (int)-1,
}""")
        self.assertRaises(ValueError, point_type.read, buffer[:7])
        self.assertRaises(ValueError, point_type.read, buffer, 1)

        self.assertEqual(str(line_segment_type), """\
struct line_segment {
	struct point a;
	struct point b;
}""")

        self.assertEqual(str(anonymous_point_type), """\
struct {
	int x;
	int y;
}""")

        type_ = StructType('line_segment', 16, [
            (None, 0, lambda: const_anonymous_point_type),
            ('b', 8, lambda: const_anonymous_point_type),
        ], {'const', 'volatile'})
        self.assertEqual(str(type_), """\
const volatile struct line_segment {
	const struct {
		int x;
		int y;
	};
	const struct {
		int x;
		int y;
	} b;
}""")

        type_ = StructType('foo', None, None)
        self.assertEqual(str(type_), 'struct foo')
        self.assertRaises(ValueError, type_.sizeof)

        type_ = StructType(None, 12, [
            ('x', 0, lambda: IntType('int', 4, True)),
            (None, 4, lambda: StructType('point', 8, [
                ('y', 0, lambda: IntType('int', 4, True)),
                ('z', 4, lambda: IntType('int', 4, True)),
            ])),
        ])
        self.assertEqual(type_.members(), ['x', 'y', 'z'])
        self.assertEqual(type_.offsetof('x'), 0)
        self.assertEqual(type_.offsetof('y'), 4)
        self.assertEqual(type_.offsetof('z'), 8)
        self.assertEqual(type_.typeof('x'), IntType('int', 4, True))
        self.assertEqual(type_.typeof('y'), IntType('int', 4, True))
        self.assertEqual(type_.typeof('z'), IntType('int', 4, True))

    def test_bit_field(self):
        type_ = StructType(None, 8, [
            ('x', 0, lambda: BitFieldType(IntType('int', 4, True), 0, 4)),
            ('y', 0, lambda: BitFieldType(IntType('int', 4, True, {'const'}), 4, 28)),
            ('z', 4, lambda: BitFieldType(IntType('int', 4, True), 0, 5)),
        ])
        self.assertEqual(str(type_), """\
struct {
	int x : 4;
	const int y : 28;
	int z : 5;
}""")
        buffer = b'\x07\x10\x5e\x5f\x1f\0\0\0'
        self.assertEqual(type_.typeof('x').read(buffer), 7)
        self.assertEqual(type_.typeof('x').read(b'\0' + buffer, 1), 7)
        self.assertRaises(ValueError, type_.typeof('x').read, b'')
        self.assertEqual(type_.typeof('y').read(buffer), 100000000)
        self.assertEqual(type_.typeof('y').read(b'\0\0\0' + buffer, 3),
                         100000000)
        self.assertRaises(ValueError, type_.typeof('y').read, buffer[:3])
        self.assertEqual(type_.typeof('z').read(buffer, 4), -1)
        self.assertEqual(type_.typeof('z').read(b'\0\0' + buffer, 6), -1)
        self.assertRaises(ValueError, type_.typeof('z').read, buffer, 8)
        self.assertEqual(type_.read(buffer), OrderedDict([
            ('x', 7),
            ('y', 100000000),
            ('z', -1),
        ]))
        self.assertEqual(type_.format(buffer), """\
{
	.x = (int)7,
	.y = (const int)100000000,
	.z = (int)-1,
}""")

        type_ = BitFieldType(IntType('int', 4, True), 0, 4)
        self.assertEqual(str(type_), 'int : 4')
        self.assertRaises(ValueError, type_.type_name)

    def test_union(self):
        type_ = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ])
        self.assertEqual(str(type_), """\
union value {
	int i;
	float f;
}""")
        self.assertEqual(type_.sizeof(), 4)
        buffer = b'\x00\x00\x80?'
        self.assertEqual(type_.read(buffer), OrderedDict([
            ('i', 1065353216),
            ('f', 1.0),
        ]))
        self.assertEqual(type_.read(b'\0' + buffer, 1), OrderedDict([
            ('i', 1065353216),
            ('f', 1.0),
        ]))
        self.assertEqual(type_.format(buffer), """\
(union value){
	.i = (int)1065353216,
	.f = (float)1.0,
}""")

        type_ = UnionType('value', 8, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
            ('p', 0, lambda: point_type),
        ])
        self.assertEqual(str(type_), """\
union value {
	int i;
	float f;
	struct point p;
}""")

        type_ = UnionType('foo', None, None)
        self.assertEqual(str(type_), 'union foo')
        self.assertRaises(ValueError, type_.sizeof)

    def test_enum(self):
        type_ = EnumType('color', 4, False, [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
        self.assertEqual(str(type_), """\
enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""")
        self.assertEqual(type_.sizeof(), 4)
        buffer = (0).to_bytes(4, sys.byteorder)
        self.assertEqual(type_.read(buffer), type_._enum.RED)
        buffer = (1).to_bytes(4, sys.byteorder)
        self.assertEqual(type_.read(b'\0' + buffer, 1), type_._enum.GREEN)
        self.assertEqual(type_.format(b'\0' + buffer, 1), '(enum color)GREEN')
        buffer = (4).to_bytes(4, sys.byteorder)
        self.assertEqual(type_.read(b'\0\0\0' + buffer, 3), 4)
        self.assertEqual(type_.format(b'\0\0\0' + buffer, 3), '(enum color)4')
        self.assertRaises(ValueError, type_.read, buffer, 3)
        self.assertRaises(ValueError, type_.read, b'')

        type_.qualifiers.add('const')
        self.assertEqual(str(type_), """\
const enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""")

        type_.qualifiers.add('volatile')
        self.assertEqual(str(type_), """\
const volatile enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""")

        type_ = EnumType(None, 4, True, [
            ('RED', 10),
            ('GREEN', 11),
            ('BLUE', -1)
        ])
        self.assertEqual(str(type_), """\
enum {
	RED = 10,
	GREEN = 11,
	BLUE = -1,
}""")
        buffer = (-1).to_bytes(4, sys.byteorder, signed=True)
        self.assertEqual(type_.read(buffer), -1)

        type_ = EnumType('foo', None, None, None)
        self.assertEqual(str(type_), 'enum foo')
        self.assertRaises(ValueError, type_.sizeof)

    def test_pointer(self):
        type_ = PointerType(pointer_size, IntType('int', 4, True))
        self.assertEqual(str(type_), 'int *')
        self.assertEqual(type_.sizeof(), pointer_size)
        buffer = (0x7fffffff).to_bytes(pointer_size, sys.byteorder)
        self.assertEqual(type_.read(buffer), 0x7fffffff)
        self.assertEqual(type_.read(b'\0' + buffer, 1), 0x7fffffff)
        self.assertEqual(type_.format(b'\0' + buffer, 1), '(int *)0x7fffffff')

        type_ = PointerType(pointer_size, IntType('int', 4, True), {'const'})
        self.assertEqual(str(type_), 'int * const')

        type_ = PointerType(pointer_size, point_type)
        self.assertEqual(str(type_), 'struct point *')

        type_ = PointerType(pointer_size, PointerType(pointer_size, IntType('int', 4, True)))
        self.assertEqual(str(type_), 'int **')

        type_ = PointerType(pointer_size, VoidType())
        self.assertEqual(str(type_), 'void *')

    def test_array(self):
        type_ = ArrayType(IntType('int', 4, True), 2)
        self.assertEqual(str(type_), 'int [2]')
        self.assertEqual(type_.sizeof(), 8)
        buffer = ((99).to_bytes(4, sys.byteorder, signed=True) +
                  (-1).to_bytes(4, sys.byteorder, signed=True))
        self.assertEqual(type_.read(buffer), [99, -1])
        self.assertEqual(type_.read(b'\0\0\0' + buffer, 3), [99, -1])
        self.assertEqual(type_.format(b'\0\0\0' + buffer, 3), """\
(int [2]){
	99,
	-1,
}""")
        buffer = ((99).to_bytes(4, sys.byteorder, signed=True) +
                  (0).to_bytes(4, sys.byteorder, signed=True))
        self.assertEqual(type_.format(b'\0\0\0' + buffer, 3), """\
(int [2]){
	99,
}""")
        buffer = ((0).to_bytes(4, sys.byteorder, signed=True) +
                  (-1).to_bytes(4, sys.byteorder, signed=True))
        self.assertEqual(type_.format(b'\0\0\0' + buffer, 3), """\
(int [2]){
	0,
	-1,
}""")
        self.assertRaises(ValueError, type_.read, buffer, 3)
        self.assertRaises(ValueError, type_.format, buffer, 3)

        type_ = ArrayType(ArrayType(IntType('int', 4, True), 3), 2)
        self.assertEqual(str(type_), 'int [2][3]')

        type_ = ArrayType(ArrayType(ArrayType(IntType('int', 4, True), 4), 3), 2)
        self.assertEqual(str(type_), 'int [2][3][4]')

    def test_array_with_empty_element(self):
        type_ = ArrayType(StructType('empty', 0, []), 2)
        self.assertEqual(str(type_), 'struct empty [2]')
        self.assertEqual(type_.sizeof(), 0)
        self.assertEqual(type_.read(b''), [OrderedDict(), OrderedDict()])
        self.assertEqual(type_.format(b''), '(struct empty [2]){}')
        self.assertRaises(ValueError, type_.format, b'', 1)

    def test_incomplete_array(self):
        type_ = ArrayType(IntType('int', 4, True), None)
        self.assertEqual(str(type_), 'int []')
        self.assertRaises(ValueError, type_.sizeof)
        self.assertRaises(ValueError, type_.read, b'')
        self.assertEqual(type_.format(b''), '(int []){}')

        type_ = ArrayType(ArrayType(IntType('int', 4, True), 2), None)
        self.assertEqual(str(type_), 'int [][2]')


class TestFromDwarfType(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def compile_type(self, decl):
        object_path = os.path.join(self.tmp_dir.name, 'test')
        source_path = object_path + '.c'
        with open(source_path, 'w') as f:
            f.write(decl)
            f.write(';\nint main(void) { return 0; }\n')
        subprocess.check_call(['gcc', '-g', '-gz=none', '-c', '-o', object_path, source_path])
        dwarf_index = DwarfIndex([object_path])
        type_factory = TypeFactory(dwarf_index)
        dwarf_type = dwarf_index.find('x', DW_TAG.variable).type()
        return type_factory.from_dwarf_type(dwarf_type)

    def test_char(self):
        self.assertEqual(self.compile_type('char x'),
                        IntType('char', 1, True))
        self.assertEqual(self.compile_type('signed char x'),
                        IntType('signed char', 1, True))
        self.assertEqual(self.compile_type('unsigned char x'),
                        IntType('unsigned char', 1, False))

    def test_short(self):
        self.assertEqual(self.compile_type('short x'),
                        IntType('short int', 2, True))
        self.assertEqual(self.compile_type('signed short x'),
                        IntType('short int', 2, True))
        self.assertEqual(self.compile_type('unsigned short x'),
                        IntType('short unsigned int', 2, False))

    def test_int(self):
        self.assertEqual(self.compile_type('int x'),
                        IntType('int', 4, True))
        self.assertEqual(self.compile_type('signed int x'),
                        IntType('int', 4, True))
        self.assertEqual(self.compile_type('unsigned int x'),
                        IntType('unsigned int', 4, False))

    def test_long(self):
        self.assertEqual(self.compile_type('long x'),
                        IntType('long int', 8, True))
        self.assertEqual(self.compile_type('signed long x'),
                        IntType('long int', 8, True))
        self.assertEqual(self.compile_type('unsigned long x'),
                        IntType('long unsigned int', 8, False))

    def test_long_long(self):
        self.assertEqual(self.compile_type('long long x'),
                        IntType('long long int', 8, True))
        self.assertEqual(self.compile_type('signed long long x'),
                        IntType('long long int', 8, True))
        self.assertEqual(self.compile_type('unsigned long long x'),
                        IntType('long long unsigned int', 8, False))

    def test_float(self):
        self.assertEqual(self.compile_type('float x'),
                         FloatType('float', 4))
        self.assertEqual(self.compile_type('double x'),
                         FloatType('double', 8))
        self.assertEqual(self.compile_type('long double x'),
                         FloatType('long double', 16))

    def test_bool(self):
        self.assertEqual(self.compile_type('_Bool x'), BoolType('_Bool', 1))

    def test_qualifiers(self):
        # restrict is only valid in function parameters, and GCC doesn't seem
        # to create a type for _Atomic.
        self.assertEqual(self.compile_type('const int x'),
                        IntType('int', 4, True, {'const'}))
        self.assertEqual(self.compile_type('volatile int x'),
                        IntType('int', 4, True, {'volatile'}))
        self.assertEqual(self.compile_type('const volatile int x'),
                        IntType('int', 4, True, {'const', 'volatile'}))

    def test_typedef(self):
        self.assertEqual(self.compile_type('typedef int INT; INT x'),
                         TypedefType('INT', IntType('int', 4, True)))
        self.assertEqual(self.compile_type('typedef char *string; string x'),
                        TypedefType('string', PointerType(pointer_size, IntType('char', 1, True))))
        self.assertEqual(self.compile_type('typedef const int CINT; CINT x'),
                         TypedefType('CINT', IntType('int', 4, True, {'const'})))
        self.assertEqual(self.compile_type('typedef int INT; const INT x'),
                         TypedefType('INT', IntType('int', 4, True), {'const'}))

    def test_struct(self):
        self.assertEqual(self.compile_type("""\
struct point {
	int x;
	int y;
} x;"""), point_type)

        self.assertEqual(self.compile_type("""\
struct point {
	int x;
	int y;
};

struct line_segment {
	struct point a;
	struct point b;
} x;"""), line_segment_type)

        self.assertEqual(self.compile_type("""\
struct {
	int x;
	int y;
} x;"""), anonymous_point_type)

        self.assertEqual(self.compile_type("""\
const struct line_segment {
	const struct {
		int x;
		int y;
	};
	const struct {
		int x;
		int y;
	} b;
} x;"""), StructType('line_segment', 16, [
    (None, 0, lambda: const_anonymous_point_type),
    ('b', 8, lambda: const_anonymous_point_type),
], {'const'}))

    def test_incomplete_struct(self):
        self.assertEqual(self.compile_type('struct foo; extern struct foo x'),
                         StructType('foo', None, None))

    def test_bit_field(self):
        self.assertEqual(self.compile_type("""\
struct {
	int x : 4;
	const int y : 28;
	int z : 5;
} x;"""), StructType(None, 8, [
    ('x', 0, lambda: BitFieldType(IntType('int', 4, True), 0, 4)),
    ('y', 0, lambda: BitFieldType(IntType('int', 4, True, {'const'}), 4, 28)),
    ('z', 4, lambda: BitFieldType(IntType('int', 4, True), 0, 5)),
]))

    def test_union(self):
        self.assertEqual(self.compile_type("""\
union value {
	int i;
	float f;
} x;"""), UnionType('value', 4, [
    ('i', 0, lambda: IntType('int', 4, True)),
    ('f', 0, lambda: FloatType('float', 4)),
]))

        self.assertEqual(self.compile_type("""\
struct point {
	int x;
	int y;
};

union value {
	int i;
	float f;
	struct point p;
} x;"""), UnionType('value', 8, [
    ('i', 0, lambda: IntType('int', 4, True)),
    ('f', 0, lambda: FloatType('float', 4)),
    ('p', 0, lambda: point_type),
]))

    def test_incomplete_union(self):
        self.assertEqual(self.compile_type('union foo; extern union foo x'),
                         UnionType('foo', None, None))

    def test_enum(self):
        self.assertEqual(self.compile_type("""\
enum color {
	RED,
	GREEN,
	BLUE,
} x;"""), EnumType('color', 4, False, [('RED', 0), ('GREEN', 1), ('BLUE', 2)]))

        self.assertEqual(self.compile_type("""\
enum {
	RED = 10,
	GREEN,
	BLUE = -1,
} x;"""), EnumType(None, 4, True, [('RED', 10), ('GREEN', 11), ('BLUE', -1)]))

    def test_incomplete_enum(self):
        self.assertEqual(self.compile_type('enum foo; extern enum foo x'),
                         EnumType('foo', None, None, None))

    def test_pointer(self):
        self.assertEqual(self.compile_type('int *x'),
                         PointerType(pointer_size, IntType('int', 4, True)))

        self.assertEqual(self.compile_type('int * const x'),
                         PointerType(pointer_size, IntType('int', 4, True), {'const'}))

        self.assertEqual(self.compile_type("""\
struct point {
	int x;
	int y;
} *x;"""), PointerType(pointer_size, point_type))

        self.assertEqual(self.compile_type('int **x'),
                         PointerType(pointer_size, PointerType(pointer_size, IntType('int', 4, True))))

        self.assertEqual(self.compile_type('void *x'),
                         PointerType(pointer_size, VoidType()))

    def test_array(self):
        self.assertEqual(self.compile_type('int x[2]'),
                        ArrayType(IntType('int', 4, True), 2))
        self.assertEqual(self.compile_type('int x[2][3]'),
                        ArrayType(ArrayType(IntType('int', 4, True), 3), 2))
        self.assertEqual(self.compile_type('int x[2][3][4]'),
                        ArrayType(ArrayType(ArrayType(IntType('int', 4, True), 4), 3), 2))

    def test_incomplete_array(self):
        self.assertEqual(self.compile_type('extern int x[]'),
                        ArrayType(IntType('int', 4, True), None))
        self.assertEqual(self.compile_type('extern int x[][2]'),
                        ArrayType(ArrayType(IntType('int', 4, True), 2), None))


class TestFromTypeString(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmp_dir:
            object_path = os.path.join(tmp_dir, 'test')
            source_path = object_path + '.c'
            with open(source_path, 'w') as f:
                f.write("""\
int i;

struct point {
	int x, y;
} u;

union value {
	int i;
	float f;
} v;

enum color {
	RED,
	GREEN,
	BLUE,
} e;

typedef struct point point;

point t;

int main(void)
{
	return 0;
}
""")
            subprocess.check_call(['gcc', '-g', '-gz=none', '-c', '-o', object_path, source_path])
            dwarf_index = DwarfIndex([object_path])
            cls.type_factory = TypeFactory(dwarf_index)

    def test_void_type(self):
        self.assertEqual(self.type_factory.from_type_string('void'),
                         VoidType())
        self.assertEqual(self.type_factory.from_type_string('const void'),
                         VoidType({'const'}))

    def test_base_type(self):
        self.assertEqual(self.type_factory.from_type_string('int'),
                         IntType('int', 4, True))
        self.assertEqual(self.type_factory.from_type_string('volatile int'),
                         IntType('int', 4, True, {'volatile'}))

    def test_struct_type(self):
        self.assertEqual(self.type_factory.from_type_string('struct point'),
                         point_type)

    def test_union_type(self):
        self.assertEqual(self.type_factory.from_type_string('union value'),
                         UnionType('value', 4, [
                             ('i', 0, lambda: IntType('int', 4, True)),
                             ('f', 0, lambda: FloatType('float', 4)),
                         ]))

    def test_enum_type(self):
        self.assertEqual(self.type_factory.from_type_string('enum color'),
                         EnumType('color', 4, False, [
                             ('RED', 0),
                             ('GREEN', 1),
                             ('BLUE', 2)
                         ]))

    def test_typedef_type(self):
        self.assertEqual(self.type_factory.from_type_string('point'),
                         TypedefType('point', point_type))
        self.assertEqual(self.type_factory.from_type_string('const point'),
                         TypedefType('point', point_type, {'const'}))

    def test_pointer_type(self):
        self.assertEqual(self.type_factory.from_type_string('int *'),
                         PointerType(pointer_size, IntType('int', 4, True)))
        self.assertEqual(self.type_factory.from_type_string('int * const'),
                         PointerType(pointer_size, IntType('int', 4, True), {'const'}))

    def test_array_type(self):
        self.assertEqual(self.type_factory.from_type_string('int [4]'),
                         ArrayType(IntType('int', 4, True), 4))
        self.assertEqual(self.type_factory.from_type_string('int []'),
                         ArrayType(IntType('int', 4, True), None))
