from collections import OrderedDict
import ctypes
import math
import struct
import sys
import unittest

from drgn.type import (
    ArrayType,
    BitFieldType,
    BoolType,
    EnumType,
    FloatType,
    IntType,
    PointerType,
    StructType,
    Type,
    TypedefType,
    UnionType,
    VoidType,
)


def compound_type_dict_for_eq(type_):
    # Compare the result of the type thunks rather than the thunks themselves.
    d = dict(type_.__dict__)
    if d['_members'] is not None:
        d['_members'] = [
            (name, offset, type_thunk()) for name, offset, type_thunk in
            d['_members']
        ]
    del d['_members_by_name']
    return d


def enum_type_dict_for_eq(type_):
    d = dict(type_.__dict__)
    if d['enum'] is not None:
        d['enum'] = d['enum'].__members__
    return d


def type_eq(self, other):
    if not isinstance(other, self.__class__):
        return False
    if isinstance(self, (StructType, UnionType)):
        return compound_type_dict_for_eq(self) == compound_type_dict_for_eq(other)
    elif isinstance(self, EnumType):
        return enum_type_dict_for_eq(self) == enum_type_dict_for_eq(other)
    else:
        return self.__dict__ == other.__dict__


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
], frozenset({'const'}))
line_segment_type = StructType('line_segment', 16, [
    ('a', 0, lambda: point_type),
    ('b', 8, lambda: point_type),
])
pointer_size = ctypes.sizeof(ctypes.c_void_p)


class TypeTestCase(unittest.TestCase):
    def setUp(self):
        Type.__eq__ = type_eq

    def tearDown(self):
        del Type.__eq__


class TestType(TypeTestCase):
    def test_void(self):
        type_ = VoidType()
        self.assertEqual(str(type_), 'void')
        self.assertRaises(ValueError, type_.sizeof)
        self.assertRaises(ValueError, type_.read, b'')
        self.assertRaises(ValueError, type_.read_pretty, b'')

    def test_int(self):
        type_ = IntType('int', 4, True)
        self.assertEqual(str(type_), 'int')
        self.assertEqual(type_.sizeof(), 4)
        buffer = (99).to_bytes(4, sys.byteorder)
        self.assertEqual(type_.read(buffer), 99)
        self.assertEqual(type_.read_pretty(buffer), '(int)99')
        self.assertEqual(type_.read_pretty(buffer, cast=False), '99')
        buffer = b'\0\0' + (-1).to_bytes(4, sys.byteorder, signed=True)
        self.assertEqual(type_.read(buffer, 2), -1)
        self.assertRaises(ValueError, type_.read, buffer, 3)
        self.assertEqual(type_.real_type(), type_)

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
        self.assertEqual(type_.read_pretty(b'\0'), '(_Bool)0')
        self.assertEqual(type_.read(b'\0\x01', 1), 1)
        self.assertEqual(type_.read_pretty(b'\x01'), '(_Bool)1')
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
        self.assertEqual(type_.read_pretty(b'\0\0\0\0'), '(INT)0')

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

        type1 = TypedefType('INT', IntType('int', 4, True))
        type2 = TypedefType('InT', type1)
        self.assertEqual(type1.real_type(), IntType('int', 4, True))
        self.assertEqual(type2.real_type(), IntType('int', 4, True))

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
        self.assertEqual(point_type.read_pretty(b'\0' + buffer, 1), """\
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

        type_ = StructType('foo', 0, [])
        self.assertEqual(type_.members(), [])
        self.assertEqual(type_.read_pretty(b''), '(struct foo){}')

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
        self.assertEqual(type_.read_pretty(buffer), """\
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
        self.assertEqual(type_.read_pretty(buffer), """\
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
        ], 'unsigned int')
        self.assertEqual(str(type_), """\
enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""")
        self.assertEqual(type_.sizeof(), 4)
        buffer = (0).to_bytes(4, sys.byteorder)
        self.assertEqual(type_.read(buffer), type_.enum.RED)
        buffer = (1).to_bytes(4, sys.byteorder)
        self.assertEqual(type_.read(b'\0' + buffer, 1), type_.enum.GREEN)
        self.assertEqual(type_.read_pretty(b'\0' + buffer, 1), '(enum color)GREEN')
        buffer = (4).to_bytes(4, sys.byteorder)
        self.assertEqual(type_.read(b'\0\0\0' + buffer, 3), 4)
        self.assertEqual(type_.read_pretty(b'\0\0\0' + buffer, 3), '(enum color)4')
        self.assertRaises(ValueError, type_.read, buffer, 3)
        self.assertRaises(ValueError, type_.read, b'')

        type_.qualifiers = frozenset({'const'})
        self.assertEqual(str(type_), """\
const enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""")

        type_.qualifiers = frozenset({'const', 'volatile'})
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
        ], 'int')
        self.assertEqual(str(type_), """\
enum {
	RED = 10,
	GREEN = 11,
	BLUE = -1,
}""")
        buffer = (-1).to_bytes(4, sys.byteorder, signed=True)
        self.assertEqual(type_.read(buffer), -1)

        type_ = EnumType('foo', None, None, None, None)
        self.assertEqual(str(type_), 'enum foo')
        self.assertRaises(ValueError, type_.sizeof)

    def test_pointer(self):
        type_ = PointerType(pointer_size, IntType('int', 4, True))
        self.assertEqual(str(type_), 'int *')
        self.assertEqual(type_.sizeof(), pointer_size)
        buffer = (0x7fffffff).to_bytes(pointer_size, sys.byteorder)
        self.assertEqual(type_.read(buffer), 0x7fffffff)
        self.assertEqual(type_.read(b'\0' + buffer, 1), 0x7fffffff)
        self.assertEqual(type_.read_pretty(b'\0' + buffer, 1), '(int *)0x7fffffff')

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
        self.assertEqual(type_.read_pretty(b'\0\0\0' + buffer, 3), """\
(int [2]){
	99,
	-1,
}""")
        buffer = ((99).to_bytes(4, sys.byteorder, signed=True) +
                  (0).to_bytes(4, sys.byteorder, signed=True))
        self.assertEqual(type_.read_pretty(b'\0\0\0' + buffer, 3), """\
(int [2]){
	99,
}""")
        buffer = ((0).to_bytes(4, sys.byteorder, signed=True) +
                  (-1).to_bytes(4, sys.byteorder, signed=True))
        self.assertEqual(type_.read_pretty(b'\0\0\0' + buffer, 3), """\
(int [2]){
	0,
	-1,
}""")
        self.assertRaises(ValueError, type_.read, buffer, 3)
        self.assertRaises(ValueError, type_.read_pretty, buffer, 3)

        type_ = ArrayType(ArrayType(IntType('int', 4, True), 3), 2)
        self.assertEqual(str(type_), 'int [2][3]')

        type_ = ArrayType(ArrayType(ArrayType(IntType('int', 4, True), 4), 3), 2)
        self.assertEqual(str(type_), 'int [2][3][4]')

    def test_array_with_empty_element(self):
        type_ = ArrayType(StructType('empty', 0, []), 2)
        self.assertEqual(str(type_), 'struct empty [2]')
        self.assertEqual(type_.sizeof(), 0)
        self.assertEqual(type_.read(b''), [OrderedDict(), OrderedDict()])
        self.assertEqual(type_.read_pretty(b''), '(struct empty [2]){}')
        self.assertRaises(ValueError, type_.read_pretty, b'', 1)

    def test_incomplete_array(self):
        type_ = ArrayType(IntType('int', 4, True), None)
        self.assertEqual(str(type_), 'int []')
        self.assertRaises(ValueError, type_.sizeof)
        self.assertEqual(type_.read(b''), [])
        self.assertEqual(type_.read_pretty(b''), '(int []){}')

        type_ = ArrayType(ArrayType(IntType('int', 4, True), 2), None)
        self.assertEqual(str(type_), 'int [][2]')

    def test_array_of_structs(self):
        type_ = ArrayType(point_type, 2)
        self.assertEqual(str(type_), 'struct point [2]')
        self.assertEqual(type_.sizeof(), 16)
        buffer = ((1).to_bytes(4, sys.byteorder, signed=True) +
                  (2).to_bytes(4, sys.byteorder, signed=True) +
                  (3).to_bytes(4, sys.byteorder, signed=True) +
                  (4).to_bytes(4, sys.byteorder, signed=True))
        self.assertEqual(type_.read(buffer), [
            OrderedDict([('x', 1), ('y', 2)]),
            OrderedDict([('x', 3), ('y', 4)]),
        ])
        self.assertEqual(type_.read_pretty(buffer), """\
(struct point [2]){
	{
		.x = (int)1,
		.y = (int)2,
	},
	{
		.x = (int)3,
		.y = (int)4,
	},
}""")


class TestTypeUnqualified(TypeTestCase):
    def assertUnqualified(self, type, unqualified_type):
        self.assertEqual(type.unqualified(), unqualified_type)
        self.assertEqual(type.unqualified().unqualified(), unqualified_type)

    def test_void(self):
        self.assertUnqualified(VoidType(frozenset({'const'})), VoidType())

    def test_int(self):
        self.assertUnqualified(IntType('int', 4, True, frozenset({'const'})),
                               IntType('int', 4, True))

    def test_bool(self):
        self.assertUnqualified(BoolType('_Bool', 1, frozenset({'const'})),
                               BoolType('_Bool', 1))

    def test_float(self):
        self.assertUnqualified(FloatType('double', 8, frozenset({'const'})),
                               FloatType('double', 8))

    def test_bit_field(self):
        self.assertUnqualified(BitFieldType(IntType('int', 4, True, frozenset({'const'})), 0, 4),
                               BitFieldType(IntType('int', 4, True), 0, 4))

    def test_struct(self):
        const_point_type = StructType('point', 8, [
            ('x', 0, lambda: IntType('int', 4, True)),
            ('y', 4, lambda: IntType('int', 4, True)),
        ], frozenset({'const'}))
        self.assertUnqualified(const_point_type, point_type)

    def test_union(self):
        union_type = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ])
        const_union_type = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ], frozenset({'const'}))
        self.assertUnqualified(const_union_type, union_type)

    def test_enum(self):
        enum_type = EnumType(None, 4, True, [
            ('RED', 10),
            ('GREEN', 11),
            ('BLUE', -1)
        ], 'int')
        const_enum_type = EnumType(None, 4, True, [
            ('RED', 10),
            ('GREEN', 11),
            ('BLUE', -1)
        ], 'int', frozenset({'const'}))
        self.assertUnqualified(const_enum_type, enum_type)

    def test_typedef(self):
        const_typedef_type = TypedefType(
            'u32', IntType('unsigned int', 4, False), frozenset({'const'}))
        typedef_const_type = TypedefType('u32', IntType('unsigned int', 4, False, frozenset({'const'})))
        const_typedef_const_type = TypedefType(
            'u32', IntType('unsigned int', 4, False, frozenset({'const'})),
            frozenset({'const'}))
        typedef_type = TypedefType('u32', IntType('unsigned int', 4, False))

        self.assertUnqualified(const_typedef_type, typedef_type)
        self.assertUnqualified(typedef_const_type,
                               IntType('unsigned int', 4, False))
        self.assertUnqualified(const_typedef_const_type,
                               IntType('unsigned int', 4, False))

    def test_pointer(self):
        const_pointer_type = PointerType(
            8, IntType('unsigned int', 4, False), frozenset({'const'}))
        pointer_type = PointerType(8, IntType('unsigned int', 4, False))
        self.assertUnqualified(const_pointer_type, pointer_type)

        const_pointer_const_type = PointerType(
            8, IntType('unsigned int', 4, False, frozenset({'const'})),
            frozenset({'const'}))
        pointer_const_type = PointerType(8, IntType('unsigned int', 4, False, frozenset({'const'})))
        self.assertUnqualified(const_pointer_const_type, pointer_const_type)

    def test_array(self):
        type = ArrayType(IntType('int', 4, True), 2)
        self.assertUnqualified(type, type)


class TestConvert(unittest.TestCase):
    def test_void(self):
        self.assertIsNone(VoidType().convert(4))

    def test_int(self):
        type_ = IntType('unsigned int', 4, False)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert('0')
        self.assertEqual(type_.convert(0), 0)
        self.assertEqual(type_.convert(4096), 4096)
        self.assertEqual(type_.convert(999999), 999999)
        self.assertEqual(type_.convert(2**32 - 1), 2**32 - 1)
        self.assertEqual(type_.convert(2**32 + 4), 4)
        self.assertEqual(type_.convert(-1), 2**32 - 1)
        self.assertEqual(type_.convert(-2 * 2**32), 0)
        self.assertEqual(type_.convert(-4 * 2**32 - 1), 2**32 - 1)
        self.assertEqual(type_.convert(-2**31), 2**31)
        self.assertEqual(type_.convert(1.5), 1)

        type_ = IntType('int', 4, True)
        self.assertEqual(type_.convert(0), 0)
        self.assertEqual(type_.convert(4096), 4096)
        self.assertEqual(type_.convert(999999), 999999)
        self.assertEqual(type_.convert(2**32 - 1), -1)
        self.assertEqual(type_.convert(2**32 + 4), 4)
        self.assertEqual(type_.convert(-1), -1)
        self.assertEqual(type_.convert(-2 * 2**32), 0)
        self.assertEqual(type_.convert(-4 * 2**32 - 1), -1)
        self.assertEqual(type_.convert(-2**31), -2**31)
        self.assertEqual(type_.convert(2**31), -2**31)
        self.assertEqual(type_.convert(2**31 - 1), 2**31 - 1)
        self.assertEqual(type_.convert(-1.5), -1)

    def test_bool(self):
        type_ = BoolType('_Bool', 1)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert('')
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert('0')
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert([1, 2, 3])
        self.assertEqual(type_.convert(0), False)
        self.assertEqual(type_.convert(1), True)
        self.assertEqual(type_.convert(-1), True)
        self.assertEqual(type_.convert(0.0), False)
        self.assertEqual(type_.convert(-0.0), False)
        self.assertEqual(type_.convert(-0.0), False)
        self.assertEqual(type_.convert(0.5), True)
        self.assertEqual(type_.convert(-0.5), True)
        self.assertEqual(type_.convert(float('nan')), True)

    def test_float(self):
        type_ = FloatType('double', 8)
        self.assertEqual(type_.convert(0.0), 0.0)
        self.assertEqual(type_.convert(0.5), 0.5)
        self.assertEqual(type_.convert(-0.5), -0.5)
        self.assertEqual(type_.convert(55), 55.0)
        self.assertEqual(type_.convert(float('inf')), float('inf'))
        self.assertEqual(type_.convert(float('-inf')), float('-inf'))
        self.assertTrue(math.isnan(type_.convert(float('nan'))))

        type_ = FloatType('float', 4)
        self.assertEqual(type_.convert(0.0), 0.0)
        self.assertEqual(type_.convert(0.5), 0.5)
        self.assertEqual(type_.convert(-0.5), -0.5)
        self.assertEqual(type_.convert(55), 55.0)
        self.assertEqual(type_.convert(float('inf')), float('inf'))
        self.assertEqual(type_.convert(float('-inf')), float('-inf'))
        self.assertTrue(math.isnan(type_.convert(float('nan'))))
        self.assertEqual(type_.convert(1e-50), 0.0)

    def test_bit_field(self):
        type_ = BitFieldType(IntType('unsigned int', 4, False), 0, 4)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert('0')
        self.assertEqual(type_.convert(0), 0)
        self.assertEqual(type_.convert(10), 10)
        self.assertEqual(type_.convert(15), 15)
        self.assertEqual(type_.convert(20), 4)
        self.assertEqual(type_.convert(-1), 15)
        self.assertEqual(type_.convert(32), 0)
        self.assertEqual(type_.convert(-17), 15)
        self.assertEqual(type_.convert(-8), 8)
        self.assertEqual(type_.convert(1.5), 1)

        type_ = BitFieldType(IntType('int', 4, True), 0, 4)
        self.assertEqual(type_.convert(0), 0)
        self.assertEqual(type_.convert(10), -6)
        self.assertEqual(type_.convert(15), -1)
        self.assertEqual(type_.convert(20), 4)
        self.assertEqual(type_.convert(-1), -1)
        self.assertEqual(type_.convert(32), 0)
        self.assertEqual(type_.convert(-17), -1)
        self.assertEqual(type_.convert(-8), -8)
        self.assertEqual(type_.convert(1.5), 1)

    def test_no_convert(self):
        union_type = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ])
        array_type = ArrayType(IntType('int', 4, True), 2)
        incomplete_array_type = ArrayType(IntType('int', 4, True), None)
        for type_ in [point_type, union_type, array_type,
                      incomplete_array_type]:
            with self.subTest(type=type_):
                with self.assertRaisesRegex(TypeError, 'cannot convert'):
                    point_type.convert(None)
                with self.assertRaisesRegex(TypeError, 'cannot convert'):
                    point_type.convert({})
                with self.assertRaisesRegex(TypeError, 'cannot convert'):
                    point_type.convert(1)

    def test_enum(self):
        type_ = EnumType('color', 4, False, [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ], 'unsigned int')
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert('0')
        self.assertEqual(type_.convert(1), type_.enum.GREEN)
        self.assertEqual(type_.convert(3), 3)
        self.assertEqual(type_.convert(-1), 2**32 - 1)
        self.assertEqual(type_.convert(0.1), type_.enum.RED)

    def test_typedef(self):
        type_ = TypedefType('u32', IntType('unsigned int', 4, False))
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert('0')
        self.assertEqual(type_.convert(0), 0)
        self.assertEqual(type_.convert(2**32 - 1), 2**32 - 1)
        self.assertEqual(type_.convert(-1), 2**32 - 1)

    def test_pointer(self):
        type_ = PointerType(8, VoidType())
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert('0')
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_.convert(0.0)
        self.assertEqual(type_.convert(0), 0)
        self.assertEqual(type_.convert(0xffffffff93000000), 0xffffffff93000000)
        self.assertEqual(type_.convert(2**64 - 1), 2**64 - 1)
        self.assertEqual(type_.convert(-1), 2**64 - 1)
        self.assertEqual(type_.convert(2**64 + 1), 1)
