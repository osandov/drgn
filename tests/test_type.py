from collections import OrderedDict
import ctypes
import math
import struct
import sys
import unittest

from drgn.corereader import CoreReader
from drgn.type import (
    ArrayType,
    BitFieldType,
    BoolType,
    EnumType,
    FloatType,
    FunctionType,
    IntType,
    PointerType,
    StructType,
    Type,
    TypedefType,
    UnionType,
    VoidType,
)
from tests.test_corereader import tmpfile


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


pointer_size = ctypes.sizeof(ctypes.c_void_p)
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
quadrilateral_type = StructType('quadrilateral', 16, [
    ('points', 0, lambda: ArrayType(point_type, 4, pointer_size)),
])
color_type = EnumType('color', IntType('unsigned int', 4, False), [
    ('RED', 0),
    ('GREEN', 1),
    ('BLUE', 2)
])


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
        self.assertFalse(type_.is_arithmetic())
        self.assertFalse(type_.is_integer())

    def test_int(self):
        type_ = IntType('int', 4, True)
        self.assertEqual(str(type_), 'int')
        self.assertEqual(type_.sizeof(), 4)
        self.assertEqual(type_.real_type(), type_)
        self.assertTrue(type_.is_arithmetic())
        self.assertTrue(type_.is_integer())

    def test_float(self):
        type_ = FloatType('double', 8)
        self.assertEqual(str(type_), 'double')
        self.assertEqual(type_.sizeof(), 8)
        self.assertTrue(type_.is_arithmetic())
        self.assertFalse(type_.is_integer())

    def test_bool(self):
        type_ = BoolType('_Bool', 1)
        self.assertEqual(str(type_), '_Bool')
        self.assertEqual(type_.sizeof(), 1)

    def test_qualifiers(self):
        type_ = IntType('int', 4, True, {'const'})
        self.assertEqual(str(type_), 'const int')
        self.assertEqual(type_.sizeof(), 4)

        type_.qualifiers.add('volatile')
        self.assertEqual(str(type_), 'const volatile int')
        self.assertEqual(type_.sizeof(), 4)

    def test_typedef(self):
        type_ = TypedefType('INT', IntType('int', 4, True))
        self.assertEqual(str(type_), 'typedef int INT')
        self.assertEqual(type_.sizeof(), 4)
        self.assertTrue(type_.is_arithmetic())
        self.assertTrue(type_.is_integer())

        type_ = TypedefType('string', PointerType(pointer_size, IntType('char', 1, True)))
        self.assertEqual(str(type_), 'typedef char *string')
        self.assertEqual(type_.sizeof(), pointer_size)
        self.assertFalse(type_.is_arithmetic())
        self.assertFalse(type_.is_integer())

        type_ = TypedefType('CINT', IntType('int', 4, True, {'const'}))
        self.assertEqual(str(type_), 'typedef const int CINT')
        self.assertEqual(type_.sizeof(), 4)

        type_ = TypedefType('INT', IntType('int', 4, True), {'const'})
        self.assertEqual(str(type_), 'const typedef int INT')
        self.assertEqual(type_.sizeof(), 4)

        type1 = TypedefType('INT', IntType('int', 4, True))
        type2 = TypedefType('InT', type1)
        self.assertEqual(type1.real_type(), IntType('int', 4, True))
        self.assertEqual(type2.real_type(), IntType('int', 4, True))

        type1 = TypedefType('Point', anonymous_point_type)
        type2 = TypedefType('POINT', type1)
        self.assertEqual(str(type1), """\
typedef struct {
	int x;
	int y;
} Point""")
        self.assertEqual(str(type2), 'typedef Point POINT')

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

        self.assertEqual(str(line_segment_type), """\
struct line_segment {
	struct point a;
	struct point b;
}""")
        self.assertEqual(line_segment_type.offsetof('a.x'), 0)
        self.assertEqual(line_segment_type.offsetof('a.y'), 4)
        self.assertEqual(line_segment_type.offsetof('b.x'), 8)
        self.assertEqual(line_segment_type.offsetof('b.y'), 12)
        self.assertRaisesRegex(ValueError, 'no member',
                               line_segment_type.offsetof, 'c')
        self.assertRaisesRegex(ValueError, 'not a struct or union',
                               line_segment_type.offsetof, 'a.x.z')
        self.assertRaisesRegex(ValueError, 'not an array',
                               line_segment_type.offsetof, 'a[0]')

        self.assertEqual(str(quadrilateral_type), """\
struct quadrilateral {
	struct point points[4];
}""")
        for i in range(5):
            self.assertEqual(quadrilateral_type.offsetof(f'points[{i}].x'),
                             8 * i)
            self.assertEqual(quadrilateral_type.offsetof(f'points[{i}].y'),
                             8 * i + 4)

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

        type_ = BitFieldType(IntType('int', 4, True), 0, 4)
        self.assertEqual(str(type_), 'int : 4')
        self.assertRaises(ValueError, type_.type_name)
        self.assertTrue(type_.is_arithmetic())

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
        self.assertEqual(str(color_type), """\
enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""")
        self.assertEqual(color_type.sizeof(), 4)

        type_ = EnumType('color', IntType('unsigned int', 4, False), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ], qualifiers=frozenset({'const'}))
        self.assertEqual(str(type_), """\
const enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""")

        type_ = EnumType('color', IntType('unsigned int', 4, False), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ], qualifiers=frozenset({'const', 'volatile'}))
        self.assertEqual(str(type_), """\
const volatile enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""")

        type_ = EnumType(None, IntType('int', 4, True), [
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

        type_ = EnumType('foo', None, None)
        self.assertEqual(str(type_), 'enum foo')
        self.assertRaises(ValueError, type_.sizeof)

    def test_pointer(self):
        type_ = PointerType(pointer_size, IntType('int', 4, True))
        self.assertEqual(str(type_), 'int *')
        self.assertEqual(type_.sizeof(), pointer_size)

        type_ = PointerType(pointer_size, IntType('int', 4, True), {'const'})
        self.assertEqual(str(type_), 'int * const')

        type_ = PointerType(pointer_size, point_type)
        self.assertEqual(str(type_), 'struct point *')

        type_ = PointerType(pointer_size, PointerType(pointer_size, IntType('int', 4, True)))
        self.assertEqual(str(type_), 'int **')

        type_ = PointerType(pointer_size, VoidType())
        self.assertEqual(str(type_), 'void *')

    def test_array(self):
        type_ = ArrayType(IntType('int', 4, True), 2, pointer_size)
        self.assertEqual(str(type_), 'int [2]')
        self.assertEqual(type_.sizeof(), 8)

        type_ = ArrayType(ArrayType(IntType('int', 4, True), 3, pointer_size), 2, pointer_size)
        self.assertEqual(str(type_), 'int [2][3]')

        type_ = ArrayType(ArrayType(ArrayType(IntType('int', 4, True), 4, pointer_size), 3, pointer_size), 2, pointer_size)
        self.assertEqual(str(type_), 'int [2][3][4]')

    def test_array_with_empty_element(self):
        type_ = ArrayType(StructType('empty', 0, []), 2, pointer_size)
        self.assertEqual(str(type_), 'struct empty [2]')
        self.assertEqual(type_.sizeof(), 0)

    def test_incomplete_array(self):
        type_ = ArrayType(IntType('int', 4, True), None, pointer_size)
        self.assertEqual(str(type_), 'int []')
        self.assertRaises(ValueError, type_.sizeof)

        type_ = ArrayType(ArrayType(IntType('int', 4, True), 2, pointer_size), None, pointer_size)
        self.assertEqual(str(type_), 'int [][2]')

    def test_array_of_structs(self):
        type_ = ArrayType(point_type, 2, pointer_size)
        self.assertEqual(str(type_), 'struct point [2]')
        self.assertEqual(type_.sizeof(), 16)


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
        array_type = ArrayType(IntType('int', 4, True), 2, pointer_size)
        incomplete_array_type = ArrayType(IntType('int', 4, True), None, pointer_size)
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
        type_ = EnumType('color', IntType('unsigned int', 4, False), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
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


class TestOperandType(TypeTestCase):
    def assertOperandType(self, type_, expected):
        for i in range(2):
            type_ = type_.operand_type()
            self.assertEqual(type_, expected)

    def test_void(self):
        self.assertOperandType(VoidType(frozenset({'const'})), VoidType())

    def test_int(self):
        self.assertOperandType(IntType('int', 4, True, frozenset({'const'})),
                               IntType('int', 4, True))

    def test_bool(self):
        self.assertOperandType(BoolType('_Bool', 1, frozenset({'const'})),
                               BoolType('_Bool', 1))

    def test_float(self):
        self.assertOperandType(FloatType('double', 8, frozenset({'const'})),
                               FloatType('double', 8))

    def test_bit_field(self):
        self.assertOperandType(BitFieldType(IntType('int', 4, True, frozenset({'const'})), 0, 4),
                               BitFieldType(IntType('int', 4, True), 0, 4))

    def test_struct(self):
        const_point_type = StructType('point', 8, [
            ('x', 0, lambda: IntType('int', 4, True)),
            ('y', 4, lambda: IntType('int', 4, True)),
        ], frozenset({'const'}))
        self.assertOperandType(const_point_type, point_type)

    def test_union(self):
        union_type = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ])
        const_union_type = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ], frozenset({'const'}))
        self.assertOperandType(const_union_type, union_type)

    def test_enum(self):
        enum_type = EnumType(None, IntType('int', 4, True), [
            ('RED', 10),
            ('GREEN', 11),
            ('BLUE', -1)
        ])
        const_enum_type = EnumType(None, IntType('int', 4, True), [
            ('RED', 10),
            ('GREEN', 11),
            ('BLUE', -1)
        ], frozenset({'const'}))
        self.assertOperandType(const_enum_type, enum_type)

    def test_typedef(self):
        const_typedef_type = TypedefType(
            'u32', IntType('unsigned int', 4, False), frozenset({'const'}))
        typedef_const_type = TypedefType('u32', IntType('unsigned int', 4, False, frozenset({'const'})))
        const_typedef_const_type = TypedefType(
            'u32', IntType('unsigned int', 4, False, frozenset({'const'})),
            frozenset({'const'}))
        typedef_type = TypedefType('u32', IntType('unsigned int', 4, False))

        self.assertOperandType(const_typedef_type, typedef_type)
        self.assertOperandType(typedef_const_type,
                               IntType('unsigned int', 4, False))
        self.assertOperandType(const_typedef_const_type,
                               IntType('unsigned int', 4, False))

    def test_pointer(self):
        const_pointer_type = PointerType(
            8, IntType('unsigned int', 4, False), frozenset({'const'}))
        pointer_type = PointerType(8, IntType('unsigned int', 4, False))
        self.assertOperandType(const_pointer_type, pointer_type)

        const_pointer_const_type = PointerType(
            8, IntType('unsigned int', 4, False, frozenset({'const'})),
            frozenset({'const'}))
        pointer_const_type = PointerType(8, IntType('unsigned int', 4, False, frozenset({'const'})))
        self.assertOperandType(const_pointer_const_type, pointer_const_type)

    def test_array(self):
        type_ = ArrayType(IntType('int', 4, True), 2, pointer_size)
        self.assertOperandType(type_, PointerType(pointer_size, type_.type))

        typedef_type = TypedefType('pair_t', type_)
        self.assertOperandType(typedef_type, PointerType(pointer_size, type_.type))

    def test_function(self):
        type_ = FunctionType(pointer_size, VoidType, [])
        self.assertOperandType(type_, PointerType(pointer_size, type_))

        typedef_type = TypedefType('callback_t', type_)
        self.assertOperandType(typedef_type, PointerType(pointer_size, type_))


class TestTypeRead(unittest.TestCase):
    def test_void(self):
        type_ = VoidType()
        with tmpfile(b'') as file:
            reader = CoreReader(file, [])
            self.assertRaises(ValueError, type_.read, reader, 0x0)
            self.assertRaises(ValueError, type_.read_pretty, reader, 0x0)

    def assertReads(self, type_, buffer, expected_value,
                    expected_pretty_cast, expected_pretty_nocast):
        segments = [(0, 0xffff0000, 0x0, len(buffer), len(buffer))]
        with tmpfile(buffer) as file:
            reader = CoreReader(file, segments)
            self.assertEqual(type_.read(reader, 0xffff0000), expected_value)
            self.assertEqual(type_.read_pretty(reader, 0xffff0000),
                             expected_pretty_cast)
            self.assertEqual(type_.read_pretty(reader, 0xffff0000, cast=False),
                             expected_pretty_nocast)

    def test_int(self):
        type_ = IntType('int', 4, True)
        self.assertReads(type_, (99).to_bytes(4, sys.byteorder), 99, '(int)99',
                         '99')

        type_ = IntType('int', 4, True, qualifiers=frozenset({'const'}))
        self.assertReads(type_, (99).to_bytes(4, sys.byteorder), 99,
                         '(const int)99', '99')

    def test_float(self):
        type_ = FloatType('double', 8)
        self.assertReads(type_, struct.pack('d', 3.14), 3.14, '(double)3.14',
                         '3.14')

        type_ = FloatType('float', 4)
        self.assertReads(type_, struct.pack('f', 1.5), 1.5, '(float)1.5',
                         '1.5')

    def test_bool(self):
        type_ = BoolType('_Bool', 1)
        self.assertReads(type_, b'\0', False, '(_Bool)0', '0')
        self.assertReads(type_, b'\1', True, '(_Bool)1', '1')

    def test_typedef(self):
        type_ = TypedefType('INT', IntType('int', 4, True))
        self.assertReads(type_, (99).to_bytes(4, sys.byteorder), 99, '(INT)99',
                         '99')

        type_ = TypedefType('CINT', IntType('int', 4, True, qualifiers=frozenset({'const'})))
        self.assertReads(type_, (99).to_bytes(4, sys.byteorder), 99,
                         '(CINT)99', '99')

        type_ = TypedefType('INT', IntType('int', 4, True), qualifiers=frozenset({'const'}))
        self.assertReads(type_, (99).to_bytes(4, sys.byteorder), 99,
                         '(const INT)99', '99')

    def test_struct(self):
        buffer = ((99).to_bytes(4, sys.byteorder, signed=True) +
                  (-1).to_bytes(4, sys.byteorder, signed=True))
        self.assertReads(point_type, buffer, OrderedDict([
            ('x', 99),
            ('y', -1),
        ]), """\
(struct point){
	.x = (int)99,
	.y = (int)-1,
}""", """\
{
	.x = (int)99,
	.y = (int)-1,
}""")

        type_ = StructType('foo', 0, [])
        self.assertReads(type_, b'', OrderedDict(),  '(struct foo){}', '{}')

    def test_bit_field(self):
        type_ = StructType('bits', 8, [
            ('x', 0, lambda: BitFieldType(IntType('int', 4, True), 0, 4)),
            ('y', 0, lambda: BitFieldType(IntType('int', 4, True, {'const'}), 4, 28)),
            ('z', 4, lambda: BitFieldType(IntType('int', 4, True), 0, 5)),
        ])

        buffer = b'\x07\x10\x5e\x5f\x1f\0\0\0'
        self.assertReads(type_.typeof('x'), buffer, 7, '(int)7', '7')
        self.assertReads(type_.typeof('y'), buffer, 100000000,
                         '(const int)100000000', '100000000')
        self.assertReads(type_.typeof('z'), buffer[4:], -1, '(int)-1', '-1')
        self.assertReads(type_, buffer, OrderedDict([
            ('x', 7),
            ('y', 100000000),
            ('z', -1),
        ]), """\
(struct bits){
	.x = (int)7,
	.y = (const int)100000000,
	.z = (int)-1,
}""", """\
{
	.x = (int)7,
	.y = (const int)100000000,
	.z = (int)-1,
}""")

    def test_union(self):
        type_ = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ])
        self.assertReads(type_, b'\x00\x00\x80?', OrderedDict([
            ('i', 1065353216),
            ('f', 1.0),
        ]), """\
(union value){
	.i = (int)1065353216,
	.f = (float)1.0,
}""", """\
{
	.i = (int)1065353216,
	.f = (float)1.0,
}""")

    def test_enum(self):
        buffer = (0).to_bytes(4, sys.byteorder)
        self.assertReads(color_type, buffer, color_type.enum.RED,
                         '(enum color)RED', 'RED')
        buffer = (1).to_bytes(4, sys.byteorder)
        self.assertReads(color_type, buffer, color_type.enum.GREEN,
                         '(enum color)GREEN', 'GREEN')
        buffer = (4).to_bytes(4, sys.byteorder)
        self.assertReads(color_type, buffer, 4, '(enum color)4', '4')

    def test_pointer(self):
        type_ = PointerType(pointer_size, IntType('int', 4, True))
        buffer = (0x7fffffff).to_bytes(pointer_size, sys.byteorder)
        self.assertReads(type_, buffer, 0x7fffffff, '(int *)0x7fffffff',
                         '0x7fffffff')

    def test_array(self):
        type_ = ArrayType(IntType('int', 4, True), 2, pointer_size)

        buffer = ((99).to_bytes(4, sys.byteorder, signed=True) +
                  (-1).to_bytes(4, sys.byteorder, signed=True))
        self.assertReads(type_, buffer, [99, -1], """\
(int [2]){
	99,
	-1,
}""", """\
{
	99,
	-1,
}""")

        buffer = ((99).to_bytes(4, sys.byteorder, signed=True) +
                  (0).to_bytes(4, sys.byteorder, signed=True))
        self.assertReads(type_, buffer, [99, 0], """\
(int [2]){
	99,
}""", """\
{
	99,
}""")

        buffer = ((0).to_bytes(4, sys.byteorder, signed=True) +
                  (-1).to_bytes(4, sys.byteorder, signed=True))
        self.assertReads(type_, buffer, [0, -1], """\
(int [2]){
	0,
	-1,
}""", """\
{
	0,
	-1,
}""")

        type_ = ArrayType(StructType('empty', 0, []), 2, pointer_size)
        self.assertReads(type_, b'', [OrderedDict(), OrderedDict()],
                         '(struct empty [2]){}', '{}')

        type_ = ArrayType(IntType('int', 4, True), None, pointer_size)
        self.assertReads(type_, b'', [],  '(int []){}', '{}')

        type_ = ArrayType(point_type, 2, pointer_size)
        buffer = ((1).to_bytes(4, sys.byteorder, signed=True) +
                  (2).to_bytes(4, sys.byteorder, signed=True) +
                  (3).to_bytes(4, sys.byteorder, signed=True) +
                  (4).to_bytes(4, sys.byteorder, signed=True))
        self.assertReads(type_, buffer, [
            OrderedDict([('x', 1), ('y', 2)]),
            OrderedDict([('x', 3), ('y', 4)]),
        ], """\
(struct point [2]){
	{
		.x = (int)1,
		.y = (int)2,
	},
	{
		.x = (int)3,
		.y = (int)4,
	},
}""", """\
{
	{
		.x = (int)1,
		.y = (int)2,
	},
	{
		.x = (int)3,
		.y = (int)4,
	},
}""")

    def test_char_array(self):
        type_ = ArrayType(IntType('char', 1, True), 4, pointer_size)
        self.assertReads(type_, b'hello\0', list(b'hell'), '(char [4])"hell"',
                         '"hell"')
        self.assertReads(type_, b'hi\0\0', list(b'hi\0\0'), '(char [4])"hi"',
                         '"hi"')

        type_ = ArrayType(IntType('char', 1, True), 8, pointer_size)
        self.assertReads(type_, b'hello\0world\0', list(b'hello\0wo'),
                         '(char [8])"hello"', '"hello"')

        type_ = ArrayType(IntType('char', 1, True), 0, pointer_size)
        self.assertReads(type_, b'hi\0', [], '(char [0]){}', '{}')
