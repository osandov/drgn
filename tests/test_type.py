from collections import OrderedDict
import ctypes
import math
import struct
import sys
import unittest

from drgn.internal.corereader import CoreReader
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
], {'const'})
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
const_anonymous_color_type = EnumType(None, IntType('int', 4, True), [
    ('RED', 0),
    ('GREEN', -1),
    ('BLUE', -2)
], {'const'})
anonymous_color_type = const_anonymous_color_type.unqualified()


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

        type_ = IntType('int', 4, True, {'const', 'volatile'})
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

        type1 = TypedefType('Color', anonymous_color_type)
        self.assertEqual(str(type1), """\
typedef enum {
	RED = 0,
	GREEN = -1,
	BLUE = -2,
} Color""")

    def test_struct(self):
        self.assertEqual(str(point_type), """\
struct point {
	int x;
	int y;
}""")
        self.assertEqual(point_type.sizeof(), 8)
        self.assertEqual(point_type.member_names(), ['x', 'y'])
        self.assertEqual(list(point_type.members()), [
            ('x', IntType('int', 4, True), 0),
            ('y', IntType('int', 4, True), 4),
        ])
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
        self.assertEqual(type_.member_names(), ['x', 'y', 'z'])
        self.assertEqual(list(type_.members()), [
            ('x', IntType('int', 4, True), 0),
            ('y', IntType('int', 4, True), 4),
            ('z', IntType('int', 4, True), 8),
        ])
        self.assertEqual(type_.offsetof('x'), 0)
        self.assertEqual(type_.offsetof('y'), 4)
        self.assertEqual(type_.offsetof('z'), 8)
        self.assertEqual(type_.typeof('x'), IntType('int', 4, True))
        self.assertEqual(type_.typeof('y'), IntType('int', 4, True))
        self.assertEqual(type_.typeof('z'), IntType('int', 4, True))

        type_ = StructType('foo', 0, [])
        self.assertEqual(type_.member_names(), [])
        self.assertEqual(list(type_.members()), [])

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

        type_ = BitFieldType(color_type, 0, 4)
        self.assertEqual(str(type_), 'enum color : 4')

        type_ = BitFieldType(anonymous_color_type, 0, 4)
        self.assertEqual(str(type_), """\
enum {
	RED = 0,
	GREEN = -1,
	BLUE = -2,
} : 4""")

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
        ], qualifiers={'const'})
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
        ], qualifiers={'const', 'volatile'})
        self.assertEqual(str(type_), """\
const volatile enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""")

        self.assertEqual(str(anonymous_color_type), """\
enum {
	RED = 0,
	GREEN = -1,
	BLUE = -2,
}""")

        type_ = EnumType('foo', None, None)
        self.assertEqual(str(type_), 'enum foo')
        self.assertRaises(ValueError, type_.sizeof)
        self.assertTrue(type_.is_arithmetic())
        self.assertTrue(type_.is_integer())

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

    def test_array_of_anonymous(self):
        type_ = ArrayType(anonymous_point_type, 2, pointer_size)
        self.assertEqual(str(type_), """\
struct {
	int x;
	int y;
} [2]""")

        type_ = ArrayType(anonymous_color_type, 2, pointer_size)
        self.assertEqual(str(type_), """\
enum {
	RED = 0,
	GREEN = -1,
	BLUE = -2,
} [2]""")


class TestConvert(unittest.TestCase):
    def test_void(self):
        self.assertIsNone(VoidType()._convert(4))

    def test_int(self):
        type_ = IntType('unsigned int', 4, False)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert('0')
        self.assertEqual(type_._convert(0), 0)
        self.assertEqual(type_._convert(4096), 4096)
        self.assertEqual(type_._convert(999999), 999999)
        self.assertEqual(type_._convert(2**32 - 1), 2**32 - 1)
        self.assertEqual(type_._convert(2**32 + 4), 4)
        self.assertEqual(type_._convert(-1), 2**32 - 1)
        self.assertEqual(type_._convert(-2 * 2**32), 0)
        self.assertEqual(type_._convert(-4 * 2**32 - 1), 2**32 - 1)
        self.assertEqual(type_._convert(-2**31), 2**31)
        self.assertEqual(type_._convert(1.5), 1)

        type_ = IntType('int', 4, True)
        self.assertEqual(type_._convert(0), 0)
        self.assertEqual(type_._convert(4096), 4096)
        self.assertEqual(type_._convert(999999), 999999)
        self.assertEqual(type_._convert(2**32 - 1), -1)
        self.assertEqual(type_._convert(2**32 + 4), 4)
        self.assertEqual(type_._convert(-1), -1)
        self.assertEqual(type_._convert(-2 * 2**32), 0)
        self.assertEqual(type_._convert(-4 * 2**32 - 1), -1)
        self.assertEqual(type_._convert(-2**31), -2**31)
        self.assertEqual(type_._convert(2**31), -2**31)
        self.assertEqual(type_._convert(2**31 - 1), 2**31 - 1)
        self.assertEqual(type_._convert(-1.5), -1)

    def test_bool(self):
        type_ = BoolType('_Bool', 1)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert('')
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert('0')
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert([1, 2, 3])
        self.assertEqual(type_._convert(0), False)
        self.assertEqual(type_._convert(1), True)
        self.assertEqual(type_._convert(-1), True)
        self.assertEqual(type_._convert(0.0), False)
        self.assertEqual(type_._convert(-0.0), False)
        self.assertEqual(type_._convert(-0.0), False)
        self.assertEqual(type_._convert(0.5), True)
        self.assertEqual(type_._convert(-0.5), True)
        self.assertEqual(type_._convert(float('nan')), True)

    def test_float(self):
        type_ = FloatType('double', 8)
        self.assertEqual(type_._convert(0.0), 0.0)
        self.assertEqual(type_._convert(0.5), 0.5)
        self.assertEqual(type_._convert(-0.5), -0.5)
        self.assertEqual(type_._convert(55), 55.0)
        self.assertEqual(type_._convert(float('inf')), float('inf'))
        self.assertEqual(type_._convert(float('-inf')), float('-inf'))
        self.assertTrue(math.isnan(type_._convert(float('nan'))))

        type_ = FloatType('float', 4)
        self.assertEqual(type_._convert(0.0), 0.0)
        self.assertEqual(type_._convert(0.5), 0.5)
        self.assertEqual(type_._convert(-0.5), -0.5)
        self.assertEqual(type_._convert(55), 55.0)
        self.assertEqual(type_._convert(float('inf')), float('inf'))
        self.assertEqual(type_._convert(float('-inf')), float('-inf'))
        self.assertTrue(math.isnan(type_._convert(float('nan'))))
        self.assertEqual(type_._convert(1e-50), 0.0)

    def test_bit_field(self):
        type_ = BitFieldType(IntType('unsigned int', 4, False), 0, 4)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert('0')
        self.assertEqual(type_._convert(0), 0)
        self.assertEqual(type_._convert(10), 10)
        self.assertEqual(type_._convert(15), 15)
        self.assertEqual(type_._convert(20), 4)
        self.assertEqual(type_._convert(-1), 15)
        self.assertEqual(type_._convert(32), 0)
        self.assertEqual(type_._convert(-17), 15)
        self.assertEqual(type_._convert(-8), 8)
        self.assertEqual(type_._convert(1.5), 1)

        type_ = BitFieldType(IntType('int', 4, True), 0, 4)
        self.assertEqual(type_._convert(0), 0)
        self.assertEqual(type_._convert(10), -6)
        self.assertEqual(type_._convert(15), -1)
        self.assertEqual(type_._convert(20), 4)
        self.assertEqual(type_._convert(-1), -1)
        self.assertEqual(type_._convert(32), 0)
        self.assertEqual(type_._convert(-17), -1)
        self.assertEqual(type_._convert(-8), -8)
        self.assertEqual(type_._convert(1.5), 1)

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
                    point_type._convert(None)
                with self.assertRaisesRegex(TypeError, 'cannot convert'):
                    point_type._convert({})
                with self.assertRaisesRegex(TypeError, 'cannot convert'):
                    point_type._convert(1)

    def test_enum(self):
        type_ = EnumType('color', IntType('unsigned int', 4, False), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert('0')
        self.assertEqual(type_._convert(1), type_.enum.GREEN)
        self.assertEqual(type_._convert(3), 3)
        self.assertEqual(type_._convert(-1), 2**32 - 1)
        self.assertEqual(type_._convert(0.1), type_.enum.RED)

    def test_typedef(self):
        type_ = TypedefType('u32', IntType('unsigned int', 4, False))
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert('0')
        self.assertEqual(type_._convert(0), 0)
        self.assertEqual(type_._convert(2**32 - 1), 2**32 - 1)
        self.assertEqual(type_._convert(-1), 2**32 - 1)

    def test_pointer(self):
        type_ = PointerType(8, VoidType())
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert(None)
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert('0')
        with self.assertRaisesRegex(TypeError, 'cannot convert'):
            type_._convert(0.0)
        self.assertEqual(type_._convert(0), 0)
        self.assertEqual(type_._convert(0xffffffff93000000), 0xffffffff93000000)
        self.assertEqual(type_._convert(2**64 - 1), 2**64 - 1)
        self.assertEqual(type_._convert(-1), 2**64 - 1)
        self.assertEqual(type_._convert(2**64 + 1), 1)


class TestUnqualifiedAndOperandType(TypeTestCase):
    def assertUnqualifiedType(self, type_, expected):
        for i in range(2):
            type_ = type_.unqualified()
            self.assertEqual(type_, expected)

    def assertOperandType(self, type_, expected):
        for i in range(2):
            type_ = type_.operand_type()
            self.assertEqual(type_, expected)

    def assertBoth(self, type_, expected):
        self.assertUnqualifiedType(type_, expected)
        self.assertOperandType(type_, expected)

    def test_void(self):
        self.assertBoth(VoidType({'const'}), VoidType())

    def test_int(self):
        self.assertBoth(IntType('int', 4, True, {'const'}),
                        IntType('int', 4, True))

    def test_bool(self):
        self.assertBoth(BoolType('_Bool', 1, {'const'}),
                        BoolType('_Bool', 1))

    def test_float(self):
        self.assertBoth(FloatType('double', 8, {'const'}),
                        FloatType('double', 8))

    def test_bit_field(self):
        self.assertBoth(BitFieldType(IntType('int', 4, True, {'const'}), 0, 4),
                        BitFieldType(IntType('int', 4, True), 0, 4))

    def test_struct(self):
        const_point_type = StructType('point', 8, [
            ('x', 0, lambda: IntType('int', 4, True)),
            ('y', 4, lambda: IntType('int', 4, True)),
        ], {'const'})
        self.assertBoth(const_point_type, point_type)

    def test_union(self):
        union_type = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ])
        const_union_type = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ], {'const'})
        self.assertBoth(const_union_type, union_type)

    def test_enum(self):
        self.assertBoth(const_anonymous_color_type, anonymous_color_type)

    def test_typedef(self):
        const_typedef_type = TypedefType(
            'u32', IntType('unsigned int', 4, False), {'const'})
        typedef_const_type = TypedefType('u32', IntType('unsigned int', 4, False, {'const'}))
        const_typedef_const_type = TypedefType(
            'u32', IntType('unsigned int', 4, False, {'const'}), {'const'})
        typedef_type = TypedefType('u32', IntType('unsigned int', 4, False))

        self.assertUnqualifiedType(const_typedef_type, typedef_type)
        self.assertOperandType(const_typedef_type, typedef_type)

        self.assertUnqualifiedType(typedef_const_type, typedef_const_type)
        self.assertOperandType(typedef_const_type,
                               IntType('unsigned int', 4, False))

        self.assertUnqualifiedType(const_typedef_const_type, typedef_const_type)
        self.assertOperandType(const_typedef_const_type,
                               IntType('unsigned int', 4, False))

    def test_pointer(self):
        const_pointer_type = PointerType(
            8, IntType('unsigned int', 4, False), {'const'})
        pointer_type = PointerType(8, IntType('unsigned int', 4, False))
        self.assertOperandType(const_pointer_type, pointer_type)

        const_pointer_const_type = PointerType(
            8, IntType('unsigned int', 4, False, {'const'}), {'const'})
        pointer_const_type = PointerType(8, IntType('unsigned int', 4, False, {'const'}))
        self.assertOperandType(const_pointer_const_type, pointer_const_type)

    def test_array(self):
        type_ = ArrayType(IntType('int', 4, True), 2, pointer_size)
        self.assertUnqualifiedType(type_, type_)
        self.assertOperandType(type_, PointerType(pointer_size, type_.type))

        typedef_type = TypedefType('pair_t', type_)
        self.assertUnqualifiedType(typedef_type, typedef_type)
        self.assertOperandType(typedef_type, PointerType(pointer_size, type_.type))

    def test_function(self):
        type_ = FunctionType(pointer_size, VoidType, [])
        self.assertUnqualifiedType(type_, type_)
        self.assertOperandType(type_, PointerType(pointer_size, type_))

        typedef_type = TypedefType('callback_t', type_)
        self.assertUnqualifiedType(typedef_type, typedef_type)
        self.assertOperandType(typedef_type, PointerType(pointer_size, type_))


class TestTypeRead(unittest.TestCase):
    def test_void(self):
        type_ = VoidType()
        with tmpfile(b'') as file:
            reader = CoreReader(file, [])
            self.assertRaises(ValueError, type_._read, reader, 0x0)

    def assertRead(self, type_, buffer, expected_value):
        segments = [(0, 0xffff0000, 0x0, len(buffer), len(buffer))]
        with tmpfile(buffer) as file:
            reader = CoreReader(file, segments)
            self.assertEqual(type_._read(reader, 0xffff0000), expected_value)

    def test_int(self):
        type_ = IntType('int', 4, True)
        self.assertRead(type_, (99).to_bytes(4, sys.byteorder), 99)

        type_ = IntType('int', 4, True, qualifiers={'const'})
        self.assertRead(type_, (99).to_bytes(4, sys.byteorder), 99)

    def test_float(self):
        type_ = FloatType('double', 8)
        self.assertRead(type_, struct.pack('d', 3.14), 3.14)

        type_ = FloatType('float', 4)
        self.assertRead(type_, struct.pack('f', 1.5), 1.5)

    def test_bool(self):
        type_ = BoolType('_Bool', 1)
        self.assertRead(type_, b'\0', False)
        self.assertRead(type_, b'\1', True)

    def test_typedef(self):
        type_ = TypedefType('INT', IntType('int', 4, True))
        self.assertRead(type_, (99).to_bytes(4, sys.byteorder), 99)

    def test_struct(self):
        buffer = ((99).to_bytes(4, sys.byteorder, signed=True) +
                  (-1).to_bytes(4, sys.byteorder, signed=True))
        self.assertRead(point_type, buffer, OrderedDict([('x', 99), ('y', -1)]))

        type_ = StructType('foo', 0, [])
        self.assertRead(type_, b'', OrderedDict())

    def test_bit_field(self):
        type_ = StructType('bits', 8, [
            ('x', 0, lambda: BitFieldType(IntType('int', 4, True), 0, 4)),
            ('y', 0, lambda: BitFieldType(IntType('int', 4, True, {'const'}), 4, 28)),
            ('z', 4, lambda: BitFieldType(IntType('int', 4, True), 0, 5)),
        ])

        buffer = b'\x07\x10\x5e\x5f\x1f\0\0\0'
        self.assertRead(type_.typeof('x'), buffer, 7)
        self.assertRead(type_.typeof('y'), buffer, 100000000)
        self.assertRead(type_.typeof('z'), buffer[4:], -1)
        self.assertRead(type_, buffer,
                        OrderedDict([('x', 7), ('y', 100000000), ('z', -1)]))

    def test_union(self):
        type_ = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ])
        self.assertRead(type_, b'\x00\x00\x80?',
                        OrderedDict([('i', 1065353216), ('f', 1.0)]))

    def test_enum(self):
        self.assertRead(color_type, (0).to_bytes(4, sys.byteorder),
                        color_type.enum.RED)
        self.assertRead(color_type, (1).to_bytes(4, sys.byteorder),
                        color_type.enum.GREEN)
        self.assertRead(color_type, (4).to_bytes(4, sys.byteorder), 4)

    def test_pointer(self):
        type_ = PointerType(8, IntType('int', 4, True))
        self.assertRead(type_, (0x7fffffff).to_bytes(8, sys.byteorder),
                        0x7fffffff)

    def test_array(self):
        type_ = ArrayType(IntType('int', 4, True), 2, 8)

        buffer = ((99).to_bytes(4, sys.byteorder, signed=True) +
                  (-1).to_bytes(4, sys.byteorder, signed=True))
        self.assertRead(type_, buffer, [99, -1])

        buffer = ((99).to_bytes(4, sys.byteorder, signed=True) +
                  (0).to_bytes(4, sys.byteorder, signed=True))
        self.assertRead(type_, buffer, [99, 0])

        buffer = ((0).to_bytes(4, sys.byteorder, signed=True) +
                  (-1).to_bytes(4, sys.byteorder, signed=True))
        self.assertRead(type_, buffer, [0, -1])

        type_ = ArrayType(StructType('empty', 0, []), 2, 8)
        self.assertRead(type_, b'', [OrderedDict(), OrderedDict()])

        type_ = ArrayType(IntType('int', 4, True), None, 8)
        self.assertRead(type_, b'', [])

        type_ = ArrayType(point_type, 2, 8)
        buffer = ((1).to_bytes(4, sys.byteorder, signed=True) +
                  (2).to_bytes(4, sys.byteorder, signed=True) +
                  (3).to_bytes(4, sys.byteorder, signed=True) +
                  (4).to_bytes(4, sys.byteorder, signed=True))
        self.assertRead(type_, buffer, [
            OrderedDict([('x', 1), ('y', 2)]),
            OrderedDict([('x', 3), ('y', 4)]),
        ])


class TestPretty(unittest.TestCase):
    def assertPretty(self, type_, value, expected_pretty_cast,
                     expected_pretty_nocast, columns=0):
        if isinstance(columns, int):
            columns = [columns]
        for c in columns:
            with self.subTest(columns=c):
                self.assertEqual(type_._pretty(value, cast=True, columns=c),
                                 expected_pretty_cast)
                self.assertEqual(type_._pretty(value, cast=False, columns=c),
                                 expected_pretty_nocast)

    def assertPrettyCast(self, type_, value, expected, columns=0):
        if isinstance(columns, int):
            columns = [columns]
        for c in columns:
            with self.subTest(columns=c):
                self.assertEqual(type_._pretty(value, cast=True, columns=c),
                                 expected)

    def assertPrettyNoCast(self, type_, value, expected, columns=0):
        if isinstance(columns, int):
            columns = [columns]
        for c in columns:
            with self.subTest(columns=c):
                self.assertEqual(type_._pretty(value, cast=False, columns=c),
                                 expected)

    def test_int(self):
        type_ = IntType('int', 4, True)
        self.assertPretty(type_, 99, '(int)99', '99')

        type_ = IntType('int', 4, True, qualifiers={'const'})
        self.assertPretty(type_, 99, '(const int)99', '99')

    def test_float(self):
        type_ = FloatType('double', 8)
        self.assertPretty(type_, 3.14, '(double)3.14', '3.14')

        type_ = FloatType('float', 4)
        self.assertPretty(type_, 1.5, '(float)1.5', '1.5')

    def test_bool(self):
        type_ = BoolType('_Bool', 1)
        self.assertPretty(type_, False, '(_Bool)0', '0')
        self.assertPretty(type_, True, '(_Bool)1', '1')

    def test_typedef(self):
        type_ = TypedefType('INT', IntType('int', 4, True))
        self.assertPretty(type_, 99, '(INT)99', '99')

        type_ = TypedefType('CINT', IntType('int', 4, True, qualifiers={'const'}))
        self.assertPretty(type_, 99, '(CINT)99', '99')

        type_ = TypedefType('INT', IntType('int', 4, True), qualifiers={'const'})
        self.assertPretty(type_, 99, '(const INT)99', '99')

    def test_struct(self):
        self.assertPretty(point_type, {'x': 99, 'y': -1}, """\
(struct point){
	.x = (int)99,
	.y = (int)-1,
}""", """\
{
	.x = (int)99,
	.y = (int)-1,
}""")

        type_ = StructType('foo', 0, [])
        self.assertPretty(type_, {},  '(struct foo){}', '{}')

    def test_bit_field(self):
        type_ = StructType('bits', 8, [
            ('x', 0, lambda: BitFieldType(IntType('int', 4, True), 0, 4)),
            ('y', 0, lambda: BitFieldType(IntType('int', 4, True, {'const'}), 4, 28)),
            ('z', 4, lambda: BitFieldType(IntType('int', 4, True), 0, 5)),
        ])

        buffer = b'\x07\x10\x5e\x5f\x1f\0\0\0'
        self.assertPretty(type_.typeof('x'), 7, '(int)7', '7')
        self.assertPretty(type_.typeof('y'), 100000000, '(const int)100000000',
                          '100000000')
        self.assertPretty(type_.typeof('z'), -1, '(int)-1', '-1')
        self.assertPretty(type_, {'x': 7, 'y': 100000000, 'z': -1}, """\
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
        self.assertPretty(type_, {'i': 1065353216, 'f': 1.0}, """\
(union value){
	.i = (int)1065353216,
	.f = (float)1.0,
}""", """\
{
	.i = (int)1065353216,
	.f = (float)1.0,
}""")

    def test_enum(self):
        self.assertPretty(color_type, color_type.enum.RED, '(enum color)RED',
                         'RED')
        self.assertPretty(color_type, 0, '(enum color)RED', 'RED')
        self.assertPretty(color_type, color_type.enum.GREEN,
                         '(enum color)GREEN', 'GREEN')
        self.assertPretty(color_type, 4, '(enum color)4', '4')

    def test_pointer(self):
        type_ = PointerType(8, IntType('int', 4, True))
        self.assertPretty(type_, 0x7fffffff, '(int *)0x7fffffff', '0x7fffffff')

    def test_basic_array(self):
        type_ = ArrayType(IntType('int', 4, True), 5, 8)

        self.assertPrettyNoCast(type_, 5 * [1], "{ 1, 1, 1, 1, 1, }",
                                columns=18)
        self.assertPrettyNoCast(type_, 5 * [1], """\
{
	1, 1, 1,
	1, 1,
}""", columns=range(16, 18))
        self.assertPrettyNoCast(type_, 5 * [1], """\
{
	1, 1,
	1, 1,
	1,
}""", columns=range(13, 16))
        self.assertPrettyNoCast(type_, 5 * [1], """\
{
	1,
	1,
	1,
	1,
	1,
}""", columns=range(13))

        self.assertPrettyCast(type_, 5 * [1], "(int [5]){ 1, 1, 1, 1, 1, }",
                              columns=27)
        self.assertPrettyCast(type_, 5 * [1], """\
(int [5]){
	1, 1, 1, 1, 1,
}""", columns=range(22, 27))
        self.assertPrettyCast(type_, 5 * [1], """\
(int [5]){
	1, 1, 1, 1,
	1,
}""", columns=range(19, 22))
        self.assertPrettyCast(type_, 5 * [1], """\
(int [5]){
	1, 1, 1,
	1, 1,
}""", columns=range(16, 19))
        self.assertPrettyCast(type_, 5 * [1], """\
(int [5]){
	1, 1,
	1, 1,
	1,
}""", columns=range(13, 16))
        self.assertPrettyCast(type_, 5 * [1], """\
(int [5]){
	1,
	1,
	1,
	1,
	1,
}""", columns=range(13))

    def test_nested_array(self):
        type_ = ArrayType(ArrayType(IntType('int', 4, True), 5, 8), 2, 8)

        self.assertPrettyNoCast(type_, [5 * [1], 5 * [2]],
                                "{ { 1, 1, 1, 1, 1, }, { 2, 2, 2, 2, 2, }, }",
                                columns=43)
        self.assertPrettyNoCast(type_, [5 * [1], 5 * [2]], """\
{
	{ 1, 1, 1, 1, 1, },
	{ 2, 2, 2, 2, 2, },
}""", columns=range(27, 43))
        self.assertPrettyNoCast(type_, [5 * [1], 5 * [2]], """\
{
	{
		1, 1, 1,
		1, 1,
	},
	{
		2, 2, 2,
		2, 2,
	},
}""", columns=range(24, 27))
        self.assertPrettyNoCast(type_, [5 * [1], 5 * [2]], """\
{
	{
		1, 1,
		1, 1,
		1,
	},
	{
		2, 2,
		2, 2,
		2,
	},
}""", columns=range(21, 24))
        self.assertPrettyNoCast(type_, [5 * [1], 5 * [2]], """\
{
	{
		1,
		1,
		1,
		1,
		1,
	},
	{
		2,
		2,
		2,
		2,
		2,
	},
}""", columns=range(21))

        self.assertPrettyCast(type_, [5 * [1], 5 * [2]],
                              "(int [2][5]){ { 1, 1, 1, 1, 1, }, { 2, 2, 2, 2, 2, }, }",
                                columns=55)
        self.assertPrettyCast(type_, [5 * [1], 5 * [2]], """\
(int [2][5]){
	{ 1, 1, 1, 1, 1, },
	{ 2, 2, 2, 2, 2, },
}""", columns=range(27, 43))
        self.assertPrettyCast(type_, [5 * [1], 5 * [2]], """\
(int [2][5]){
	{
		1, 1, 1,
		1, 1,
	},
	{
		2, 2, 2,
		2, 2,
	},
}""", columns=range(24, 27))
        self.assertPrettyCast(type_, [5 * [1], 5 * [2]], """\
(int [2][5]){
	{
		1, 1,
		1, 1,
		1,
	},
	{
		2, 2,
		2, 2,
		2,
	},
}""", columns=range(21, 24))
        self.assertPrettyCast(type_, [5 * [1], 5 * [2]], """\
(int [2][5]){
	{
		1,
		1,
		1,
		1,
		1,
	},
	{
		2,
		2,
		2,
		2,
		2,
	},
}""", columns=range(21))

    def test_array_member(self):
        type_ = StructType(None, 20,
                           [('arr', 0, lambda: ArrayType(IntType('int', 4, True), 5, 8))])

        self.assertEqual(type_._pretty({'arr': 5 * [1]}, cast=False, columns=43), """\
{
	.arr = (int [5]){ 1, 1, 1, 1, 1, },
}""")

        self.assertEqual(type_._pretty({'arr': 5 * [1]}, cast=False, columns=42), """\
{
	.arr = (int [5]){
		1, 1, 1, 1, 1,
	},
}""")

        self.assertEqual(type_._pretty({'arr': 5 * [1]}, cast=False, columns=18), """\
{
	.arr = (int [5]){
		1,
		1,
		1,
		1,
		1,
	},
}""")

    def test_array_of_struct(self):
        type_ = ArrayType(point_type, 2, 8)

        self.assertEqual(type_._pretty([{'x': 1, 'y': 2}, {'x': 3, 'y': 4}],
                                        cast=False, columns=20), """\
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

        type_ = ArrayType(StructType('empty', 0, []), 2, 8)
        self.assertPretty(type_, [{}, {}], '(struct empty [2]){}', '{}')

    def test_zero_length_array(self):
        type_ = ArrayType(IntType('int', 4, True), None, 8)
        self.assertPretty(type_, [], '(int []){}', '{}')

        type_ = ArrayType(IntType('int', 4, True), 0, 8)
        self.assertPretty(type_, [], '(int [0]){}', '{}')

    def test_array_zeroes(self):
        type_ = ArrayType(IntType('int', 4, True), 2, 8)

        self.assertPretty(type_, [0, 0], "(int [2]){}", "{}", columns=80)
        self.assertPretty(type_, [99, 0], "(int [2]){ 99, }", "{ 99, }", columns=80)
        self.assertPretty(type_, [0, 99], "(int [2]){ 0, 99, }", "{ 0, 99, }", columns=80)

        type_ = ArrayType(ArrayType(IntType('int', 4, True), 3, 8), 2, 8)
        self.assertPretty(type_, [[1, 0, 0], [0, 0, 0]],
                          "(int [2][3]){ { 1, }, }",
                          "{ { 1, }, }", columns=80)

        type_ = ArrayType(point_type, 2, 8)
        self.assertPretty(type_, [{'x': 1, 'y': 2}, {'x': 0, 'y': 0}], """\
(struct point [2]){
	{
		.x = (int)1,
		.y = (int)2,
	},
}""", """\
{
	{
		.x = (int)1,
		.y = (int)2,
	},
}""")

    def test_char_array(self):
        type_ = ArrayType(IntType('char', 1, True), 4, 8)
        self.assertPretty(type_, list(b'hell'), '(char [4])"hell"', '"hell"')
        self.assertPretty(type_, list(b'hi\0\0'), '(char [4])"hi"', '"hi"')

        type_ = ArrayType(IntType('char', 1, True), 8, 8)
        self.assertPretty(type_, list(b'hello\0wo'), '(char [8])"hello"',
                          '"hello"')

        type_ = ArrayType(IntType('char', 1, True), 0, 8)
        self.assertPretty(type_, [], '(char [0]){}', '{}')
