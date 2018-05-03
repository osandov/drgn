import os.path
import subprocess
import tempfile
import unittest

from drgn.dwarf import DW_TAG
from drgn.dwarfindex import DwarfIndex
from drgn.typeindex import DwarfTypeIndex, TypeIndex
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
from tests.test_type import (
    anonymous_point_type,
    const_anonymous_point_type,
    line_segment_type,
    pointer_size,
    point_type,
    TypeTestCase,
)


BASE_TYPES = {
    '_Bool': BoolType('_Bool', 1),
    'char': IntType('char', 1, True),
    'signed char': IntType('signed char', 1, True),
    'unsigned char': IntType('unsigned char', 1, False),
    'short': IntType('short', 2, True),
    'unsigned short': IntType('unsigned short', 2, False),
    'int': IntType('int', 4, True),
    'unsigned int': IntType('unsigned int', 4, False),
    'long': IntType('long', 8, True),
    'unsigned long': IntType('unsigned long', 8, False),
    'long long': IntType('long long', 8, True),
    'unsigned long long': IntType('unsigned long long', 8, False),
    'float': FloatType('float', 4),
    'double': FloatType('double', 8),
    'long double': FloatType('long double', 16),
}


class TestTypeIndex(TypeTestCase):
    def setUp(self):
        super().setUp()
        self.type_index = TypeIndex()
        self.type_index.find_type = BASE_TYPES.get

    def assertPromotes(self, type, expected_type):
        self.assertEqual(self.type_index.integer_promotions(type),
                         expected_type)

    def assertConverts(self, type1, type2, expected_type):
        self.assertEqual(self.type_index.usual_arithmetic_conversions(type1, type2),
                         expected_type)
        self.assertEqual(self.type_index.usual_arithmetic_conversions(type2, type1),
                         expected_type)

    def test_literal_bool(self):
        self.assertEqual(self.type_index.literal_type(True),
                         BASE_TYPES['_Bool'])
        self.assertEqual(self.type_index.literal_type(False),
                         BASE_TYPES['_Bool'])

    def test_literal_int(self):
        self.assertEqual(self.type_index.literal_type(0), BASE_TYPES['int'])
        self.assertEqual(self.type_index.literal_type(-2**31),
                         BASE_TYPES['int'])
        self.assertEqual(self.type_index.literal_type(2**31 - 1),
                         BASE_TYPES['int'])

        self.assertEqual(self.type_index.literal_type(2**31),
                         BASE_TYPES['unsigned int'])
        self.assertEqual(self.type_index.literal_type(2**32 - 1),
                         BASE_TYPES['unsigned int'])

        self.assertEqual(self.type_index.literal_type(-2**31 - 1),
                         BASE_TYPES['long'])
        self.assertEqual(self.type_index.literal_type(-2**63),
                         BASE_TYPES['long'])
        self.assertEqual(self.type_index.literal_type(2**32),
                         BASE_TYPES['long'])
        self.assertEqual(self.type_index.literal_type(2**63 - 1),
                         BASE_TYPES['long'])

        self.assertEqual(self.type_index.literal_type(2**63),
                         BASE_TYPES['unsigned long'])
        self.assertEqual(self.type_index.literal_type(2**64 - 1),
                         BASE_TYPES['unsigned long'])

    def test_literal_float(self):
        self.assertEqual(self.type_index.literal_type(0.0),
                         BASE_TYPES['double'])
        self.assertEqual(self.type_index.literal_type(float('inf')),
                         BASE_TYPES['double'])
        self.assertEqual(self.type_index.literal_type(float('nan')),
                         BASE_TYPES['double'])

    def test_literal_error(self):
        self.assertRaises(TypeError, self.type_index.literal_type, None)
        self.assertRaises(TypeError, self.type_index.literal_type, 2**128)

    def test_char_promotions(self):
        self.assertPromotes(BASE_TYPES['char'], BASE_TYPES['int'])
        self.assertPromotes(BASE_TYPES['signed char'], BASE_TYPES['int'])
        self.assertPromotes(BASE_TYPES['unsigned char'], BASE_TYPES['int'])

    def test_short_promotions(self):
        self.assertPromotes(BASE_TYPES['short'], BASE_TYPES['int'])
        self.assertPromotes(BASE_TYPES['unsigned short'], BASE_TYPES['int'])

    def test_bool_promotions(self):
        self.assertPromotes(BASE_TYPES['_Bool'], BASE_TYPES['int'])

    def test_enum_promotions(self):
        type_ = EnumType('color', 4, True, [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ], 'int')
        self.assertPromotes(type_, BASE_TYPES['int'])

        type_ = EnumType('color', 4, False, [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ], 'unsigned int')
        self.assertPromotes(type_, BASE_TYPES['unsigned int'])

        type_ = EnumType('color', 8, False, [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ], 'unsigned long')
        self.assertPromotes(type_, BASE_TYPES['unsigned long'])

    def test_int_promotions(self):
        self.assertPromotes(BASE_TYPES['int'], BASE_TYPES['int'])
        self.assertPromotes(BASE_TYPES['unsigned int'],
                            BASE_TYPES['unsigned int'])

    def test_long_promotions(self):
        self.assertPromotes(BASE_TYPES['long'], BASE_TYPES['long'])
        self.assertPromotes(BASE_TYPES['unsigned long'],
                            BASE_TYPES['unsigned long'])

    def test_long_long_promotions(self):
        self.assertPromotes(BASE_TYPES['long long'], BASE_TYPES['long long'])
        self.assertPromotes(BASE_TYPES['unsigned long long'],
                            BASE_TYPES['unsigned long long'])

    def test_bit_field_promotions(self):
        self.assertPromotes(BitFieldType(BASE_TYPES['int'], 0, 4),
                            BASE_TYPES['int'])
        self.assertPromotes(BitFieldType(BASE_TYPES['long'], 0, 4),
                            BASE_TYPES['int'])

        self.assertPromotes(BitFieldType(BASE_TYPES['int'], 0, 32),
                            BASE_TYPES['int'])
        self.assertPromotes(BitFieldType(BASE_TYPES['long'], 0, 32),
                            BASE_TYPES['int'])

        self.assertPromotes(BitFieldType(BASE_TYPES['unsigned int'], 0, 4),
                            BASE_TYPES['int'])
        self.assertPromotes(BitFieldType(BASE_TYPES['unsigned long'], 0, 4),
                            BASE_TYPES['int'])

        self.assertPromotes(BitFieldType(BASE_TYPES['unsigned int'], 0, 32),
                            BASE_TYPES['unsigned int'])
        self.assertPromotes(BitFieldType(BASE_TYPES['unsigned long'], 0, 32),
                            BASE_TYPES['unsigned int'])

        self.assertPromotes(BitFieldType(BASE_TYPES['long'], 0, 40),
                            BitFieldType(BASE_TYPES['long'], None, 40))
        self.assertPromotes(BitFieldType(BASE_TYPES['unsigned long'], 0, 40),
                            BitFieldType(BASE_TYPES['unsigned long'], None, 40))

    def test_typedef_promotions(self):
        type_ = TypedefType('SHORT', BASE_TYPES['short'])
        self.assertPromotes(type_, BASE_TYPES['int'])

        type_ = TypedefType('INT', BASE_TYPES['int'])
        self.assertPromotes(type_, type_)

        type_ = TypedefType('LONG', BASE_TYPES['long'])
        self.assertPromotes(type_, type_)

    def test_other_promotions(self):
        self.assertPromotes(BASE_TYPES['double'], BASE_TYPES['double'])
        self.assertPromotes(BASE_TYPES['long double'],
                            BASE_TYPES['long double'])

    def test_long_double_conversions(self):
        self.assertConverts(BASE_TYPES['long double'], BASE_TYPES['double'],
                            BASE_TYPES['long double'])
        self.assertConverts(BASE_TYPES['int'], BASE_TYPES['long double'],
                            BASE_TYPES['long double'])

    def test_double_conversions(self):
        self.assertConverts(BASE_TYPES['double'], BASE_TYPES['float'],
                            BASE_TYPES['double'])
        self.assertConverts(BASE_TYPES['long'], BASE_TYPES['double'],
                            BASE_TYPES['double'])

    def test_float_conversions(self):
        self.assertConverts(BASE_TYPES['int'], BASE_TYPES['float'],
                            BASE_TYPES['float'])
        self.assertConverts(BASE_TYPES['float'], BASE_TYPES['long long'],
                            BASE_TYPES['float'])

    def test_same_conversions(self):
        self.assertConverts(BASE_TYPES['int'], BASE_TYPES['int'],
                            BASE_TYPES['int'])

    def test_same_sign_conversions(self):
        self.assertConverts(BASE_TYPES['long'], BASE_TYPES['long long'],
                            BASE_TYPES['long long'])

        self.assertConverts(IntType('unsigned long', 4, False),
                            BASE_TYPES['unsigned int'],
                            IntType('unsigned long', 4, False))

    def test_unsigned_rank_conversions(self):
        self.assertConverts(BASE_TYPES['long'],
                            BASE_TYPES['unsigned long long'],
                            BASE_TYPES['unsigned long long'])
        self.assertConverts(BASE_TYPES['unsigned int'], BASE_TYPES['int'],
                            BASE_TYPES['unsigned int'])

    def test_signed_range_conversions(self):
        self.assertConverts(BASE_TYPES['long'], BASE_TYPES['unsigned int'],
                            BASE_TYPES['long'])
        self.assertConverts(IntType('unsigned long', 4, False),
                            BASE_TYPES['long long'],
                            BASE_TYPES['long long'])

    def test_corresponding_unsigned_conversions(self):
        self.assertConverts(IntType('long', 4, True),
                            BASE_TYPES['unsigned int'],
                            IntType('unsigned long', 4, False))
        self.assertConverts(BASE_TYPES['long long'],
                            BASE_TYPES['unsigned long'],
                            BASE_TYPES['unsigned long long'])

    def test_qualified_conversions(self):
        self.assertConverts(IntType('int', 4, True, frozenset({'const'})),
                            IntType('int', 4, True, frozenset({'const'})),
                            BASE_TYPES['int'])

    def test_typedef_conversions(self):
        typedef_type = TypedefType('u32', BASE_TYPES['unsigned int'])
        self.assertConverts(typedef_type, typedef_type, typedef_type)

        const_typedef_type = TypedefType(
            'u32', BASE_TYPES['unsigned int'], frozenset({'const'}))
        self.assertConverts(const_typedef_type, const_typedef_type, typedef_type)

        const_typedef_const_type = TypedefType(
            'u32', IntType('unsigned int', 4, False, frozenset({'const'})),
            frozenset({'const'}))

        self.assertConverts(const_typedef_const_type, const_typedef_const_type,
                            BASE_TYPES['unsigned int'])

    def test_bool_conversions(self):
        self.assertConverts(BoolType('_Bool', 1), BASE_TYPES['int'],
                            BASE_TYPES['int'])

    def test_bit_field_conversions(self):
        self.assertConverts(BitFieldType(BASE_TYPES['int'], None, 4),
                            BitFieldType(BASE_TYPES['int'], None, 4),
                            BASE_TYPES['int'])

        self.assertConverts(BitFieldType(BASE_TYPES['long'], None, 4),
                            BitFieldType(BASE_TYPES['long'], None, 4),
                            BASE_TYPES['int'])

        self.assertConverts(BitFieldType(BASE_TYPES['long'], None, 40),
                            BitFieldType(BASE_TYPES['long'], None, 40),
                            BitFieldType(BASE_TYPES['long'], None, 40))

        self.assertConverts(BitFieldType(BASE_TYPES['long'], None, 40),
                            BitFieldType(BASE_TYPES['long'], None, 33),
                            BitFieldType(BASE_TYPES['long'], None, 40))

        self.assertConverts(BitFieldType(BASE_TYPES['long'], None, 40),
                            BitFieldType(BASE_TYPES['long long'], None, 33),
                            BitFieldType(BASE_TYPES['long'], None, 40))

        self.assertConverts(BitFieldType(BASE_TYPES['long'], None, 40),
                            BitFieldType(BASE_TYPES['long long'], None, 40),
                            BitFieldType(BASE_TYPES['long long'], None, 40))

        self.assertConverts(BitFieldType(BASE_TYPES['long'], None, 40),
                            BitFieldType(BASE_TYPES['unsigned long'], None, 33),
                            BitFieldType(BASE_TYPES['long'], None, 40))

        self.assertConverts(BitFieldType(BASE_TYPES['long'], None, 40),
                            BitFieldType(BASE_TYPES['unsigned long'], None, 40),
                            BitFieldType(BASE_TYPES['unsigned long'], None, 40))

        self.assertConverts(BitFieldType(BASE_TYPES['long'], None, 40),
                            BASE_TYPES['int'],
                            BitFieldType(BASE_TYPES['long'], None, 40))

        self.assertConverts(BitFieldType(BASE_TYPES['long'], None, 40),
                            BASE_TYPES['long'],
                            BASE_TYPES['long'])

    def test_enum_conversions(self):
        type_ = EnumType('color', 4, True, [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ], 'int')
        self.assertConverts(type_, BASE_TYPES['int'],
                            BASE_TYPES['int'])

        type_ = TypedefType('COLOR', type_)
        self.assertConverts(type_, BASE_TYPES['int'],
                            BASE_TYPES['int'])


class TestDwarfTypeIndexFindDwarfType(TypeTestCase):
    def setUp(self):
        super().setUp()
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp_dir.cleanup()
        super().tearDown()

    def compile_type(self, decl):
        object_path = os.path.join(self.tmp_dir.name, 'test')
        source_path = object_path + '.c'
        with open(source_path, 'w') as f:
            f.write(decl)
            f.write(';\nint main(void) { return 0; }\n')
        subprocess.check_call(['gcc', '-g', '-gz=none', '-c', '-o', object_path, source_path])
        dwarf_index = DwarfIndex([object_path])
        dwarf_type = dwarf_index.find('x', DW_TAG.variable).type()
        return DwarfTypeIndex(dwarf_index).find_dwarf_type(dwarf_type)

    def test_char(self):
        self.assertEqual(self.compile_type('char x'),
                        IntType('char', 1, True))
        self.assertEqual(self.compile_type('signed char x'),
                        IntType('signed char', 1, True))
        self.assertEqual(self.compile_type('unsigned char x'),
                        IntType('unsigned char', 1, False))

    def test_short(self):
        self.assertEqual(self.compile_type('short x'),
                        IntType('short', 2, True))
        self.assertEqual(self.compile_type('signed short x'),
                        IntType('short', 2, True))
        self.assertEqual(self.compile_type('unsigned short x'),
                        IntType('unsigned short', 2, False))

    def test_int(self):
        self.assertEqual(self.compile_type('int x'),
                        IntType('int', 4, True))
        self.assertEqual(self.compile_type('signed int x'),
                        IntType('int', 4, True))
        self.assertEqual(self.compile_type('unsigned int x'),
                        IntType('unsigned int', 4, False))

    def test_long(self):
        self.assertEqual(self.compile_type('long x'), IntType('long', 8, True))
        self.assertEqual(self.compile_type('signed long x'),
                        IntType('long', 8, True))
        self.assertEqual(self.compile_type('unsigned long x'),
                         IntType('unsigned long', 8, False))

    def test_long_long(self):
        self.assertEqual(self.compile_type('long long x'),
                         IntType('long long', 8, True))
        self.assertEqual(self.compile_type('signed long long x'),
                         IntType('long long', 8, True))
        self.assertEqual(self.compile_type('unsigned long long x'),
                         IntType('unsigned long long', 8, False))

    def test_float(self):
        self.assertEqual(self.compile_type('float x'),
                         FloatType('float', 4))
        self.assertEqual(self.compile_type('double x'),
                         FloatType('double', 8))
        self.assertEqual(self.compile_type('long double x'),
                         FloatType('long double', 16))
        self.assertEqual(self.compile_type('double long x'),
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
} x;"""), EnumType('color', 4, False, [('RED', 0), ('GREEN', 1), ('BLUE', 2)], 'unsigned int'))

        self.assertEqual(self.compile_type("""\
enum {
	RED = 10,
	GREEN,
	BLUE = -1,
} x;"""), EnumType(None, 4, True, [('RED', 10), ('GREEN', 11), ('BLUE', -1)], 'int'))

    def test_incomplete_enum(self):
        self.assertEqual(self.compile_type('enum foo; extern enum foo x'),
                         EnumType('foo', None, None, None, None))

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

    def test_pointer_to_function(self):
        self.assertEqual(self.compile_type('int (*x)(int)'),
                         PointerType(pointer_size, FunctionType(IntType('int', 4, True), [(IntType('int', 4, True), None)])))

    def test_pointer_to_variadic_function(self):
        self.assertEqual(self.compile_type('int (*x)(int, ...)'),
                         PointerType(pointer_size, FunctionType(IntType('int', 4, True), [(IntType('int', 4, True), None)], variadic=True)))

    def test_pointer_to_function_with_no_parameter_specification(self):
        self.assertEqual(self.compile_type('int (*x)()'),
                         PointerType(pointer_size, FunctionType(IntType('int', 4, True), None)))

    def test_pointer_to_function_with_no_parameters(self):
        self.assertEqual(self.compile_type('int (*x)(void)'),
                         PointerType(pointer_size, FunctionType(IntType('int', 4, True), [])))


class TestDwarfTypeIndexFindType(TypeTestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmp_dir:
            object_path = os.path.join(tmp_dir, 'test')
            source_path = object_path + '.c'
            with open(source_path, 'w') as f:
                f.write("""\
char c;
signed char sc;
unsigned char uc;
int i;
unsigned long long ull;

struct point {
	int x, y;
} p;

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
            cls.type_index = DwarfTypeIndex(DwarfIndex([object_path]))

    def test_void_type(self):
        self.assertEqual(self.type_index.find_type('void'),
                         VoidType())
        self.assertEqual(self.type_index.find_type('const void'),
                         VoidType(frozenset({'const'})))

    def test_base_type(self):
        self.assertEqual(self.type_index.find_type('int'),
                         IntType('int', 4, True))
        self.assertEqual(self.type_index.find_type('signed int'),
                         IntType('int', 4, True))
        self.assertEqual(self.type_index.find_type('int signed'),
                         IntType('int', 4, True))
        self.assertEqual(self.type_index.find_type('volatile int'),
                         IntType('int', 4, True, frozenset({'volatile'})))

        self.assertEqual(self.type_index.find_type('char'),
                         IntType('char', 1, True))
        self.assertEqual(self.type_index.find_type('signed char'),
                         IntType('signed char', 1, True))
        self.assertEqual(self.type_index.find_type('char signed'),
                         IntType('signed char', 1, True))
        self.assertEqual(self.type_index.find_type('unsigned char'),
                         IntType('unsigned char', 1, False))
        self.assertEqual(self.type_index.find_type('char unsigned'),
                         IntType('unsigned char', 1, False))

        self.assertEqual(self.type_index.find_type('unsigned long long'),
                         IntType('unsigned long long', 8, False))
        self.assertEqual(self.type_index.find_type('long long unsigned int'),
                         IntType('unsigned long long', 8, False))
        self.assertEqual(self.type_index.find_type('long long int unsigned'),
                         IntType('unsigned long long', 8, False))


    def test_struct_type(self):
        self.assertEqual(self.type_index.find_type('struct point'),
                         point_type)

    def test_union_type(self):
        self.assertEqual(self.type_index.find_type('union value'),
                         UnionType('value', 4, [
                             ('i', 0, lambda: IntType('int', 4, True)),
                             ('f', 0, lambda: FloatType('float', 4)),
                         ]))

    def test_enum_type(self):
        self.assertEqual(self.type_index.find_type('enum color'),
                         EnumType('color', 4, False, [
                             ('RED', 0),
                             ('GREEN', 1),
                             ('BLUE', 2)
                         ], 'unsigned int'))

    def test_typedef_type(self):
        self.assertEqual(self.type_index.find_type('point'),
                         TypedefType('point', point_type))
        self.assertEqual(self.type_index.find_type('const point'),
                         TypedefType('point', point_type, frozenset({'const'})))

    def test_pointer_type(self):
        self.assertEqual(self.type_index.find_type('int *'),
                         PointerType(pointer_size, IntType('int', 4, True)))
        self.assertEqual(self.type_index.find_type('int * const'),
                         PointerType(pointer_size, IntType('int', 4, True), frozenset({'const'})))

    def test_array_type(self):
        self.assertEqual(self.type_index.find_type('int [4]'),
                         ArrayType(IntType('int', 4, True), 4))
        self.assertEqual(self.type_index.find_type('int []'),
                         ArrayType(IntType('int', 4, True), None))
