import os.path
import subprocess
import tempfile
import unittest

from drgn.dwarf import DW_TAG
from drgn.dwarfindex import DwarfIndex
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
from drgn.typeindex import DwarfTypeIndex, TypeIndex
from drgn.typename import BasicTypeName, TypeName, TypedefTypeName
from tests.test_type import (
    anonymous_point_type,
    const_anonymous_point_type,
    line_segment_type,
    pointer_size,
    point_type,
    TypeTestCase,
)


TYPES = {
    'void': VoidType(),
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
    'ptrdiff_t': FloatType('long double', 16),
}
TYPES['ptrdiff_t'] = TypedefType('ptrdiff_t', TYPES['long'])


class MockTypeIndex(TypeIndex):
    def __init__(self):
        super().__init__(8)

    def _find_type(self, type_name: TypeName) -> Type:
        if isinstance(type_name, (BasicTypeName, TypedefTypeName)):
            try:
                return TYPES[type_name.name]
            except KeyError:
                pass
        raise ValueError('type not found')


class TypeIndexTestCase(TypeTestCase):
    def setUp(self):
        super().setUp()
        self.type_index = MockTypeIndex()


class TestTypeIndexLiteralType(TypeIndexTestCase):
    def test_bool(self):
        self.assertEqual(self.type_index.literal_type(True), TYPES['_Bool'])
        self.assertEqual(self.type_index.literal_type(False), TYPES['_Bool'])

    def test_int(self):
        self.assertEqual(self.type_index.literal_type(0), TYPES['int'])
        self.assertEqual(self.type_index.literal_type(-2**31), TYPES['int'])
        self.assertEqual(self.type_index.literal_type(2**31 - 1), TYPES['int'])

        self.assertEqual(self.type_index.literal_type(2**31),
                         TYPES['unsigned int'])
        self.assertEqual(self.type_index.literal_type(2**32 - 1),
                         TYPES['unsigned int'])

        self.assertEqual(self.type_index.literal_type(-2**31 - 1),
                         TYPES['long'])
        self.assertEqual(self.type_index.literal_type(-2**63), TYPES['long'])
        self.assertEqual(self.type_index.literal_type(2**32), TYPES['long'])
        self.assertEqual(self.type_index.literal_type(2**63 - 1),
                         TYPES['long'])

        self.assertEqual(self.type_index.literal_type(2**63),
                         TYPES['unsigned long'])
        self.assertEqual(self.type_index.literal_type(2**64 - 1),
                         TYPES['unsigned long'])

    def test_float(self):
        self.assertEqual(self.type_index.literal_type(0.0), TYPES['double'])
        self.assertEqual(self.type_index.literal_type(float('inf')),
                         TYPES['double'])
        self.assertEqual(self.type_index.literal_type(float('nan')),
                         TYPES['double'])

    def test_error(self):
        self.assertRaises(TypeError, self.type_index.literal_type, None)
        self.assertRaises(TypeError, self.type_index.literal_type, 2**128)


class TestTypeIndexIntegerPromotions(TypeIndexTestCase):
    def assertPromotes(self, type, expected_type):
        self.assertEqual(self.type_index.integer_promotions(type),
                         expected_type)

    def test_char(self):
        self.assertPromotes(TYPES['char'], TYPES['int'])
        self.assertPromotes(TYPES['signed char'], TYPES['int'])
        self.assertPromotes(TYPES['unsigned char'], TYPES['int'])

    def test_short(self):
        self.assertPromotes(TYPES['short'], TYPES['int'])
        self.assertPromotes(TYPES['unsigned short'], TYPES['int'])

    def test_bool(self):
        self.assertPromotes(TYPES['_Bool'], TYPES['int'])

    def test_enum(self):
        type_ = EnumType('color', IntType('int', 4, True), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
        self.assertPromotes(type_, TYPES['int'])

        type_ = EnumType('color', IntType('unsigned int', 4, False), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
        self.assertPromotes(type_, TYPES['unsigned int'])

        type_ = EnumType('color', IntType('unsigned long', 8, False), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
        self.assertPromotes(type_, TYPES['unsigned long'])

    def test_int(self):
        self.assertPromotes(TYPES['int'], TYPES['int'])
        self.assertPromotes(TYPES['unsigned int'], TYPES['unsigned int'])

    def test_long(self):
        self.assertPromotes(TYPES['long'], TYPES['long'])
        self.assertPromotes(TYPES['unsigned long'], TYPES['unsigned long'])

    def test_long_long(self):
        self.assertPromotes(TYPES['long long'], TYPES['long long'])
        self.assertPromotes(TYPES['unsigned long long'],
                            TYPES['unsigned long long'])

    def test_bit_field(self):
        self.assertPromotes(BitFieldType(TYPES['int'], 0, 4), TYPES['int'])
        self.assertPromotes(BitFieldType(TYPES['long'], 0, 4),
                            TYPES['int'])

        self.assertPromotes(BitFieldType(TYPES['int'], 0, 32), TYPES['int'])
        self.assertPromotes(BitFieldType(TYPES['long'], 0, 32), TYPES['int'])

        self.assertPromotes(BitFieldType(TYPES['unsigned int'], 0, 4),
                            TYPES['int'])
        self.assertPromotes(BitFieldType(TYPES['unsigned long'], 0, 4),
                            TYPES['int'])

        self.assertPromotes(BitFieldType(TYPES['unsigned int'], 0, 32),
                            TYPES['unsigned int'])
        self.assertPromotes(BitFieldType(TYPES['unsigned long'], 0, 32),
                            TYPES['unsigned int'])

        self.assertPromotes(BitFieldType(TYPES['long'], 0, 40),
                            BitFieldType(TYPES['long'], None, 40))
        self.assertPromotes(BitFieldType(TYPES['unsigned long'], 0, 40),
                            BitFieldType(TYPES['unsigned long'], None, 40))

    def test_typedef(self):
        type_ = TypedefType('SHORT', TYPES['short'])
        self.assertPromotes(type_, TYPES['int'])

        type_ = TypedefType('INT', TYPES['int'])
        self.assertPromotes(type_, type_)

        type_ = TypedefType('LONG', TYPES['long'])
        self.assertPromotes(type_, type_)

    def test_other(self):
        self.assertPromotes(TYPES['float'], TYPES['float'])
        self.assertPromotes(TYPES['double'], TYPES['double'])


class TestTypeIndexCommonRealType(TypeIndexTestCase):
    def assertCommon(self, type1, type2, expected_type):
        self.assertEqual(self.type_index.common_real_type(type1, type2),
                         expected_type)
        self.assertEqual(self.type_index.common_real_type(type2, type1),
                         expected_type)

    def test_long_double(self):
        self.assertCommon(TYPES['long double'], TYPES['double'],
                          TYPES['long double'])
        self.assertCommon(TYPES['int'], TYPES['long double'],
                          TYPES['long double'])

    def test_double(self):
        self.assertCommon(TYPES['double'], TYPES['float'], TYPES['double'])
        self.assertCommon(TYPES['long'], TYPES['double'], TYPES['double'])

    def test_float(self):
        self.assertCommon(TYPES['int'], TYPES['float'], TYPES['float'])
        self.assertCommon(TYPES['float'], TYPES['long long'], TYPES['float'])

    def test_same(self):
        self.assertCommon(TYPES['int'], TYPES['int'], TYPES['int'])

    def test_same_sign(self):
        self.assertCommon(TYPES['long'], TYPES['long long'],
                          TYPES['long long'])

        self.assertCommon(IntType('unsigned long', 4, False),
                          TYPES['unsigned int'],
                          IntType('unsigned long', 4, False))

    def test_unsigned_rank(self):
        self.assertCommon(TYPES['long'], TYPES['unsigned long long'],
                          TYPES['unsigned long long'])
        self.assertCommon(TYPES['unsigned int'], TYPES['int'],
                          TYPES['unsigned int'])

    def test_signed_range(self):
        self.assertCommon(TYPES['long'], TYPES['unsigned int'], TYPES['long'])
        self.assertCommon(IntType('unsigned long', 4, False),
                          TYPES['long long'], TYPES['long long'])

    def test_corresponding_unsigned(self):
        self.assertCommon(IntType('long', 4, True), TYPES['unsigned int'],
                          IntType('unsigned long', 4, False))
        self.assertCommon(TYPES['long long'], TYPES['unsigned long'],
                          TYPES['unsigned long long'])

    def test_typedef(self):
        typedef_type = TypedefType('u32', TYPES['unsigned int'])
        self.assertCommon(typedef_type, typedef_type, typedef_type)

    def test_bool(self):
        self.assertCommon(BoolType('_Bool', 1), TYPES['int'], TYPES['int'])

    def test_bit_field(self):
        self.assertCommon(BitFieldType(TYPES['int'], None, 4),
                          BitFieldType(TYPES['int'], None, 4), TYPES['int'])

        self.assertCommon(BitFieldType(TYPES['long'], None, 4),
                          BitFieldType(TYPES['long'], None, 4), TYPES['int'])

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['long'], None, 33),
                          BitFieldType(TYPES['long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['long long'], None, 33),
                          BitFieldType(TYPES['long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['long long'], None, 40),
                          BitFieldType(TYPES['long long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['unsigned long'], None, 33),
                          BitFieldType(TYPES['long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['unsigned long'], None, 40),
                          BitFieldType(TYPES['unsigned long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40), TYPES['int'],
                          BitFieldType(TYPES['long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40), TYPES['long'],
                          TYPES['long'])

    def test_enum(self):
        type_ = EnumType('color', IntType('int', 4, True), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
        self.assertCommon(type_, TYPES['int'], TYPES['int'])

        type_ = TypedefType('COLOR', type_)
        self.assertCommon(type_, TYPES['int'], TYPES['int'])


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
} x;"""), EnumType('color', IntType('unsigned int', 4, False), [('RED', 0), ('GREEN', 1), ('BLUE', 2)]))

        self.assertEqual(self.compile_type("""\
enum {
	RED = 10,
	GREEN,
	BLUE = -1,
} x;"""), EnumType(None, IntType('int', 4, True), [('RED', 10), ('GREEN', 11), ('BLUE', -1)]))

    def test_incomplete_enum(self):
        self.assertEqual(self.compile_type('enum foo; extern enum foo x'),
                         EnumType('foo', None, None))

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
                        ArrayType(IntType('int', 4, True), 2, pointer_size))
        self.assertEqual(self.compile_type('int x[2][3]'),
                        ArrayType(ArrayType(IntType('int', 4, True), 3, pointer_size), 2, pointer_size))
        self.assertEqual(self.compile_type('int x[2][3][4]'),
                        ArrayType(ArrayType(ArrayType(IntType('int', 4, True), 4, pointer_size), 3, pointer_size), 2, pointer_size))

    def test_incomplete_array(self):
        self.assertEqual(self.compile_type('extern int x[]'),
                        ArrayType(IntType('int', 4, True), None, pointer_size))
        self.assertEqual(self.compile_type('extern int x[][2]'),
                        ArrayType(ArrayType(IntType('int', 4, True), 2, pointer_size), None, pointer_size))

    def test_pointer_to_const_void(self):
        self.assertEqual(self.compile_type('const void *x'),
                         PointerType(pointer_size, VoidType(frozenset({'const'}))))

    def test_pointer_to_function(self):
        self.assertEqual(self.compile_type('int (*x)(int)'),
                         PointerType(pointer_size, FunctionType(pointer_size, IntType('int', 4, True), [(IntType('int', 4, True), None)])))

    def test_pointer_to_variadic_function(self):
        self.assertEqual(self.compile_type('int (*x)(int, ...)'),
                         PointerType(pointer_size, FunctionType(pointer_size, IntType('int', 4, True), [(IntType('int', 4, True), None)], variadic=True)))

    def test_pointer_to_function_with_no_parameter_specification(self):
        self.assertEqual(self.compile_type('int (*x)()'),
                         PointerType(pointer_size, FunctionType(pointer_size, IntType('int', 4, True), None)))

    def test_pointer_to_function_with_no_parameters(self):
        self.assertEqual(self.compile_type('int (*x)(void)'),
                         PointerType(pointer_size, FunctionType(pointer_size, IntType('int', 4, True), [])))


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
                         EnumType('color', IntType('unsigned int', 4, False), [
                             ('RED', 0),
                             ('GREEN', 1),
                             ('BLUE', 2)
                         ]))

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
                         ArrayType(IntType('int', 4, True), 4, pointer_size))
        self.assertEqual(self.type_index.find_type('int []'),
                         ArrayType(IntType('int', 4, True), None, pointer_size))
