import os.path
import subprocess
import tempfile

from drgn.internal.dwarf import DW_TAG
from drgn.internal.dwarfindex import DwarfIndex
from drgn.internal.dwarftypeindex import DwarfTypeIndex
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
        dwarf_index = DwarfIndex()
        dwarf_index.add(object_path)
        dwarf_type = dwarf_index.find('x', DW_TAG.variable)[0].type()
        return DwarfTypeIndex(dwarf_index)._from_dwarf_type(dwarf_type)

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
        self.assertEqual(self.compile_type('struct foo; struct foo *x').type,
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
        self.assertEqual(self.compile_type('union foo; union foo *x').type,
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
        self.assertEqual(self.compile_type('enum foo; enum foo *x').type,
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
        self.assertEqual(self.compile_type('int (*x)[]').type,
                        ArrayType(IntType('int', 4, True), None, pointer_size))
        self.assertEqual(self.compile_type('int (*x)[][2]').type,
                        ArrayType(ArrayType(IntType('int', 4, True), 2, pointer_size), None, pointer_size))

    def test_pointer_to_const_void(self):
        self.assertEqual(self.compile_type('const void *x'),
                         PointerType(pointer_size, VoidType({'const'})))

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
            dwarf_index = DwarfIndex()
            dwarf_index.add(object_path)
            cls.type_index = DwarfTypeIndex(dwarf_index)

    def test_void_type(self):
        self.assertEqual(self.type_index.find('void'),
                         VoidType())
        self.assertEqual(self.type_index.find('const void'),
                         VoidType({'const'}))

    def test_base_type(self):
        self.assertEqual(self.type_index.find('int'),
                         IntType('int', 4, True))
        self.assertEqual(self.type_index.find('signed int'),
                         IntType('int', 4, True))
        self.assertEqual(self.type_index.find('int signed'),
                         IntType('int', 4, True))
        self.assertEqual(self.type_index.find('volatile int'),
                         IntType('int', 4, True, {'volatile'}))

        self.assertEqual(self.type_index.find('char'),
                         IntType('char', 1, True))
        self.assertEqual(self.type_index.find('signed char'),
                         IntType('signed char', 1, True))
        self.assertEqual(self.type_index.find('char signed'),
                         IntType('signed char', 1, True))
        self.assertEqual(self.type_index.find('unsigned char'),
                         IntType('unsigned char', 1, False))
        self.assertEqual(self.type_index.find('char unsigned'),
                         IntType('unsigned char', 1, False))

        self.assertEqual(self.type_index.find('unsigned long long'),
                         IntType('unsigned long long', 8, False))
        self.assertEqual(self.type_index.find('long long unsigned int'),
                         IntType('unsigned long long', 8, False))
        self.assertEqual(self.type_index.find('long long int unsigned'),
                         IntType('unsigned long long', 8, False))


    def test_struct_type(self):
        self.assertEqual(self.type_index.find('struct point'),
                         point_type)

    def test_union_type(self):
        self.assertEqual(self.type_index.find('union value'),
                         UnionType('value', 4, [
                             ('i', 0, lambda: IntType('int', 4, True)),
                             ('f', 0, lambda: FloatType('float', 4)),
                         ]))

    def test_enum_type(self):
        self.assertEqual(self.type_index.find('enum color'),
                         EnumType('color', IntType('unsigned int', 4, False), [
                             ('RED', 0),
                             ('GREEN', 1),
                             ('BLUE', 2)
                         ]))

    def test_typedef_type(self):
        self.assertEqual(self.type_index.find('point'),
                         TypedefType('point', point_type))
        self.assertEqual(self.type_index.find('const point'),
                         TypedefType('point', point_type, {'const'}))

    def test_pointer_type(self):
        self.assertEqual(self.type_index.find('int *'),
                         PointerType(pointer_size, IntType('int', 4, True)))
        self.assertEqual(self.type_index.find('int * const'),
                         PointerType(pointer_size, IntType('int', 4, True), {'const'}))

    def test_array_type(self):
        self.assertEqual(self.type_index.find('int [4]'),
                         ArrayType(IntType('int', 4, True), 4, pointer_size))
        self.assertEqual(self.type_index.find('int []'),
                         ArrayType(IntType('int', 4, True), None, pointer_size))
