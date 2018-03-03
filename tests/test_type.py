import ctypes
import os.path
import subprocess
import tempfile
import unittest

from drgn.dwarf import DwarfFile, DwarfIndex
from drgn.elf import ElfFile
from drgn.type import (
    ArrayType,
    BaseType,
    EnumType,
    PointerType,
    StructType,
    TypedefType,
    TypeFactory,
    UnionType,
    VoidType,
)


class TestFromDwarfType(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        if hasattr(self, 'dwarf_file'):
            self.dwarf_file.close()
        if hasattr(self, 'program_file'):
            self.program_file.close()
        self.tmp_dir.cleanup()

    def compile_and_run(self, source_code):
        if hasattr(self, 'type_factory'):
            del self.type_factory
        if hasattr(self, 'dwarf_index'):
            del self.dwarf_index
        if hasattr(self, 'dwarf_file'):
            self.dwarf_file.close()
            del self.dwarf_file
        if hasattr(self, 'program_file'):
            self.program_file.close()
            del self.program_file

        program_path = os.path.join(self.tmp_dir.name, 'test')
        source_path = program_path + '.c'
        with open(source_path, 'w') as f:
            f.write(source_code)
        subprocess.check_call(['gcc', '-g', '-o', program_path, source_path])
        self.program_file = open(program_path, 'rb')
        elf_file = ElfFile(self.program_file)
        self.dwarf_file = DwarfFile(self.program_file, elf_file.sections)
        self.dwarf_index = DwarfIndex()
        for cu in self.dwarf_file.cu_headers():
            self.dwarf_index.index_cu(cu)
        self.type_factory = TypeFactory(self.dwarf_index)
        return subprocess.check_output([program_path])

    def assertType(self, decl, type_name, callback):
        do_sizeof = 'extern' not in decl
        lines = [
            '#include <stdio.h>',
            '',
            decl + ';',
            '',
            'int main(void)',
            '{',
        ]
        if do_sizeof:
            lines.append('\tprintf("%zu\\n", sizeof(x));')
        lines.append('\treturn 0;')
        lines.append('}')
        lines.append('')
        output = self.compile_and_run('\n'.join(lines))
        dwarf_type = self.dwarf_index.find_variable('x').type()
        type_ = self.type_factory.from_dwarf_type(dwarf_type)

        self.assertEqual(type_, callback(self.type_factory, dwarf_type))
        self.assertEqual(str(type_), type_name)
        if do_sizeof:
            self.assertEqual(type_.sizeof(), int(output))
        else:
            self.assertRaises(ValueError, type_.sizeof)

    def test_char(self):
        self.assertType('char x', 'char', BaseType)
        self.assertType('signed char x', 'signed char', BaseType)
        self.assertType('unsigned char x', 'unsigned char', BaseType)

    def test_short(self):
        self.assertType('short x', 'short int', BaseType)
        self.assertType('signed short x', 'short int', BaseType)
        self.assertType('unsigned short int x', 'short unsigned int', BaseType)

    def test_int(self):
        self.assertType('int x', 'int', BaseType)
        self.assertType('signed int x', 'int', BaseType)
        self.assertType('unsigned int x', 'unsigned int', BaseType)

    def test_long(self):
        self.assertType('long x', 'long int', BaseType)
        self.assertType('signed long x', 'long int', BaseType)
        self.assertType('unsigned long int x', 'long unsigned int', BaseType)

    def test_long_long(self):
        self.assertType('long long x', 'long long int', BaseType)
        self.assertType('signed long long x', 'long long int', BaseType)
        self.assertType('unsigned long long int x', 'long long unsigned int',
                        BaseType)

    def test_float(self):
        self.assertType('float x', 'float', BaseType)
        self.assertType('double x', 'double', BaseType)
        self.assertType('long double x', 'long double', BaseType)

    def test_bool(self):
        self.assertType('_Bool x', '_Bool', BaseType)

    def test_qualifiers(self):
        # restrict is only valid in function parameters, and GCC doesn't seem
        # to create a type for _Atomic.
        self.assertType('const int x', 'const int',
                        lambda factory, dwarf_type:
                        BaseType(factory, dwarf_type.unqualified(), {'const'}))
        self.assertType('volatile int x', 'volatile int',
                        lambda factory, dwarf_type:
                        BaseType(factory, dwarf_type.unqualified(), {'volatile'}))
        self.assertType('const volatile int x', 'const volatile int',
                        lambda factory, dwarf_type:
                        BaseType(factory, dwarf_type.unqualified(),
                                 {'const', 'volatile'}))

    def test_typedef(self):
        size = ctypes.sizeof(ctypes.c_void_p)

        self.assertType('typedef int INT; INT x', 'typedef int INT',
                        lambda factory, dwarf_type:
                        TypedefType(BaseType(factory, dwarf_type.unqualified()), 'INT'))
        self.assertType('typedef char *string; string x', 'typedef char *string',
                        lambda factory, dwarf_type:
                        TypedefType(PointerType(BaseType(factory, dwarf_type.unqualified().type()), size), 'string'))

    def test_struct(self):
        self.assertType("""\
struct point {
	int x;
	int y;
};

struct point x;""", """\
struct point {
	int x;
	int y;
}""",
                        lambda factory, dwarf_type:
                        StructType(factory, dwarf_type))

        self.assertType("""\
struct point {
	int x;
	int y;
};

struct line_segment {
	struct point a;
	struct point b;
};

struct line_segment x;""", """\
struct line_segment {
	struct point a;
	struct point b;
}""",
                        lambda factory, dwarf_type:
                        StructType(factory, dwarf_type))

        self.assertType("""\
struct {
	int x;
	int y;
} x;""", """\
struct {
	int x;
	int y;
}""",
                        lambda factory, dwarf_type:
                        StructType(factory, dwarf_type))

        self.assertType("""\
const struct point {
	const struct {
		int x;
		int y;
	};
} x;""", """\
const struct point {
	const struct {
		int x;
		int y;
	};
}""",
                        lambda factory, dwarf_type:
                        StructType(factory, dwarf_type.unqualified(), {'const'}))

    def test_bit_fields(self):
        self.assertType("""\
struct {
	int x : 4;
	int y : 4;
} x;""", """\
struct {
	int x : 4;
	int y : 4;
}""",
                        lambda factory, dwarf_type:
                        StructType(factory, dwarf_type))

    def test_union(self):
        self.assertType("""\
union value {
	int i;
	float f;
} x;""", """\
union value {
	int i;
	float f;
}""",
                        lambda factory, dwarf_type:
                        UnionType(factory, dwarf_type))

        self.assertType("""\
struct point {
	int x;
	int y;
};

union value {
	int i;
	float f;
	struct point p;
} x;""", """\
union value {
	int i;
	float f;
	struct point p;
}""",
                        lambda factory, dwarf_type:
                        UnionType(factory, dwarf_type))

    def test_anonymous_field(self):
        self.assertType("""\
struct tagged_union {
	int type;
	union {
		int i;
		double d;
	};
} x;""", """\
struct tagged_union {
	int type;
	union {
		int i;
		double d;
	};
}""",
                        lambda factory, dwarf_type:
                        StructType(factory, dwarf_type))

        self.assertType("""\
struct tagged_union {
	int type;
	union {
		int i;
		double d;
	} value;
} x;""", """\
struct tagged_union {
	int type;
	union {
		int i;
		double d;
	} value;
}""",
                        lambda factory, dwarf_type:
                        StructType(factory, dwarf_type))

    def test_enum(self):
        self.assertType("""\
enum color {
	RED,
	GREEN,
	BLUE,
} x;""", """\
enum color {
	RED = 0,
	GREEN = 1,
	BLUE = 2,
}""",
                        lambda factory, dwarf_type:
                        EnumType(factory, dwarf_type))
        self.assertType("""\
enum {
	RED = 10,
	GREEN,
	BLUE = -1,
} x;""", """\
enum {
	RED = 10,
	GREEN = 11,
	BLUE = -1,
}""",
                        lambda factory, dwarf_type:
                        EnumType(factory, dwarf_type))
        self.assertType("""\
struct point {
	enum {
		RED,
		GREEN,
		BLUE,
	} color;
	int x, y;
} x;""", """\
struct point {
	enum {
		RED = 0,
		GREEN = 1,
		BLUE = 2,
	} color;
	int x;
	int y;
}""",
                        lambda factory, dwarf_type:
                        StructType(factory, dwarf_type))


    def test_pointer(self):
        size = ctypes.sizeof(ctypes.c_void_p)

        self.assertType('int *x', 'int *',
                        lambda factory, dwarf_type:
                        PointerType(BaseType(factory, dwarf_type.type()), size))

        self.assertType('int * const x', 'int * const',
                        lambda factory, dwarf_type:
                        PointerType(BaseType(factory, dwarf_type.unqualified().type()), size, {'const'}))

        self.assertType("""\
struct point {
	int x;
	int y;
};

struct point *x;""", 'struct point *',
                        lambda factory, dwarf_type:
                        PointerType(StructType(factory, dwarf_type.type()), size))

        self.assertType('int **x', 'int **',
                        lambda factory, dwarf_type:
                        PointerType(PointerType(BaseType(factory, dwarf_type.type().type()), size), size))

        self.assertType('void *x', 'void *',
                        lambda factory, dwarf_type:
                        PointerType(VoidType(), size))

    def test_array(self):
        self.assertType('int x[2]', 'int [2]',
                        lambda factory, dwarf_type:
                        ArrayType(BaseType(factory, dwarf_type.type()), 2))
        self.assertType('int x[2][3]', 'int [2][3]',
                        lambda factory, dwarf_type:
                        ArrayType(ArrayType(BaseType(factory, dwarf_type.type()), 3), 2))
        self.assertType('int x[2][3][4]', 'int [2][3][4]',
                        lambda factory, dwarf_type:
                        ArrayType(ArrayType(ArrayType(BaseType(factory, dwarf_type.type()), 4), 3), 2))

    def test_incomplete_array(self):
        self.assertType('extern int x[]', 'int []',
                        lambda factory, dwarf_type:
                        ArrayType(BaseType(factory, dwarf_type.type()), None))
        self.assertType('extern int x[][2]', 'int [][2]',
                        lambda factory, dwarf_type:
                        ArrayType(ArrayType(BaseType(factory, dwarf_type.type()), 2), None))
