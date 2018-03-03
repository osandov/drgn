import unittest
from drgn.typename import (
    parse_type_name,
    ArrayTypeName,
    EnumTypeName,
    PointerTypeName,
    StructTypeName,
    TypedefTypeName,
    TypeName,
    UnionTypeName,
)


# TODO: complex types


class TestParseTypeName(unittest.TestCase):
    def test_empty(self):
        self.assertRaises(ValueError, parse_type_name, '')
        self.assertRaises(ValueError, parse_type_name, '  ')

    def test_invalid_character(self):
        self.assertRaises(ValueError, parse_type_name, '`')

    def test_void(self):
        self.assertEqual(parse_type_name('void'), TypeName('void'))

    def test_basic_types(self):
        self.assertEqual(parse_type_name('char'), TypeName('char'))
        self.assertEqual(parse_type_name('int'), TypeName('int'))
        self.assertEqual(parse_type_name('float'), TypeName('float'))
        self.assertEqual(parse_type_name('double'), TypeName('double'))
        self.assertEqual(parse_type_name('_Bool'), TypeName('_Bool'))

    def test_size(self):
        self.assertEqual(parse_type_name('long int'), TypeName('long int'))
        self.assertEqual(parse_type_name('long'), TypeName('long int'))
        self.assertEqual(parse_type_name('int long'), TypeName('long int'))

        self.assertEqual(parse_type_name('long long int'),
                         TypeName('long long int'))
        self.assertEqual(parse_type_name('long long'),
                         TypeName('long long int'))
        self.assertEqual(parse_type_name('int long long'),
                         TypeName('long long int'))
        self.assertEqual(parse_type_name('long int long'),
                         TypeName('long long int'))

        self.assertEqual(parse_type_name('short int'), TypeName('short int'))
        self.assertEqual(parse_type_name('short'), TypeName('short int'))
        self.assertEqual(parse_type_name('int short'), TypeName('short int'))

        self.assertEqual(parse_type_name('long double'),
                         TypeName('long double'))
        self.assertEqual(parse_type_name('double long'),
                         TypeName('long double'))

        self.assertRaises(ValueError, parse_type_name, 'short long int')
        self.assertRaises(ValueError, parse_type_name, 'long long long int')
        self.assertRaises(ValueError, parse_type_name, 'short double')
        self.assertRaises(ValueError, parse_type_name, 'double short')
        self.assertRaises(ValueError, parse_type_name, 'long long double')
        self.assertRaises(ValueError, parse_type_name, 'long double long')
        self.assertRaises(ValueError, parse_type_name, 'double long long')
        self.assertRaises(ValueError, parse_type_name, 'long char')
        self.assertRaises(ValueError, parse_type_name, 'char long')

    def test_sign(self):
        self.assertEqual(parse_type_name('signed int'), TypeName('int'))
        self.assertEqual(parse_type_name('signed'), TypeName('int'))
        self.assertEqual(parse_type_name('int signed'), TypeName('int'))

        self.assertEqual(parse_type_name('unsigned int'),
                         TypeName('unsigned int'))
        self.assertEqual(parse_type_name('unsigned'),
                         TypeName('unsigned int'))
        self.assertEqual(parse_type_name('int unsigned'),
                         TypeName('unsigned int'))

        self.assertEqual(parse_type_name('signed char'),
                         TypeName('signed char'))
        self.assertEqual(parse_type_name('char signed'),
                         TypeName('signed char'))

        self.assertEqual(parse_type_name('unsigned char'),
                         TypeName('unsigned char'))
        self.assertEqual(parse_type_name('char unsigned'),
                         TypeName('unsigned char'))

        self.assertRaises(ValueError, parse_type_name, 'signed unsigned int')
        self.assertRaises(ValueError, parse_type_name, 'signed _Bool')
        self.assertRaises(ValueError, parse_type_name, '_Bool signed')

    def test_qualifiers(self):
        self.assertEqual(parse_type_name('const int'),
                         TypeName('int', qualifiers={'const'}))
        self.assertEqual(parse_type_name('restrict int'),
                         TypeName('int', qualifiers={'restrict'}))
        self.assertEqual(parse_type_name('volatile int'),
                         TypeName('int', qualifiers={'volatile'}))
        self.assertEqual(parse_type_name('_Atomic int'),
                         TypeName('int', qualifiers={'_Atomic'}))
        self.assertEqual(parse_type_name('const volatile int'),
                         TypeName('int', qualifiers={'const', 'volatile'}))
        self.assertEqual(parse_type_name('const const int'),
                         TypeName('int', qualifiers={'const'}))

    def test_specifiers_qualifiers(self):
        self.assertEqual(parse_type_name('long const int unsigned'),
                         TypeName('long unsigned int', qualifiers={'const'}))

    def test_typedef(self):
        self.assertEqual(parse_type_name('u32'), TypedefTypeName('u32'))

    def test_tagged_type(self):
        self.assertEqual(parse_type_name('struct point'),
                         StructTypeName('point'))
        self.assertEqual(parse_type_name('union value'),
                         UnionTypeName('value'))
        self.assertEqual(parse_type_name('enum color'), EnumTypeName('color'))

    def test_pointer(self):
        self.assertEqual(parse_type_name('int *'),
                         PointerTypeName(TypeName('int')))
        self.assertEqual(parse_type_name('int * const'),
                         PointerTypeName(TypeName('int'),
                                         qualifiers={'const'}))

        self.assertEqual(parse_type_name('struct point *'),
                         PointerTypeName(StructTypeName('point')))

        self.assertEqual(parse_type_name('int **'),
                         PointerTypeName(PointerTypeName(TypeName('int'))))

        self.assertEqual(parse_type_name('int *((*))'),
                         PointerTypeName(PointerTypeName(TypeName('int'))))

        self.assertEqual(parse_type_name('int * const *'),
                         PointerTypeName(PointerTypeName(TypeName('int'),
                                                         qualifiers={'const'})))

    def test_array(self):
        self.assertEqual(parse_type_name('int []'),
                         ArrayTypeName(TypeName('int'), None))
        self.assertEqual(parse_type_name('int [2]'),
                         ArrayTypeName(TypeName('int'), 2))
        self.assertEqual(parse_type_name('int [0x10]'),
                         ArrayTypeName(TypeName('int'), 16))
        self.assertEqual(parse_type_name('int [010]'),
                         ArrayTypeName(TypeName('int'), 8))
        self.assertEqual(parse_type_name('int [2][3]'),
                         ArrayTypeName(ArrayTypeName(TypeName('int'), 3), 2))
        self.assertEqual(parse_type_name('int [2][3][4]'),
                         ArrayTypeName(ArrayTypeName(ArrayTypeName(TypeName('int'), 4), 3), 2))

    def test_array_of_pointers(self):
        self.assertEqual(parse_type_name('int *[2][3]'),
                         ArrayTypeName(ArrayTypeName(PointerTypeName(TypeName('int')), 3), 2))

    def test_pointer_to_array(self):
        self.assertEqual(parse_type_name('int (*)[2]'),
                         PointerTypeName(ArrayTypeName(TypeName('int'), 2)))
        self.assertEqual(parse_type_name('int (*)[2][3]'),
                         PointerTypeName(ArrayTypeName(ArrayTypeName(TypeName('int'), 3), 2)))

    def test_pointer_to_pointer_to_array(self):
        self.assertEqual(parse_type_name('int (**)[2]'),
                         PointerTypeName(PointerTypeName(ArrayTypeName(TypeName('int'), 2))))

    def test_pointer_to_array_of_pointers(self):
        self.assertEqual(parse_type_name('int *(*)[2]'),
                         PointerTypeName(ArrayTypeName(PointerTypeName(TypeName('int')), 2)))
        self.assertEqual(parse_type_name('int *((*)[2])'),
                         PointerTypeName(ArrayTypeName(PointerTypeName(TypeName('int')), 2)))

    def test_array_of_pointers_to_array(self):
        self.assertEqual(parse_type_name('int (*[2])[3]'),
                         ArrayTypeName(PointerTypeName(ArrayTypeName(TypeName('int'), 3)), 2))


class TestTypeStr(unittest.TestCase):
    def test_void(self):
        self.assertEqual(str(TypeName('void')), 'void')

    def test_basic_types(self):
        self.assertEqual(str(TypeName('char')), 'char')
        self.assertEqual(str(TypeName('int')), 'int')
        self.assertEqual(str(TypeName('float')), 'float')
        self.assertEqual(str(TypeName('double')), 'double')
        self.assertEqual(str(TypeName('_Bool')), '_Bool')

    def test_size(self):
        self.assertEqual(str(TypeName('long int')), 'long int')
        self.assertEqual(str(TypeName('long long int')), 'long long int')
        self.assertEqual(str(TypeName('short int')), 'short int')
        self.assertEqual(str(TypeName('long double')), 'long double')

    def test_sign(self):
        self.assertEqual(str(TypeName('unsigned int')), 'unsigned int')
        self.assertEqual(str(TypeName('signed char')), 'signed char')
        self.assertEqual(str(TypeName('unsigned char')), 'unsigned char')

    def test_qualifiers(self):
        self.assertEqual(str(TypeName('int', qualifiers={'const'})),
                         'const int')
        self.assertEqual(str(TypeName('int', qualifiers={'restrict'})),
                         'restrict int')
        self.assertEqual(str(TypeName('int', qualifiers={'volatile'})),
                         'volatile int')
        self.assertEqual(str(TypeName('int', qualifiers={'_Atomic'})),
                         '_Atomic int')
        self.assertEqual(str(TypeName('int', qualifiers={'const', 'volatile'})),
                         'const volatile int')

    def test_specifiers_qualifiers(self):
        self.assertEqual(str(TypeName('long unsigned int',
                                      qualifiers={'const'})),
                         'const long unsigned int')

    def test_typedef(self):
        self.assertEqual(str(TypedefTypeName('u32')), 'u32')

    def test_tagged_type(self):
        self.assertEqual(str(StructTypeName('point')), 'struct point')
        self.assertEqual(str(UnionTypeName('value')), 'union value')
        self.assertEqual(str(EnumTypeName('color')), 'enum color')

        self.assertEqual(str(StructTypeName(None)), 'struct <anonymous>')
        self.assertEqual(str(UnionTypeName(None)), 'union <anonymous>')
        self.assertEqual(str(EnumTypeName(None)), 'enum <anonymous>')

    def test_pointer(self):
        self.assertEqual(str(PointerTypeName(TypeName('int'))), 'int *')
        self.assertEqual(str(PointerTypeName(TypeName('int'), qualifiers={'const'})),
                         'int * const')

        self.assertEqual(str(PointerTypeName(TypeName('struct point'))),
                         'struct point *')

        self.assertEqual(str(PointerTypeName(PointerTypeName(TypeName('int')))),
                         'int **')

        self.assertEqual(str(PointerTypeName(PointerTypeName(TypeName('int'),
                                                             qualifiers={'const'}))),
                         'int * const *')

    def test_array(self):
        self.assertEqual(str(ArrayTypeName(TypeName('int'), None)),
                         'int []')
        self.assertEqual(str(ArrayTypeName(TypeName('int'), 2)),
                         'int [2]')
        self.assertEqual(str(ArrayTypeName(ArrayTypeName(TypeName('int'), 3), 2)),
                         'int [2][3]')
        self.assertEqual(str(ArrayTypeName(ArrayTypeName(ArrayTypeName(TypeName('int'), 4), 3), 2)),
                         'int [2][3][4]')

    def test_array_of_pointers(self):
        self.assertEqual(str(ArrayTypeName(ArrayTypeName(PointerTypeName(TypeName('int')), 3), 2)),
                         'int *[2][3]')

    def test_pointer_to_array(self):
        self.assertEqual(str(PointerTypeName(ArrayTypeName(TypeName('int'), 2))),
                         'int (*)[2]')
        self.assertEqual(parse_type_name('int (*)[2][3]'),
                         PointerTypeName(ArrayTypeName(ArrayTypeName(TypeName('int'), 3), 2)))

    def test_pointer_to_pointer_to_array(self):
        self.assertEqual(str(PointerTypeName(PointerTypeName(ArrayTypeName(TypeName('int'), 2)))),
                         'int (**)[2]')

    def test_pointer_to_array_of_pointers(self):
        self.assertEqual(str(PointerTypeName(ArrayTypeName(PointerTypeName(TypeName('int')), 2))),
                         'int *(*)[2]')

    def test_array_of_pointers_to_array(self):
        self.assertEqual(str(ArrayTypeName(PointerTypeName(ArrayTypeName(TypeName('int'), 3)), 2)),
                         'int (*[2])[3]')
