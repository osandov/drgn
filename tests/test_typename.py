import unittest
from drgn.type import parse_type_name, ArrayType, PointerType, TypeSpecifier


class TestParseTypeName(unittest.TestCase):
    def test_empty(self):
        self.assertRaises(ValueError, parse_type_name, '')
        self.assertRaises(ValueError, parse_type_name, '  ')

    def test_invalid_character(self):
        self.assertRaises(ValueError, parse_type_name, '`')

    def test_base_type(self):
        self.assertEqual(parse_type_name('void'), TypeSpecifier('void'))
        self.assertEqual(parse_type_name('char'), TypeSpecifier('char'))
        self.assertEqual(parse_type_name('int'), TypeSpecifier('int'))
        self.assertEqual(parse_type_name('float'), TypeSpecifier('float'))
        self.assertEqual(parse_type_name('double'), TypeSpecifier('double'))
        self.assertEqual(parse_type_name('_Bool'), TypeSpecifier('_Bool'))
        self.assertEqual(parse_type_name('_Complex'), TypeSpecifier('_Complex'))

    def test_size(self):
        long_int = TypeSpecifier('int', size='long')
        self.assertEqual(parse_type_name('long int'), long_int)
        self.assertEqual(parse_type_name('long'), long_int)
        self.assertEqual(parse_type_name('int long'), long_int)

        long_long_int = TypeSpecifier('int', size='long long')
        self.assertEqual(parse_type_name('long long int'), long_long_int)
        self.assertEqual(parse_type_name('long long'), long_long_int)
        self.assertEqual(parse_type_name('int long long'), long_long_int)
        self.assertEqual(parse_type_name('long int long'), long_long_int)

        short_int = TypeSpecifier('int', size='short')
        self.assertEqual(parse_type_name('short int'), short_int)
        self.assertEqual(parse_type_name('short'), short_int)
        self.assertEqual(parse_type_name('int short'), short_int)

        self.assertRaises(ValueError, parse_type_name, 'short long int')
        self.assertRaises(ValueError, parse_type_name, 'long long long int')
        self.assertRaises(ValueError, parse_type_name, 'long char')
        self.assertRaises(ValueError, parse_type_name, 'char long')

    def test_sign(self):
        signed_int = TypeSpecifier('int', sign='signed')
        self.assertEqual(parse_type_name('signed int'), signed_int)
        self.assertEqual(parse_type_name('signed'), signed_int)
        self.assertEqual(parse_type_name('int signed'), signed_int)

        unsigned_int = TypeSpecifier('int', sign='unsigned')
        self.assertEqual(parse_type_name('unsigned int'), unsigned_int)
        self.assertEqual(parse_type_name('unsigned'), unsigned_int)
        self.assertEqual(parse_type_name('int unsigned'), unsigned_int)

        signed_char = TypeSpecifier('char', sign='signed')
        self.assertEqual(parse_type_name('signed char'), signed_char)
        self.assertEqual(parse_type_name('char signed'), signed_char)

        unsigned_char = TypeSpecifier('char', sign='unsigned')
        self.assertEqual(parse_type_name('unsigned char'), unsigned_char)
        self.assertEqual(parse_type_name('char unsigned'), unsigned_char)

        signed_complex = TypeSpecifier('_Complex', sign='signed')
        self.assertEqual(parse_type_name('signed _Complex'), signed_complex)
        self.assertEqual(parse_type_name('_Complex signed'), signed_complex)

        unsigned_complex = TypeSpecifier('_Complex', sign='unsigned')
        self.assertEqual(parse_type_name('unsigned _Complex'), unsigned_complex)
        self.assertEqual(parse_type_name('_Complex unsigned'), unsigned_complex)

        self.assertRaises(ValueError, parse_type_name, 'signed unsigned int')
        self.assertRaises(ValueError, parse_type_name, 'signed _Bool')
        self.assertRaises(ValueError, parse_type_name, '_Bool signed')

    def test_qualifiers(self):
        self.assertEqual(parse_type_name('const int'),
                         TypeSpecifier('int', qualifiers={'const'}))
        self.assertEqual(parse_type_name('restrict int'),
                         TypeSpecifier('int', qualifiers={'restrict'}))
        self.assertEqual(parse_type_name('volatile int'),
                         TypeSpecifier('int', qualifiers={'volatile'}))
        self.assertEqual(parse_type_name('_Atomic int'),
                         TypeSpecifier('int', qualifiers={'_Atomic'}))
        self.assertEqual(parse_type_name('const volatile int'),
                         TypeSpecifier('int', qualifiers={'const', 'volatile'}))
        self.assertEqual(parse_type_name('const const int'),
                         TypeSpecifier('int', qualifiers={'const'}))

    def test_specifiers_qualifiers(self):
        self.assertEqual(parse_type_name('long const int unsigned'),
                         TypeSpecifier('int', size='long', sign='unsigned',
                                       qualifiers={'const'}))

    def test_typedef(self):
        self.assertEqual(parse_type_name('u32'), TypeSpecifier('u32'))

    def test_tagged_type(self):
        self.assertEqual(parse_type_name('struct point'),
                         TypeSpecifier('struct point'))
        self.assertEqual(parse_type_name('union value'),
                         TypeSpecifier('union value'))
        self.assertEqual(parse_type_name('enum color'),
                         TypeSpecifier('enum color'))

    def test_pointer(self):
        self.assertEqual(parse_type_name('int *'),
                         PointerType(TypeSpecifier('int')))
        self.assertEqual(parse_type_name('int * const'),
                         PointerType(TypeSpecifier('int'), qualifiers={'const'}))

        self.assertEqual(parse_type_name('struct point *'),
                         PointerType(TypeSpecifier('struct point')))

        self.assertEqual(parse_type_name('int **'),
                         PointerType(PointerType(TypeSpecifier('int'))))

        self.assertEqual(parse_type_name('int *((*))'),
                         PointerType(PointerType(TypeSpecifier('int'))))

        self.assertEqual(parse_type_name('int * const *'),
                         PointerType(PointerType(TypeSpecifier('int'),
                                                 qualifiers={'const'})))

    def test_array(self):
        self.assertEqual(parse_type_name('int []'),
                         ArrayType(TypeSpecifier('int'), None))
        self.assertEqual(parse_type_name('int [2]'),
                         ArrayType(TypeSpecifier('int'), 2))
        self.assertEqual(parse_type_name('int [0x10]'),
                         ArrayType(TypeSpecifier('int'), 16))
        self.assertEqual(parse_type_name('int [010]'),
                         ArrayType(TypeSpecifier('int'), 8))
        self.assertEqual(parse_type_name('int [2][3]'),
                         ArrayType(ArrayType(TypeSpecifier('int'), 3), 2))
        self.assertEqual(parse_type_name('int [2][3][4]'),
                         ArrayType(ArrayType(ArrayType(TypeSpecifier('int'), 4), 3), 2))

    def test_array_of_pointers(self):
        self.assertEqual(parse_type_name('int *[2][3]'),
                         ArrayType(ArrayType(PointerType(TypeSpecifier('int')), 3), 2))

    def test_pointer_to_array(self):
        self.assertEqual(parse_type_name('int (*)[2]'),
                         PointerType(ArrayType(TypeSpecifier('int'), 2)))
        self.assertEqual(parse_type_name('int (*)[2][3]'),
                         PointerType(ArrayType(ArrayType(TypeSpecifier('int'), 3), 2)))

    def test_pointer_to_pointer_to_array(self):
        self.assertEqual(parse_type_name('int (**)[2]'),
                         PointerType(PointerType(ArrayType(TypeSpecifier('int'), 2))))

    def test_pointer_to_array_of_pointers(self):
        self.assertEqual(parse_type_name('int *(*)[2]'),
                         PointerType(ArrayType(PointerType(TypeSpecifier('int')), 2)))
        self.assertEqual(parse_type_name('int *((*)[2])'),
                         PointerType(ArrayType(PointerType(TypeSpecifier('int')), 2)))

    def test_array_of_pointers_to_array(self):
        self.assertEqual(parse_type_name('int (*[2])[3]'),
                         ArrayType(PointerType(ArrayType(TypeSpecifier('int'), 3)), 2))


class TestTypeStr(unittest.TestCase):
    def test_base_type(self):
        self.assertEqual(str(TypeSpecifier('void')), 'void')
        self.assertEqual(str(TypeSpecifier('char')), 'char')
        self.assertEqual(str(TypeSpecifier('int')), 'int')
        self.assertEqual(str(TypeSpecifier('float')), 'float')
        self.assertEqual(str(TypeSpecifier('double')), 'double')
        self.assertEqual(str(TypeSpecifier('_Bool')), '_Bool')
        self.assertEqual(str(TypeSpecifier('_Complex')), '_Complex')

    def test_size(self):
        self.assertEqual(str(TypeSpecifier('int', size='long')), 'long int')
        self.assertEqual(str(TypeSpecifier('int', size='long long')),
                         'long long int')
        self.assertEqual(str(TypeSpecifier('int', size='short')), 'short int')

    def test_sign(self):
        self.assertEqual(str(TypeSpecifier('int', sign='signed')),
                         'signed int')
        self.assertEqual(str(TypeSpecifier('int', sign='unsigned')),
                         'unsigned int')
        self.assertEqual(str(TypeSpecifier('char', sign='signed')),
                         'signed char')
        self.assertEqual(str(TypeSpecifier('char', sign='unsigned')),
                         'unsigned char')
        self.assertEqual(str(TypeSpecifier('_Complex', sign='signed')),
                         'signed _Complex')
        self.assertEqual(str(TypeSpecifier('_Complex', sign='unsigned')),
                         'unsigned _Complex')

    def test_qualifiers(self):
        self.assertEqual(str(TypeSpecifier('int', qualifiers={'const'})),
                         'const int')
        self.assertEqual(str(TypeSpecifier('int', qualifiers={'restrict'})),
                         'restrict int')
        self.assertEqual(str(TypeSpecifier('int', qualifiers={'volatile'})),
                         'volatile int')
        self.assertEqual(str(TypeSpecifier('int', qualifiers={'_Atomic'})),
                         '_Atomic int')
        self.assertEqual(str(TypeSpecifier('int', qualifiers={'const', 'volatile'})),
                         'const volatile int')

    def test_specifiers_qualifiers(self):
        self.assertEqual(str(TypeSpecifier('int', size='long', sign='unsigned',
                                           qualifiers={'const'})),
                         'const long unsigned int')
    def test_typedef(self):
        self.assertEqual(str(TypeSpecifier('u32')), 'u32')

    def test_tagged_type(self):
        self.assertEqual(str(TypeSpecifier('struct point')), 'struct point')
        self.assertEqual(str(TypeSpecifier('union value')), 'union value')
        self.assertEqual(str(TypeSpecifier('enum color')), 'enum color')

    def test_pointer(self):
        self.assertEqual(str(PointerType(TypeSpecifier('int'))), 'int *')
        self.assertEqual(str(PointerType(TypeSpecifier('int'), qualifiers={'const'})),
                         'int * const')

        self.assertEqual(str(PointerType(TypeSpecifier('struct point'))),
                         'struct point *')

        self.assertEqual(str(PointerType(PointerType(TypeSpecifier('int')))),
                         'int **')

        self.assertEqual(str(PointerType(PointerType(TypeSpecifier('int'),
                                                     qualifiers={'const'}))),
                         'int * const *')

    def test_array(self):
        self.assertEqual(str(ArrayType(TypeSpecifier('int'), None)),
                         'int []')
        self.assertEqual(str(ArrayType(TypeSpecifier('int'), 2)),
                         'int [2]')
        self.assertEqual(str(ArrayType(ArrayType(TypeSpecifier('int'), 3), 2)),
                         'int [2][3]')
        self.assertEqual(str(ArrayType(ArrayType(ArrayType(TypeSpecifier('int'), 4), 3), 2)),
                         'int [2][3][4]')

    def test_array_of_pointers(self):
        self.assertEqual(str(ArrayType(ArrayType(PointerType(TypeSpecifier('int')), 3), 2)),
                         'int *[2][3]')

    def test_pointer_to_array(self):
        self.assertEqual(str(PointerType(ArrayType(TypeSpecifier('int'), 2))),
                         'int (*)[2]')
        self.assertEqual(parse_type_name('int (*)[2][3]'),
                         PointerType(ArrayType(ArrayType(TypeSpecifier('int'), 3), 2)))

    def test_pointer_to_pointer_to_array(self):
        self.assertEqual(str(PointerType(PointerType(ArrayType(TypeSpecifier('int'), 2)))),
                         'int (**)[2]')

    def test_pointer_to_array_of_pointers(self):
        self.assertEqual(str(PointerType(ArrayType(PointerType(TypeSpecifier('int')), 2))),
                         'int *(*)[2]')

    def test_array_of_pointers_to_array(self):
        self.assertEqual(str(ArrayType(PointerType(ArrayType(TypeSpecifier('int'), 3)), 2)),
                         'int (*[2])[3]')
