import unittest
from drgn.typename import (
    parse_type_name,
    ArrayTypeName,
    BasicTypeName,
    EnumTypeName,
    FunctionTypeName,
    PointerTypeName,
    StructTypeName,
    TypedefTypeName,
    TypeName,
    UnionTypeName,
    VoidTypeName,
)


# TODO: complex types


def type_name_eq(self, other):
    return (isinstance(other, self.__class__) and
            self.__dict__ == other.__dict__)


class TestParseTypeName(unittest.TestCase):
    def setUp(self):
        TypeName.__eq__ = type_name_eq

    def tearDown(self):
        del TypeName.__eq__

    def test_empty(self):
        self.assertRaises(ValueError, parse_type_name, '')
        self.assertRaises(ValueError, parse_type_name, '  ')

    def test_invalid_character(self):
        self.assertRaises(ValueError, parse_type_name, '`')

    def test_void(self):
        self.assertEqual(parse_type_name('void'), VoidTypeName())

    def test_basic_types(self):
        self.assertEqual(parse_type_name('char'), BasicTypeName('char'))
        self.assertEqual(parse_type_name('int'), BasicTypeName('int'))
        self.assertEqual(parse_type_name('float'), BasicTypeName('float'))
        self.assertEqual(parse_type_name('double'), BasicTypeName('double'))
        self.assertEqual(parse_type_name('_Bool'), BasicTypeName('_Bool'))

    def test_size(self):
        self.assertEqual(parse_type_name('long int'), BasicTypeName('long'))
        self.assertEqual(parse_type_name('long'), BasicTypeName('long'))
        self.assertEqual(parse_type_name('int long'), BasicTypeName('long'))

        self.assertEqual(parse_type_name('long long int'),
                         BasicTypeName('long long'))
        self.assertEqual(parse_type_name('long long'),
                         BasicTypeName('long long'))
        self.assertEqual(parse_type_name('int long long'),
                         BasicTypeName('long long'))
        self.assertEqual(parse_type_name('long int long'),
                         BasicTypeName('long long'))

        self.assertEqual(parse_type_name('short int'), BasicTypeName('short'))
        self.assertEqual(parse_type_name('short'), BasicTypeName('short'))
        self.assertEqual(parse_type_name('int short'), BasicTypeName('short'))

        self.assertEqual(parse_type_name('long double'),
                         BasicTypeName('long double'))
        self.assertEqual(parse_type_name('double long'),
                         BasicTypeName('long double'))

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
        self.assertEqual(parse_type_name('signed int'), BasicTypeName('int'))
        self.assertEqual(parse_type_name('signed'), BasicTypeName('int'))
        self.assertEqual(parse_type_name('int signed'), BasicTypeName('int'))

        self.assertEqual(parse_type_name('unsigned'),
                         BasicTypeName('unsigned int'))
        self.assertEqual(parse_type_name('unsigned int'),
                         BasicTypeName('unsigned int'))
        self.assertEqual(parse_type_name('unsigned'),
                         BasicTypeName('unsigned int'))
        self.assertEqual(parse_type_name('int unsigned'),
                         BasicTypeName('unsigned int'))

        self.assertEqual(parse_type_name('signed char'),
                         BasicTypeName('signed char'))
        self.assertEqual(parse_type_name('char signed'),
                         BasicTypeName('signed char'))

        self.assertEqual(parse_type_name('unsigned char'),
                         BasicTypeName('unsigned char'))
        self.assertEqual(parse_type_name('char unsigned'),
                         BasicTypeName('unsigned char'))

        self.assertRaises(ValueError, parse_type_name, 'signed unsigned int')
        self.assertRaises(ValueError, parse_type_name, 'signed _Bool')
        self.assertRaises(ValueError, parse_type_name, '_Bool signed')

    def test_qualifiers(self):
        self.assertEqual(parse_type_name('const int'),
                         BasicTypeName('int', qualifiers=frozenset({'const'})))
        self.assertEqual(parse_type_name('restrict int'),
                         BasicTypeName('int', qualifiers=frozenset({'restrict'})))
        self.assertEqual(parse_type_name('volatile int'),
                         BasicTypeName('int', qualifiers=frozenset({'volatile'})))
        self.assertEqual(parse_type_name('_Atomic int'),
                         BasicTypeName('int', qualifiers=frozenset({'_Atomic'})))
        self.assertEqual(parse_type_name('const volatile int'),
                         BasicTypeName('int', qualifiers=frozenset({'const', 'volatile'})))
        self.assertEqual(parse_type_name('const const int'),
                         BasicTypeName('int', qualifiers=frozenset({'const'})))

    def test_specifiers_qualifiers(self):
        self.assertEqual(parse_type_name('long const int unsigned'),
                         BasicTypeName('unsigned long',
                                       qualifiers=frozenset({'const'})))

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
                         PointerTypeName(BasicTypeName('int')))
        self.assertEqual(parse_type_name('int * const'),
                         PointerTypeName(BasicTypeName('int'),
                                         qualifiers=frozenset({'const'})))

        self.assertEqual(parse_type_name('struct point *'),
                         PointerTypeName(StructTypeName('point')))

        self.assertEqual(parse_type_name('int **'),
                         PointerTypeName(PointerTypeName(BasicTypeName('int'))))

        self.assertEqual(parse_type_name('int *((*))'),
                         PointerTypeName(PointerTypeName(BasicTypeName('int'))))

        self.assertEqual(parse_type_name('int * const *'),
                         PointerTypeName(PointerTypeName(BasicTypeName('int'),
                                                         qualifiers=frozenset({'const'}))))

    def test_array(self):
        self.assertEqual(parse_type_name('int []'),
                         ArrayTypeName(BasicTypeName('int'), None))
        self.assertEqual(parse_type_name('int [2]'),
                         ArrayTypeName(BasicTypeName('int'), 2))
        self.assertEqual(parse_type_name('int [0x10]'),
                         ArrayTypeName(BasicTypeName('int'), 16))
        self.assertEqual(parse_type_name('int [010]'),
                         ArrayTypeName(BasicTypeName('int'), 8))
        self.assertEqual(parse_type_name('int [2][3]'),
                         ArrayTypeName(ArrayTypeName(BasicTypeName('int'), 3), 2))
        self.assertEqual(parse_type_name('int [2][3][4]'),
                         ArrayTypeName(ArrayTypeName(ArrayTypeName(BasicTypeName('int'), 4), 3), 2))

    def test_array_of_pointers(self):
        self.assertEqual(parse_type_name('int *[2][3]'),
                         ArrayTypeName(ArrayTypeName(PointerTypeName(BasicTypeName('int')), 3), 2))

    def test_pointer_to_array(self):
        self.assertEqual(parse_type_name('int (*)[2]'),
                         PointerTypeName(ArrayTypeName(BasicTypeName('int'), 2)))
        self.assertEqual(parse_type_name('int (*)[2][3]'),
                         PointerTypeName(ArrayTypeName(ArrayTypeName(BasicTypeName('int'), 3), 2)))

    def test_pointer_to_pointer_to_array(self):
        self.assertEqual(parse_type_name('int (**)[2]'),
                         PointerTypeName(PointerTypeName(ArrayTypeName(BasicTypeName('int'), 2))))

    def test_pointer_to_array_of_pointers(self):
        self.assertEqual(parse_type_name('int *(*)[2]'),
                         PointerTypeName(ArrayTypeName(PointerTypeName(BasicTypeName('int')), 2)))
        self.assertEqual(parse_type_name('int *((*)[2])'),
                         PointerTypeName(ArrayTypeName(PointerTypeName(BasicTypeName('int')), 2)))

    def test_array_of_pointers_to_array(self):
        self.assertEqual(parse_type_name('int (*[2])[3]'),
                         ArrayTypeName(PointerTypeName(ArrayTypeName(BasicTypeName('int'), 3)), 2))


class TestTypeStr(unittest.TestCase):
    def test_void(self):
        self.assertEqual(str(BasicTypeName('void')), 'void')

    def test_basic_types(self):
        self.assertEqual(str(BasicTypeName('char')), 'char')
        self.assertEqual(str(BasicTypeName('int')), 'int')
        self.assertEqual(str(BasicTypeName('float')), 'float')
        self.assertEqual(str(BasicTypeName('double')), 'double')
        self.assertEqual(str(BasicTypeName('_Bool')), '_Bool')

    def test_size(self):
        self.assertEqual(str(BasicTypeName('long')), 'long')
        self.assertEqual(str(BasicTypeName('long long')), 'long long')
        self.assertEqual(str(BasicTypeName('short')), 'short')
        self.assertEqual(str(BasicTypeName('long double')), 'long double')

    def test_sign(self):
        self.assertEqual(str(BasicTypeName('unsigned int')), 'unsigned int')
        self.assertEqual(str(BasicTypeName('signed char')), 'signed char')
        self.assertEqual(str(BasicTypeName('unsigned char')), 'unsigned char')

    def test_qualifiers(self):
        self.assertEqual(str(BasicTypeName('int', qualifiers=frozenset({'const'}))),
                         'const int')
        self.assertEqual(str(BasicTypeName('int', qualifiers=frozenset({'restrict'}))),
                         'restrict int')
        self.assertEqual(str(BasicTypeName('int', qualifiers=frozenset({'volatile'}))),
                         'volatile int')
        self.assertEqual(str(BasicTypeName('int', qualifiers=frozenset({'_Atomic'}))),
                         '_Atomic int')
        self.assertEqual(str(BasicTypeName('int', qualifiers=frozenset({'const', 'volatile'}))),
                         'const volatile int')

    def test_specifiers_qualifiers(self):
        self.assertEqual(str(BasicTypeName('unsigned long',
                                      qualifiers=frozenset({'const'}))),
                         'const unsigned long')

    def test_typedef(self):
        self.assertEqual(str(TypedefTypeName('u32')), 'u32')

    def test_tagged_type(self):
        self.assertEqual(str(StructTypeName('point')), 'struct point')
        self.assertEqual(str(UnionTypeName('value')), 'union value')
        self.assertEqual(str(EnumTypeName('color')), 'enum color')

        self.assertEqual(str(StructTypeName(None)), 'struct')
        self.assertEqual(str(UnionTypeName(None)), 'union')
        self.assertEqual(str(EnumTypeName(None)), 'enum')

    def test_pointer(self):
        self.assertEqual(str(PointerTypeName(BasicTypeName('int'))), 'int *')
        self.assertEqual(str(PointerTypeName(BasicTypeName('int'), qualifiers=frozenset({'const'}))),
                         'int * const')

        self.assertEqual(str(PointerTypeName(BasicTypeName('struct point'))),
                         'struct point *')

        self.assertEqual(str(PointerTypeName(PointerTypeName(BasicTypeName('int')))),
                         'int **')

        self.assertEqual(str(PointerTypeName(PointerTypeName(BasicTypeName('int'),
                                                             qualifiers=frozenset({'const'})))),
                         'int * const *')

    def test_array(self):
        self.assertEqual(str(ArrayTypeName(BasicTypeName('int'), None)),
                         'int []')
        self.assertEqual(str(ArrayTypeName(BasicTypeName('int'), 2)),
                         'int [2]')
        self.assertEqual(str(ArrayTypeName(ArrayTypeName(BasicTypeName('int'), 3), 2)),
                         'int [2][3]')
        self.assertEqual(str(ArrayTypeName(ArrayTypeName(ArrayTypeName(BasicTypeName('int'), 4), 3), 2)),
                         'int [2][3][4]')

    def test_array_of_pointers(self):
        self.assertEqual(str(ArrayTypeName(ArrayTypeName(PointerTypeName(BasicTypeName('int')), 3), 2)),
                         'int *[2][3]')

    def test_pointer_to_array(self):
        self.assertEqual(str(PointerTypeName(ArrayTypeName(BasicTypeName('int'), 2))),
                         'int (*)[2]')

    def test_pointer_to_pointer_to_array(self):
        self.assertEqual(str(PointerTypeName(PointerTypeName(ArrayTypeName(BasicTypeName('int'), 2)))),
                         'int (**)[2]')

    def test_pointer_to_array_of_pointers(self):
        self.assertEqual(str(PointerTypeName(ArrayTypeName(PointerTypeName(BasicTypeName('int')), 2))),
                         'int *(*)[2]')

    def test_array_of_pointers_to_array(self):
        self.assertEqual(str(ArrayTypeName(PointerTypeName(ArrayTypeName(BasicTypeName('int'), 3)), 2)),
                         'int (*[2])[3]')

    def test_pointer_to_function(self):
        self.assertEqual(str(PointerTypeName(FunctionTypeName(BasicTypeName('int'), [(BasicTypeName('int'), None)]))),
                         'int (*)(int)')
        self.assertEqual(str(PointerTypeName(FunctionTypeName(BasicTypeName('int'), [(BasicTypeName('int'), 'x')]))),
                         'int (*)(int x)')
        self.assertEqual(str(PointerTypeName(FunctionTypeName(BasicTypeName('int'), [(BasicTypeName('int'), None), (BasicTypeName('float'), None)]))),
                         'int (*)(int, float)')

    def test_pointer_to_function_returning_pointer(self):
        self.assertEqual(str(PointerTypeName(FunctionTypeName(PointerTypeName(BasicTypeName('int')), [(BasicTypeName('int'), None)]))),
                         'int *(*)(int)')
        self.assertEqual(str(PointerTypeName(FunctionTypeName(PointerTypeName(BasicTypeName('int')), [(PointerTypeName(BasicTypeName('int')), None)]))),
                         'int *(*)(int *)')

    def test_pointer_to_function_returning_pointer_to_const(self):
        self.assertEqual(str(PointerTypeName(FunctionTypeName(PointerTypeName(BasicTypeName('int', qualifiers=frozenset({'const'}))), [(BasicTypeName('int'), None)]))),
                         'const int *(*)(int)')

    def test_pointer_to_function_returning_const_pointer(self):
        self.assertEqual(str(PointerTypeName(FunctionTypeName(PointerTypeName(BasicTypeName('int'), qualifiers=frozenset({'const'})), [(BasicTypeName('int'), None)]))),
                         'int * const (*)(int)')

    def test_const_pointer_to_function_returning_pointer(self):
        self.assertEqual(str(PointerTypeName(FunctionTypeName(PointerTypeName(BasicTypeName('int')), [(BasicTypeName('int'), None)]), qualifiers=frozenset({'const'}))),
                         'int *(* const)(int)')

    def test_array_of_pointers_to_functions(self):
        self.assertEqual(str(ArrayTypeName(PointerTypeName(FunctionTypeName(BasicTypeName('int'), [(BasicTypeName('int'), None)])), 4)),
                         'int (*[4])(int)')

    def test_array_of_const_pointers_to_functions(self):
        self.assertEqual(str(ArrayTypeName(PointerTypeName(FunctionTypeName(BasicTypeName('int'), [(BasicTypeName('int'), None)]), qualifiers=frozenset({'const'})), None)),
                         'int (* const [])(int)')

    def test_pointer_to_variadic_function(self):
        self.assertEqual(str(PointerTypeName(FunctionTypeName(BasicTypeName('int'), [(BasicTypeName('int'), None)], variadic=True))),
                         'int (*)(int, ...)')

    def test_pointer_to_function_with_no_parameter_specification(self):
        self.assertEqual(str(PointerTypeName(FunctionTypeName(BasicTypeName('int'), None))),
                         'int (*)()')

    def test_pointer_to_function_with_no_parameters(self):
        self.assertEqual(str(PointerTypeName(FunctionTypeName(BasicTypeName('int'), []))),
                         'int (*)(void)')
