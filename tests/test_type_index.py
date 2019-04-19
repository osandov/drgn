import itertools
import unittest

from drgn import (
    array_type,
    bool_type,
    enum_type,
    float_type,
    int_type,
    pointer_type,
    Qualifiers,
    struct_type,
    typedef_type,
    union_type,
)
from drgn.internal.mock import MockType
from tests.libdrgn import MockTypeIndex


point_type = struct_type('point', 8, (
    (int_type('int', 4, True), 'x', 0),
    (int_type('int', 4, True), 'y', 32),
))
line_segment_type = struct_type('line_segment', 16, (
    (point_type, 'a'),
    (point_type, 'b', 64),
))
option_type = union_type('option', 4, (
    (int_type('int', 4, True), 'i'),
    (float_type('float', 4), 'f'),
))
color_type = enum_type('color', int_type('unsigned int', 4, False),
                       (('RED', 0), ('GREEN', 1), ('BLUE', 2)))
pid_type = typedef_type('pid_t', int_type('int', 4, True))


class TestTypeIndex(unittest.TestCase):
    def test_c_types(self):
        def spellings(tokens, num_optional=0):
            for i in range(len(tokens) - num_optional, len(tokens) + 1):
                for perm in itertools.permutations(tokens[:i]):
                    yield ' '.join(perm)

        for word_size in [8, 4]:
            tindex = MockTypeIndex(word_size, 'little', [])
            self.assertEqual(tindex.find('_Bool'), bool_type('_Bool', 1))
            self.assertEqual(tindex.find('char'), int_type('char', 1, True))
            for spelling in spellings(['signed', 'char']):
                self.assertEqual(tindex.find(spelling),
                                 int_type('signed char', 1, True))
            for spelling in spellings(['unsigned', 'char']):
                self.assertEqual(tindex.find(spelling),
                                 int_type('unsigned char', 1, False))
            for spelling in spellings(['short', 'signed', 'int'], 2):
                self.assertEqual(tindex.find(spelling),
                                 int_type('short', 2, True))
            for spelling in spellings(['short', 'unsigned', 'int'], 1):
                self.assertEqual(tindex.find(spelling),
                                 int_type('unsigned short', 2, False))
            for spelling in spellings(['int', 'signed'], 1):
                self.assertEqual(tindex.find(spelling),
                                 int_type('int', 4, True))
            for spelling in spellings(['unsigned', 'int']):
                self.assertEqual(tindex.find(spelling),
                                 int_type('unsigned int', 4, False))
            for spelling in spellings(['long', 'signed', 'int'], 2):
                self.assertEqual(tindex.find(spelling),
                                 int_type('long', word_size, True))
            for spelling in spellings(['long', 'unsigned', 'int'], 1):
                self.assertEqual(tindex.find(spelling),
                                 int_type('unsigned long', word_size, False))
            for spelling in spellings(['long', 'long', 'signed', 'int'], 2):
                self.assertEqual(tindex.find(spelling),
                                 int_type('long long', 8, True))
            for spelling in spellings(['long', 'long', 'unsigned', 'int'], 1):
                self.assertEqual(tindex.find(spelling),
                                 int_type('unsigned long long', 8, False))
            self.assertEqual(tindex.find('float'),
                             float_type('float', 4))
            self.assertEqual(tindex.find('double'),
                             float_type('double', 8))
            for spelling in spellings(['long', 'double']):
                self.assertEqual(tindex.find(spelling),
                                 float_type('long double', 16))
            self.assertEqual(tindex.find('size_t'),
                             typedef_type('size_t',
                                          int_type('unsigned long', word_size,
                                                   False)))
            self.assertEqual(tindex.find('ptrdiff_t'),
                             typedef_type('ptrdiff_t',
                                          int_type('long', word_size, True)))

    def test_tagged_type(self):
        tindex = MockTypeIndex(8, 'little', [
            MockType(point_type),
            MockType(option_type),
            MockType(color_type),
        ])

        self.assertEqual(tindex.find('struct point'), point_type)
        self.assertEqual(tindex.find('union option'), option_type)
        self.assertEqual(tindex.find('enum color'), color_type)

    def test_typedef(self):
        tindex = MockTypeIndex(8, 'little', [MockType(pid_type)])
        self.assertEqual(tindex.find('pid_t'), pid_type)

    def test_pointer(self):
        tindex = MockTypeIndex(8, 'little', [])
        self.assertEqual(tindex.find('int *'),
                         pointer_type(8, int_type('int', 4, True)))
        self.assertEqual(tindex.find('const int *'),
                         pointer_type(8, int_type('int', 4, True, Qualifiers.CONST)))
        self.assertEqual(tindex.find('int * const'),
                         pointer_type(8, int_type('int', 4, True), Qualifiers.CONST))
        self.assertEqual(tindex.find('int **'),
                         pointer_type(8, pointer_type(8, int_type('int', 4, True))))
        self.assertEqual(tindex.find('int *((*))'),
                         pointer_type(8, pointer_type(8, int_type('int', 4, True))))
        self.assertEqual(tindex.find('int * const *'),
                         pointer_type(8, pointer_type(8, int_type('int', 4, True), Qualifiers.CONST)))

    def test_array(self):
        tindex = MockTypeIndex(8, 'little', [])
        self.assertEqual(tindex.find('int []'),
                         array_type(None, int_type('int', 4, True)))
        self.assertEqual(tindex.find('int [20]'),
                         array_type(20, int_type('int', 4, True)))
        self.assertEqual(tindex.find('int [0x20]'),
                         array_type(32, int_type('int', 4, True)))
        self.assertEqual(tindex.find('int [020]'),
                         array_type(16, int_type('int', 4, True)))
        self.assertEqual(tindex.find('int [2][3]'),
                         array_type(2, array_type(3, int_type('int', 4, True))))
        self.assertEqual(tindex.find('int [2][3][4]'),
                         array_type(2, array_type(3, array_type(4, int_type('int', 4, True)))))

    def test_array_of_pointers(self):
        tindex = MockTypeIndex(8, 'little', [])
        self.assertEqual(tindex.find('int *[2][3]'),
                         array_type(2, array_type(3, pointer_type(8, int_type('int', 4, True)))))

    def test_pointer_to_array(self):
        tindex = MockTypeIndex(8, 'little', [])
        self.assertEqual(tindex.find('int (*)[2]'),
                         pointer_type(8, array_type(2, int_type('int', 4, True))))
        self.assertEqual(tindex.find('int (*)[2][3]'),
                         pointer_type(8, array_type(2, array_type(3, int_type('int', 4, True)))))

    def test_pointer_to_pointer_to_array(self):
        tindex = MockTypeIndex(8, 'little', [])
        self.assertEqual(tindex.find('int (**)[2]'),
                         pointer_type(8, pointer_type(8, array_type(2, int_type('int', 4, True)))))

    def test_pointer_to_array_of_pointers(self):
        tindex = MockTypeIndex(8, 'little', [])
        self.assertEqual(tindex.find('int *(*)[2]'),
                         pointer_type(8, array_type(2, pointer_type(8, int_type('int', 4, True)))))
        self.assertEqual(tindex.find('int *((*)[2])'),
                         pointer_type(8, array_type(2, pointer_type(8, int_type('int', 4, True)))))

    def test_array_of_pointers_to_array(self):
        tindex = MockTypeIndex(8, 'little', [])
        self.assertEqual(tindex.find('int (*[2])[3]'),
                         array_type(2, pointer_type(8, array_type(3, int_type('int', 4, True)))))
