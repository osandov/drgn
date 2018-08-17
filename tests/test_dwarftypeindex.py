import os.path
from unittest.mock import Mock

from drgn.internal.dwarf import (
    Die,
    DieAttrib,
    DwarfAttribNotFoundError,
    DW_AT,
    DW_FORM,
    DW_TAG,
)
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
    anonymous_color_type,
    anonymous_point_type,
    color_type,
    line_segment_type,
    pointer_size,
    point_type,
    TypeTestCase,
)


class MockDwarfIndex:
    def __init__(self, dies):
        self._dies = dies
        self.address_size = 8

    def find(self, name, tag=0):
        result = []
        for die in self._dies:
            try:
                if (tag == 0 or die.tag == tag) and die.name() == name:
                    result.append(die)
            except DwarfAttribNotFoundError:
                continue
        if not result:
            raise ValueError()
        return result


class TestDwarfTypeIndex(TypeTestCase):
    def setUp(self):
        super().setUp()
        self.dies = []
        self.dwarf_index = MockDwarfIndex(self.dies)

        self.type_index = DwarfTypeIndex(self.dwarf_index)
        self.cu = Mock()
        self.cu.die = self.dies.__getitem__

    def tearDown(self):
        super().tearDown()

    def assertFromDwarfType(self, offset, type_):
        self.assertEqual(self.type_index._from_dwarf_type(self.cu.die(offset)),
                         type_)

    def test_void(self):
        self.assertEqual(self.type_index.find('void'), VoidType())
        self.assertEqual(self.type_index.find('const void'),
                         VoidType({'const'}))

    def test_char(self):
        self.dies[:] = [
            # char
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x01'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x06'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'char'),
            ]),
            # signed char
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x01'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x06'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'signed char'),
            ]),
            # unsigned char
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x01'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x08'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'unsigned char'),
            ]),
        ]

        self.assertFromDwarfType(0, IntType('char', 1, True))
        self.assertFromDwarfType(1, IntType('signed char', 1, True))
        self.assertFromDwarfType(2, IntType('unsigned char', 1, False))

        self.assertEqual(self.type_index.find('char'),
                         IntType('char', 1, True))

    def test_short(self):
        self.dies[:] = [
            # short
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x02'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'short'),
            ]),
            # signed short
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x02'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'signed short'),
            ]),
            # unsigned short
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x02'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x07'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'unsigned short'),
            ]),
        ]

        self.assertFromDwarfType(0, IntType('short', 2, True))
        self.assertFromDwarfType(1, IntType('short', 2, True))
        self.assertFromDwarfType(2, IntType('unsigned short', 2, False))

    def test_int(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # signed int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'signed int'),
            ]),
            # unsigned int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x07'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'unsigned int'),
            ]),
        ]

        self.assertFromDwarfType(0, IntType('int', 4, True))
        self.assertFromDwarfType(1, IntType('int', 4, True))
        self.assertFromDwarfType(2, IntType('unsigned int', 4, False))

    def test_long(self):
        self.dies[:] = [
            # long
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'long'),
            ]),
            # signed long
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'signed long'),
            ]),
            # unsigned long
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x07'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'unsigned long'),
            ]),
        ]

        self.assertFromDwarfType(0, IntType('long', 8, True))
        self.assertFromDwarfType(1, IntType('long', 8, True))
        self.assertFromDwarfType(2, IntType('unsigned long', 8, False))

    def test_long_long(self):
        self.dies[:] = [
            # long long
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'long long'),
            ]),
            # signed long long
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'signed long long'),
            ]),
            # unsigned long long
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x07'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'unsigned long long'),
            ]),
        ]

        self.assertFromDwarfType(0, IntType('long long', 8, True))
        self.assertFromDwarfType(1, IntType('long long', 8, True))
        self.assertFromDwarfType(2, IntType('unsigned long long', 8, False))

    def test_float(self):
        self.dies[:] = [
            # float
            Die(None, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'float'),
            ]),
            # double
            Die(None, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'double'),
            ]),
            # long double
            Die(None, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x10'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'long double'),
            ]),
            # double long
            Die(None, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x10'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'double long'),
            ]),
        ]

        self.assertFromDwarfType(0, FloatType('float', 4))
        self.assertFromDwarfType(1, FloatType('double', 8))
        self.assertFromDwarfType(2, FloatType('long double', 16))
        self.assertFromDwarfType(3, FloatType('long double', 16))

    def test_bool(self):
        self.dies[:] = [
            # _Bool
            Die(None, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x01'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x02'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'_Bool'),
            ]),
        ]
        self.assertFromDwarfType(0, BoolType('_Bool', 1))

    def test_qualifiers(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # const int
            Die(self.cu, DW_TAG.const_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ]),
            # volatile int
            Die(self.cu, DW_TAG.volatile_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ]),
            # volatile const int
            Die(self.cu, DW_TAG.volatile_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 1),
            ]),
            # _Atomic volatile const int
            Die(self.cu, DW_TAG.atomic_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 3),
            ]),
            # restrict int
            Die(self.cu, DW_TAG.restrict_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ]),
            # const void
            Die(self.cu, DW_TAG.const_type, []),
        ]

        self.assertFromDwarfType(1, IntType('int', 4, True, {'const'}))
        self.assertFromDwarfType(2, IntType('int', 4, True, {'volatile'}))
        self.assertFromDwarfType(3, IntType('int', 4, True, {'const', 'volatile'}))
        self.assertFromDwarfType(4, IntType('int', 4, True, {'_Atomic', 'const', 'volatile'}))
        self.assertFromDwarfType(5, IntType('int', 4, True, {'restrict'}))
        self.assertFromDwarfType(6, VoidType({'const'}))

        self.assertEqual(self.type_index._from_dwarf_type(self.cu.die(1),
                                                          frozenset({'volatile'})),
                         IntType('int', 4, True, {'const', 'volatile'}))
        self.assertEqual(self.type_index._from_dwarf_type(self.cu.die(6),
                                                          frozenset({'volatile'})),
                         VoidType({'const', 'volatile'}))

    def test_typedef(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # const int
            Die(self.cu, DW_TAG.const_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ]),
            # typedef int INT
            Die(self.cu, DW_TAG.typedef, [
                DieAttrib(DW_AT.name, DW_FORM.string, b'INT'),
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ]),
            # const INT
            Die(self.cu, DW_TAG.const_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 2),
            ]),
            # typedef const int CINT
            Die(self.cu, DW_TAG.typedef, [
                DieAttrib(DW_AT.name, DW_FORM.string, b'CINT'),
                DieAttrib(DW_AT.type, DW_FORM.ref4, 1),
            ]),
        ]

        typedef_type = TypedefType('INT', IntType('int', 4, True))

        self.assertFromDwarfType(2, typedef_type)
        self.assertFromDwarfType(3, TypedefType('INT', IntType('int', 4, True), {'const'}))
        self.assertFromDwarfType(4, TypedefType('CINT', IntType('int', 4, True, {'const'})))

        self.assertEqual(self.type_index.find('INT'), typedef_type)

    def test_struct(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # struct point {
            #     int x, y;
            # };
            Die(self.cu, DW_TAG.structure_type, [
                DieAttrib(DW_AT.name, DW_FORM.string, b'point'),
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
            ], lambda: [
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'x'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'y'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x04'),
                ]),
            ]),
            # struct line_segment {
            #     struct point a, b;
            # };
            Die(self.cu, DW_TAG.structure_type, [
                DieAttrib(DW_AT.name, DW_FORM.string, b'line_segment'),
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x10'),
            ], lambda: [
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'a'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 1),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'b'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 1),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x08'),
                ]),
            ]),
            # struct {
            #     int x, y;
            # };
            Die(self.cu, DW_TAG.structure_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
            ], lambda: [
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'x'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'y'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x04'),
                ]),
            ]),
            # struct foo;
            Die(self.cu, DW_TAG.structure_type, [
                DieAttrib(DW_AT.name, DW_FORM.string, b'foo'),
                DieAttrib(DW_AT.declaration, DW_FORM.flag_present, 1),
            ]),
        ]

        self.assertFromDwarfType(1, point_type)
        self.assertFromDwarfType(2, line_segment_type)
        self.assertFromDwarfType(3, anonymous_point_type)
        self.assertFromDwarfType(4, StructType('foo', None, None))

        self.assertEqual(self.type_index.find('struct point'),
                         point_type)

    def test_bit_field(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # const int
            Die(self.cu, DW_TAG.const_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ]),
            # struct {
            #     int x : 4;
            #     const int y : 28;
            #     int z : 5;
            # };
            Die(self.cu, DW_TAG.structure_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
            ], lambda: [
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'x'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                    DieAttrib(DW_AT.bit_size, DW_FORM.data1, b'\x04'),
                    DieAttrib(DW_AT.bit_offset, DW_FORM.data1, b'\x1c'),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'y'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 1),
                    DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                    DieAttrib(DW_AT.bit_size, DW_FORM.data1, b'\x1c'),
                    DieAttrib(DW_AT.bit_offset, DW_FORM.data1, b'\x00'),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'z'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                    DieAttrib(DW_AT.bit_size, DW_FORM.data1, b'\x05'),
                    DieAttrib(DW_AT.bit_offset, DW_FORM.data1, b'\x1b'),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x04'),
                ]),
            ]),
        ]

        self.assertFromDwarfType(2, StructType(None, 8, [
            ('x', 0, lambda: BitFieldType(IntType('int', 4, True), 0, 4)),
            ('y', 0, lambda: BitFieldType(IntType('int', 4, True, {'const'}), 4, 28)),
            ('z', 4, lambda: BitFieldType(IntType('int', 4, True), 0, 5)),
        ]))

    def test_union(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # float
            Die(None, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'float'),
            ]),
            # union value {
            #    int i;
            #    float f;
            # };
            Die(self.cu, DW_TAG.union_type, [
                DieAttrib(DW_AT.name, DW_FORM.string, b'value'),
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
            ], lambda: [
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'i'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'f'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 1),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
            ]),
            # union foo;
            Die(self.cu, DW_TAG.union_type, [
                DieAttrib(DW_AT.name, DW_FORM.string, b'foo'),
                DieAttrib(DW_AT.declaration, DW_FORM.flag_present, 1),
            ]),
        ]

        value_type = UnionType('value', 4, [
            ('i', 0, lambda: IntType('int', 4, True)),
            ('f', 0, lambda: FloatType('float', 4)),
        ])

        self.assertFromDwarfType(2, value_type)
        self.assertFromDwarfType(3, UnionType('foo', None, None))

        self.assertEqual(self.type_index.find('union value'), value_type)

    def test_enum(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # unsigned int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x07'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'unsigned int'),
            ]),
            # enum color {
            #     RED,
            #     GREEN,
            #     BLUE,
            # };
            Die(self.cu, DW_TAG.enumeration_type, [
                DieAttrib(DW_AT.name, DW_FORM.string, b'color'),
                DieAttrib(DW_AT.type, DW_FORM.ref4, 1),
            ], lambda: [
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'RED'),
                    DieAttrib(DW_AT.const_value, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'GREEN'),
                    DieAttrib(DW_AT.const_value, DW_FORM.data1, b'\x01'),
                ]),
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'BLUE'),
                    DieAttrib(DW_AT.const_value, DW_FORM.data1, b'\x02'),
                ]),
            ]),
            # enum {
            #     RED = 0,
            #     GREEN = -1,
            #     BLUE = -2,
            # };
            Die(self.cu, DW_TAG.enumeration_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'RED'),
                    DieAttrib(DW_AT.const_value, DW_FORM.sdata, 0),
                ]),
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'GREEN'),
                    DieAttrib(DW_AT.const_value, DW_FORM.sdata, -1),
                ]),
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'BLUE'),
                    DieAttrib(DW_AT.const_value, DW_FORM.sdata, -2),
                ]),
            ]),
            # These two are the same as the two above, but without DW_AT_type,
            # like generated by GCC before 5.1.
            Die(self.cu, DW_TAG.enumeration_type, [
                DieAttrib(DW_AT.name, DW_FORM.string, b'color'),
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
            ], lambda: [
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'RED'),
                    DieAttrib(DW_AT.const_value, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'GREEN'),
                    DieAttrib(DW_AT.const_value, DW_FORM.data1, b'\x01'),
                ]),
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'BLUE'),
                    DieAttrib(DW_AT.const_value, DW_FORM.data1, b'\x02'),
                ]),
            ]),
            Die(self.cu, DW_TAG.enumeration_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
            ], lambda: [
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'RED'),
                    DieAttrib(DW_AT.const_value, DW_FORM.sdata, 0),
                ]),
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'GREEN'),
                    DieAttrib(DW_AT.const_value, DW_FORM.sdata, -1),
                ]),
                Die(self.cu, DW_TAG.enumerator, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'BLUE'),
                    DieAttrib(DW_AT.const_value, DW_FORM.sdata, -2),
                ]),
            ]),
            Die(self.cu, DW_TAG.enumeration_type, [
                DieAttrib(DW_AT.name, DW_FORM.string, b'foo'),
                DieAttrib(DW_AT.declaration, DW_FORM.flag_present, 1),
            ]),
        ]

        self.assertFromDwarfType(2, color_type)
        self.assertFromDwarfType(3, anonymous_color_type)
        self.assertFromDwarfType(4, EnumType('color', IntType('', 4, False), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ]))
        self.assertFromDwarfType(5, EnumType(None, IntType('', 4, True), [
            ('RED', 0),
            ('GREEN', -1),
            ('BLUE', -2)
        ]))
        self.assertFromDwarfType(6, EnumType('foo', None, None))

        self.assertEqual(self.type_index.find('enum color'), color_type)

    def test_pointer(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # const int
            Die(self.cu, DW_TAG.const_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ]),
            # int *
            Die(self.cu, DW_TAG.pointer_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ]),
            # int * const
            Die(self.cu, DW_TAG.const_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 2),
            ]),
            # void *
            Die(self.cu, DW_TAG.pointer_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x08'),
            ]),
        ]

        self.assertFromDwarfType(2, PointerType(8, IntType('int', 4, True)))
        self.assertFromDwarfType(3, PointerType(8, IntType('int', 4, True), {'const'}))
        self.assertFromDwarfType(4, PointerType(8, VoidType()))

        self.assertEqual(self.type_index.find('void *'), PointerType(8, VoidType()))

    def test_array(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # int [2]
            Die(self.cu, DW_TAG.array_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.subrange_type, [
                    DieAttrib(DW_AT.upper_bound, DW_FORM.data1, b'\x01'),
                ]),
            ]),
            # int [2][3]
            Die(self.cu, DW_TAG.array_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.subrange_type, [
                    DieAttrib(DW_AT.upper_bound, DW_FORM.data1, b'\x01'),
                ]),
                Die(self.cu, DW_TAG.subrange_type, [
                    DieAttrib(DW_AT.upper_bound, DW_FORM.data1, b'\x02'),
                ]),
            ]),
            # int [2][3][4]
            Die(self.cu, DW_TAG.array_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.subrange_type, [
                    DieAttrib(DW_AT.upper_bound, DW_FORM.data1, b'\x01'),
                ]),
                Die(self.cu, DW_TAG.subrange_type, [
                    DieAttrib(DW_AT.upper_bound, DW_FORM.data1, b'\x02'),
                ]),
                Die(self.cu, DW_TAG.subrange_type, [
                    DieAttrib(DW_AT.upper_bound, DW_FORM.data1, b'\x03'),
                ]),
            ]),
        ]

        self.assertFromDwarfType(1, ArrayType(IntType('int', 4, True), 2, 8))
        self.assertFromDwarfType(2, ArrayType(ArrayType(IntType('int', 4, True), 3, 8), 2, 8))
        self.assertFromDwarfType(3, ArrayType(ArrayType(ArrayType(IntType('int', 4, True), 4, 8), 3, 8), 2, 8))

    def test_flexible_or_zero_length_array(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # int [] or possibly int [0] if generated by GCC
            Die(self.cu, DW_TAG.array_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.subrange_type, []),
            ]),
            # int [0]
            Die(self.cu, DW_TAG.array_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.subrange_type, [
                    DieAttrib(DW_AT.count, DW_FORM.data1, b'\x00'),
                ]),
            ]),
            # struct {
            #     int foo[0];
            # };
            Die(self.cu, DW_TAG.structure_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x00'),
            ], lambda: [
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'foo'),
                    # Note that this is the ambiguous int [] or int [0] DIE.
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 1),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
            ]),
            # struct {
            #     int n;
            #     int foo[];
            # };
            Die(self.cu, DW_TAG.structure_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
            ], lambda: [
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'n'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'foo'),
                    # Note that this is the ambiguous int [] or int [0] DIE.
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 1),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x04'),
                ]),
            ]),
            # struct {
            #     int n;
            #     int foo[0];
            # };
            Die(self.cu, DW_TAG.structure_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
            ], lambda: [
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'n'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'foo'),
                    # This is the unambiguous int [0] DIE.
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 2),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x04'),
                ]),
            ]),
            # union {
            #     int n;
            #     int foo[0];
            # };
            Die(self.cu, DW_TAG.union_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
            ], lambda: [
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'n'),
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
                Die(self.cu, DW_TAG.member, [
                    DieAttrib(DW_AT.name, DW_FORM.string, b'foo'),
                    # Note that this is the ambiguous int [] or int [0] DIE.
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 1),
                    DieAttrib(DW_AT.data_member_location, DW_FORM.data1, b'\x00'),
                ]),
            ]),
            # int [][2]
            Die(self.cu, DW_TAG.array_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.subrange_type, []),
                Die(self.cu, DW_TAG.subrange_type, [
                    DieAttrib(DW_AT.upper_bound, DW_FORM.data1, b'\x01'),
                ]),
            ]),
            # int [2][0]
            Die(self.cu, DW_TAG.array_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.subrange_type, [
                    DieAttrib(DW_AT.upper_bound, DW_FORM.data1, b'\x01'),
                ]),
                Die(self.cu, DW_TAG.subrange_type, []),
            ]),
        ]

        self.assertFromDwarfType(1, ArrayType(IntType('int', 4, True), None, 8))
        self.assertFromDwarfType(2, ArrayType(IntType('int', 4, True), 0, 8))
        self.assertFromDwarfType(3, StructType(None, 0, [
            ('foo', 0, lambda: ArrayType(IntType('int', 4, True), 0, 8)),
        ]))
        self.assertFromDwarfType(4, StructType(None, 4, [
            ('n', 0, lambda: IntType('int', 4, True)),
            ('foo', 4, lambda: ArrayType(IntType('int', 4, True), None, 8)),
        ]))
        self.assertFromDwarfType(5, StructType(None, 4, [
            ('n', 0, lambda: IntType('int', 4, True)),
            ('foo', 4, lambda: ArrayType(IntType('int', 4, True), 0, 8)),
        ]))
        self.assertFromDwarfType(6, UnionType(None, 4, [
            ('n', 0, lambda: IntType('int', 4, True)),
            ('foo', 0, lambda: ArrayType(IntType('int', 4, True), 0, 8)),
        ]))
        self.assertFromDwarfType(7, ArrayType(ArrayType(IntType('int', 4, True), 2, 8), None, 8))
        self.assertFromDwarfType(8, ArrayType(ArrayType(IntType('int', 4, True), 0, 8), 2, 8))

        self.assertEqual(self.type_index.find('int []'),
                         ArrayType(IntType('int', 4, True), None, 8))
        self.assertEqual(self.type_index.find('int [0]'),
                         ArrayType(IntType('int', 4, True), 0, 8))

    def test_function(self):
        self.dies[:] = [
            # int
            Die(self.cu, DW_TAG.base_type, [
                DieAttrib(DW_AT.byte_size, DW_FORM.data1, b'\x04'),
                DieAttrib(DW_AT.encoding, DW_FORM.data1, b'\x05'),
                DieAttrib(DW_AT.name, DW_FORM.string, b'int'),
            ]),
            # int foo(int)
            Die(self.cu, DW_TAG.subroutine_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.formal_parameter, [
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                ]),
            ]),
            # int foo(int x)
            Die(self.cu, DW_TAG.subroutine_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.formal_parameter, [
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DieAttrib(DW_AT.name, DW_FORM.string, b'x'),
                ]),
            ]),
            # int foo(int, ...)
            Die(self.cu, DW_TAG.subroutine_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.formal_parameter, [
                    DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
                ]),
                Die(self.cu, DW_TAG.unspecified_parameters, []),
            ]),
            # int foo()
            Die(self.cu, DW_TAG.subroutine_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ], lambda: [
                Die(self.cu, DW_TAG.unspecified_parameters, []),
            ]),
            # int foo(void)
            Die(self.cu, DW_TAG.subroutine_type, [
                DieAttrib(DW_AT.type, DW_FORM.ref4, 0),
            ]),
        ]

        self.assertFromDwarfType(1, FunctionType(8, IntType('int', 4, True), [(IntType('int', 4, True), None)]))
        self.assertFromDwarfType(2, FunctionType(8, IntType('int', 4, True), [(IntType('int', 4, True), 'x')]))
        self.assertFromDwarfType(3, FunctionType(8, IntType('int', 4, True), [(IntType('int', 4, True), None)], variadic=True))
        self.assertFromDwarfType(4, FunctionType(8, IntType('int', 4, True), None))
        self.assertFromDwarfType(5, FunctionType(8, IntType('int', 4, True), []))
