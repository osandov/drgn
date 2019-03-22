import copy
import unittest

from drgn import (
    enum_type,
    FileFormatError,
    function_type,
    int_type,
    Type,
)
from tests.dwarf import DW_AT, DW_ATE, DW_FORM, DW_TAG
from tests.dwarfwriter import compile_dwarf, DwarfDie, DwarfAttrib
from tests.libdrgn import (
    DwarfIndex,
    DwarfTypeIndex,
    DwarfObjectIndex,
    FindObjectFlags,
    PartialObject,
)
import tests.libelf as libelf
from tests.test_dwarf_type_index import int_die, unsigned_int_die
from tests.test_type_index import color_type


class TestDwarfObjectIndex(unittest.TestCase):
    @staticmethod
    def object_index(dies):
        dindex = DwarfIndex()
        dindex.open(libelf.elf_memory(compile_dwarf(dies), mutable=True))
        dindex.update()
        dtindex = DwarfTypeIndex(dindex)
        return DwarfObjectIndex(dtindex)

    def test_constant(self):
        dies = [
            int_die,
            DwarfDie(
                DW_TAG.enumeration_type,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, 'color'),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DwarfAttrib(DW_AT.byte_size, DW_FORM.data1, 4),
                ],
                [
                    DwarfDie(
                        DW_TAG.enumerator,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, 'RED'),
                            DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 0),
                        ]
                    ),
                    DwarfDie(
                        DW_TAG.enumerator,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, 'GREEN'),
                            DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 1),
                        ]
                    ),
                    DwarfDie(
                        DW_TAG.enumerator,
                        [
                            DwarfAttrib(DW_AT.name, DW_FORM.string, 'BLUE'),
                            DwarfAttrib(DW_AT.const_value, DW_FORM.data1, 2),
                        ]
                    ),
                ]
            ),
            DwarfDie(
                DW_TAG.variable,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, 'RED'),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DwarfAttrib(DW_AT.location, DW_FORM.exprloc,
                                b'\x03\x04\x03\x02\x01\xff\xff\xff\xff'),
                ],
            ),
        ]

        type_ = enum_type('color', int_type('int', 4, True),
                          [('RED', 0), ('GREEN', 1), ('BLUE', 2)])
        oindex = self.object_index(dies)
        self.assertEqual(oindex.find('BLUE'),
                         PartialObject(type=type_, is_enumerator=True, value=2))

        dies[0] = unsigned_int_die
        type_ = enum_type('color', int_type('unsigned int', 4, False),
                          [('RED', 0), ('GREEN', 1), ('BLUE', 2)])
        oindex = self.object_index(dies)
        self.assertEqual(oindex.find('GREEN'),
                         PartialObject(type=type_, is_enumerator=True, value=1))

        del dies[1].attribs[0]
        type_ = enum_type(None, int_type('unsigned int', 4, False),
                          [('RED', 0), ('GREEN', 1), ('BLUE', 2)])
        oindex = self.object_index(dies)
        self.assertEqual(oindex.find('RED', flags=FindObjectFlags.CONSTANT),
                         PartialObject(type=type_, is_enumerator=True, value=0))

    def test_function(self):
        dies = [
            int_die,
            DwarfDie(
                DW_TAG.subprogram,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, 'abs'),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DwarfAttrib(DW_AT.low_pc, DW_FORM.addr, 0x7fc3eb9b1c30),
                ],
                [
                    DwarfDie(
                        DW_TAG.formal_parameter,
                        [DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0)],
                    ),
                ]
            ),
        ]
        type_ = function_type(int_type('int', 4, True),
                              ((int_type('int', 1, True),),), False)

        oindex = self.object_index(dies)
        self.assertEqual(oindex.find('abs'),
                         PartialObject(type=type_, address=0x7fc3eb9b1c30,
                                       little_endian=True))
        self.assertEqual(oindex.find('abs', flags=FindObjectFlags.FUNCTION),
                         oindex.find('abs'))
        self.assertRaisesRegex(LookupError, 'could not find variable',
                               oindex.find, 'abs',
                               flags=FindObjectFlags.VARIABLE)

        del dies[1].attribs[2]
        oindex = self.object_index(dies)
        self.assertRaisesRegex(LookupError, 'could not find address',
                               oindex.find, 'abs')

    def test_variable(self):
        dies = [
            int_die,
            DwarfDie(
                DW_TAG.variable,
                [
                    DwarfAttrib(DW_AT.name, DW_FORM.string, 'x'),
                    DwarfAttrib(DW_AT.type, DW_FORM.ref4, 0),
                    DwarfAttrib(DW_AT.location, DW_FORM.exprloc,
                                b'\x03\x04\x03\x02\x01\xff\xff\xff\xff'),
                ],
            ),
        ]

        oindex = self.object_index(dies)
        self.assertEqual(oindex.find('x'),
                         PartialObject(type=int_type('int', 4, True),
                                       address=0xffffffff01020304,
                                       little_endian=True))
        self.assertEqual(oindex.find('x', flags=FindObjectFlags.VARIABLE),
                         oindex.find('x'))
        self.assertRaisesRegex(LookupError, 'could not find constant',
                               oindex.find, 'x',
                               flags=FindObjectFlags.CONSTANT)

        del dies[1].attribs[2]
        oindex = self.object_index(dies)
        self.assertRaisesRegex(LookupError, 'could not find address',
                               oindex.find, 'x')

        dies[1].attribs.insert(
            2, DwarfAttrib(DW_AT.location, DW_FORM.exprloc, b'\xe0'))
        oindex = self.object_index(dies)
        self.assertRaisesRegex(FileFormatError, 'unimplemented operation',
                               oindex.find, 'x')

    def test_not_found(self):
        oindex = self.object_index([int_die])
        self.assertRaisesRegex(LookupError, 'could not find', oindex.find, 'y')
