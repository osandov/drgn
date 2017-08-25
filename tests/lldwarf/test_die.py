import drgn.lldwarf as lldwarf
from drgn.dwarf.defs import DW_TAG, DW_FORM, DW_AT
import unittest


class TestDieObject(unittest.TestCase):
    def test_find(self):
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.sdata, -99),))
        self.assertEqual(die.find(DW_AT.lo_user), (DW_FORM.sdata, -99))
        with self.assertRaises(KeyError):
            die.find(DW_AT.name)

    def test_init_errors(self):
        with self.assertRaises(TypeError):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, None)
        with self.assertRaises(TypeError):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, (None,))
        with self.assertRaises(TypeError):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((None, None, None),))
        with self.assertRaisesRegex(ValueError, 'triple'):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((1, 2, 3, 4),))

    def test_init_overflow(self):
        with self.assertRaisesRegex(OverflowError, 'offset'):
            lldwarf.DwarfDie(2**63, 10, DW_TAG.lo_user, None, ())
        with self.assertRaisesRegex(OverflowError, 'die_length'):
            lldwarf.DwarfDie(0, 2**63, DW_TAG.lo_user, None, ())
        with self.assertRaisesRegex(OverflowError, 'tag'):
            lldwarf.DwarfDie(0, 10, 2**64, None, ())
        with self.assertRaisesRegex(OverflowError, 'name'):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((2**64, DW_FORM.flag_present, True),))
        with self.assertRaisesRegex(OverflowError, 'form'):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, 2**64, True),))

    def test_udata(self):
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.udata, 2**33),))
        self.assertEqual(die[0], (DW_AT.lo_user, DW_FORM.udata, 2**33))
        with self.assertRaises(OverflowError):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.udata, 2**64),))
        with self.assertRaises(TypeError):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.udata, 'foo'),))

    def test_sdata(self):
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.sdata, -2**33),))
        self.assertEqual(die[0], (DW_AT.lo_user, DW_FORM.sdata, -2**33))
        with self.assertRaises(OverflowError):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.sdata, 2**63),))
        with self.assertRaises(TypeError):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.sdata, 'foo'),))

    def test_string(self):
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.string, (0, 20)),))
        self.assertEqual(die[0], (DW_AT.lo_user, DW_FORM.string, (0, 20)))
        with self.assertRaises(TypeError):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.string, None),))
        with self.assertRaises(TypeError):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.string, (None, None)),))
        with self.assertRaises(ValueError):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.string, (1, 2, 3)),))
        with self.assertRaisesRegex(OverflowError, 'offset'):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.string, (2**63, 1)),))
        with self.assertRaisesRegex(OverflowError, 'length'):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.string, (0, 2**63)),))

    def test_data(self):
        with self.assertRaises(TypeError):
            lldwarf.DwarfDie(0, 0, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.data1, 64),))
        with self.assertRaises(ValueError):
            lldwarf.DwarfDie(0, 0, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.data1, b'aa'),))
        with self.assertRaises(ValueError):
            lldwarf.DwarfDie(0, 0, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.data2, b'aaa'),))
        with self.assertRaises(ValueError):
            lldwarf.DwarfDie(0, 0, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.data4, b'aaa'),))
        with self.assertRaises(ValueError):
            lldwarf.DwarfDie(0, 0, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.data8, b''),))

    def test_flag(self):
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.flag, True),))
        self.assertEqual(die[0], (DW_AT.lo_user, DW_FORM.flag, True))
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.flag, 0),))
        self.assertEqual(die[0], (DW_AT.lo_user, DW_FORM.flag, False))

    def test_flag_present(self):
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.flag_present, True),))
        self.assertEqual(die[0], (DW_AT.lo_user, DW_FORM.flag_present, True))
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.flag_present, 0),))
        self.assertEqual(die[0], (DW_AT.lo_user, DW_FORM.flag_present, True))

    def test_unknown_form(self):
        with self.assertRaisesRegex(ValueError, f'unknown form {2**64 - 1}'):
            lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, 2**64 - 1, None),))

    def test_repr(self):
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ())
        self.assertEqual(repr(die), f'DwarfDie(offset=0, die_length=10, tag={DW_TAG.lo_user.value}, children=None, attributes=())')
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.flag, True),))
        self.assertEqual(repr(die), f'DwarfDie(offset=0, die_length=10, tag={DW_TAG.lo_user.value}, children=None, attributes=(({DW_AT.lo_user.value}, {DW_FORM.flag.value}, True),))')

    def test_recursive_repr(self):
        die = lldwarf.DwarfDie(0, 10, DW_TAG.lo_user, None, ())
        die.children = [die]
        self.assertEqual(repr(die), f'DwarfDie(offset=0, die_length=10, tag={DW_TAG.lo_user.value}, children=[DwarfDie(...)], attributes=())')


header = lldwarf.CompilationUnitHeader(
    offset=0,
    unit_length=200,
    version=2,
    debug_abbrev_offset=0,
    address_size=8,
    is_64_bit=False,
)


header32addr = lldwarf.CompilationUnitHeader(
    offset=0,
    unit_length=200,
    version=2,
    debug_abbrev_offset=0,
    address_size=4,
    is_64_bit=False,
)

header64 = lldwarf.CompilationUnitHeader(
    offset=0,
    unit_length=200,
    version=2,
    debug_abbrev_offset=0,
    address_size=8,
    is_64_bit=True,
)


class TestParseDie(unittest.TestCase):
    def test_negative_offset(self):
        with self.assertRaises(ValueError):
            lldwarf.parse_die(header, {}, b'', -1)
        with self.assertRaises(ValueError):
            lldwarf.parse_die_siblings(header, {}, b'', -1)

    def test_bad_cu(self):
        with self.assertRaises(TypeError):
            lldwarf.parse_die(None, {}, b'')

    def test_bad_abbrev_table(self):
        with self.assertRaises(TypeError):
            lldwarf.parse_die(header, None, b'')

    def test_null(self):
        self.assertIsNone(lldwarf.parse_die(header, {}, b'\0'))

    def test_unknown_abbreviation(self):
        with self.assertRaisesRegex(ValueError, 'unknown abbreviation code'):
            lldwarf.parse_die(header, {}, b'\x01\xff')

    def assertDie(self, header, abbrev_table, buf, die_args):
        tag, children, attribs = die_args
        die = lldwarf.DwarfDie(0, len(buf), tag, children, attribs)
        self.assertEqual(tuple(die), tuple(attribs))
        self.assertEqual(lldwarf.parse_die(header, abbrev_table, buf), die)

    def test_address(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.addr),)),
        }

        self.assertDie(header, abbrev_table, b'\x01\xff\xff\xff\xff\xff\xff\xff\x7f',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.addr, 2**63 - 1),)))
        self.assertDie(header32addr, abbrev_table, b'\x01\xff\xff\xff\x7f',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.addr, 2**31 - 1),)))

        bogus_header = lldwarf.CompilationUnitHeader(
            offset=0,
            unit_length=200,
            version=2,
            debug_abbrev_offset=0,
            address_size=1,
            is_64_bit=False,
        )
        with self.assertRaisesRegex(ValueError, 'unsupported address size'):
            lldwarf.parse_die(bogus_header, abbrev_table, b'\x01\xff')

    def test_block(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.block1),)),
            2: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.block2),)),
            3: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.block4),)),
            4: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.block),)),
            5: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.exprloc),)),
        }

        self.assertDie(header, abbrev_table, b'\x01\x04aaaa',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.block1, (2, 4)),)))
        self.assertDie(header, abbrev_table, b'\x02\x01\x00b',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.block2, (3, 1)),)))
        self.assertDie(header, abbrev_table, b'\x03\x10\x00\x00\x00' + b'z' * 16,
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.block4, (5, 16)),)))
        self.assertDie(header, abbrev_table, b'\x04\x03xyz',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.block, (2, 3)),)))
        self.assertDie(header, abbrev_table, b'\x05\x0f012345678901234',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.exprloc, (2, 15)),)))
        with self.assertRaisesRegex(ValueError, 'attribute length too big'):
            lldwarf.parse_die(header, abbrev_table, b'\x05\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01')

    def test_data(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.data1),)),
            2: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.data2),)),
            3: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.data4),)),
            4: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.data8),)),
        }

        self.assertDie(header, abbrev_table, b'\x01a',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.data1, b'a'),)))

        self.assertDie(header, abbrev_table, b'\x02ab',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.data2, b'ab'),)))

        self.assertDie(header, abbrev_table, b'\x03abcd',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.data4, b'abcd'),)))

        self.assertDie(header, abbrev_table, b'\x04abcdefgh',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.data8, b'abcdefgh'),)))

    def test_constant(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.udata),)),
            2: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.sdata),)),
        }

        self.assertDie(header, abbrev_table, b'\x01\x64',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.udata, 100),)))

        self.assertDie(header, abbrev_table, b'\x02\x7f',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.sdata, -1),)))

        with self.assertRaises(OverflowError):
            lldwarf.DwarfDie(0, 0, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.udata, 2**64),))
        with self.assertRaises(OverflowError):
            lldwarf.DwarfDie(0, 0, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.sdata, 2**63),))
        with self.assertRaises(OverflowError):
            lldwarf.DwarfDie(0, 0, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.sdata, -2**63 - 1),))

    def test_flag(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.flag),)),
            2: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.flag_present),)),
        }

        self.assertDie(header, abbrev_table, b'\x01\x01',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.flag, True),)))
        self.assertDie(header, abbrev_table, b'\x01\x00',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.flag, False),)))
        self.assertDie(header, abbrev_table, b'\x02',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.flag_present, True),)))

    def test_reference(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.ref1),)),
            2: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.ref2),)),
            3: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.ref4),)),
            4: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.ref8),)),
            5: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.ref_sig8),)),
            6: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.ref_udata),)),
        }

        self.assertDie(header, abbrev_table, b'\x01\xff',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.ref1, 255),)))
        self.assertDie(header, abbrev_table, b'\x02\x10\x27',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.ref2, 10000),)))
        self.assertDie(header, abbrev_table, b'\x03\x00\x00\x00\x80',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.ref4, 2**31),)))
        self.assertDie(header, abbrev_table, b'\x04\x00\x00\x00\x00\x00\x00\x00\x80',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.ref8, 2**63),)))
        self.assertDie(header, abbrev_table, b'\x05\x00\x00\x00\x00\x00\x00\x00\x80',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.ref_sig8, 2**63),)))
        self.assertDie(header, abbrev_table, b'\x06\x00',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.ref_udata, 0),)))

    def test_sec_offset(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.sec_offset),)),
        }

        self.assertDie(header, abbrev_table, b'\x01\xff\xff\xff\x7f',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.sec_offset, 2**31 - 1),)))
        self.assertDie(header64, abbrev_table, b'\x01\xff\xff\xff\xff\xff\xff\xff\x7f',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.sec_offset, 2**63 - 1),)))

    def test_strp(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.strp),)),
        }

        self.assertDie(header, abbrev_table, b'\x01\xff\xff\xff\x7f',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.strp, 2**31 - 1),)))
        self.assertDie(header64, abbrev_table, b'\x01\xff\xff\xff\xff\xff\xff\xff\x7f',
                       (DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.strp, 2**63 - 1),)))

    def test_string(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, False,
                                  ((DW_AT.lo_user, DW_FORM.string),
                                   (DW_AT.lo_user, DW_FORM.string))),
        }

        self.assertDie(header, abbrev_table, b'\x01foo\0asdf\0',
                       (DW_TAG.lo_user, None,
                        ((DW_AT.lo_user, DW_FORM.string, (1, 3)),
                         (DW_AT.lo_user, DW_FORM.string, (5, 4)))))

        with self.assertRaisesRegex(ValueError, 'unterminated string'):
            lldwarf.parse_die(header, abbrev_table, b'\x01foo')

    def test_recursive(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, True, ((DW_AT.lo_user, DW_FORM.udata),)),
            2: lldwarf.AbbrevDecl(DW_TAG.lo_user + 1, False, ((DW_AT.lo_user + 1, DW_FORM.sdata),)),
        }
        die = lldwarf.parse_die(header, abbrev_table, b'\x01\x01\x02\x02\x00', recurse=True)

        child = lldwarf.DwarfDie(2, 2, DW_TAG.lo_user + 1, None, ((DW_AT.lo_user + 1, DW_FORM.sdata, 2),))
        parent = lldwarf.DwarfDie(0, 2, DW_TAG.lo_user, [child], ((DW_AT.lo_user, DW_FORM.udata, 1),))

        self.assertEqual(die, parent)

    def test_siblings(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, False, ((DW_AT.lo_user, DW_FORM.udata),)),
            2: lldwarf.AbbrevDecl(DW_TAG.lo_user + 1, False, ((DW_AT.lo_user + 1, DW_FORM.sdata),)),
        }
        siblings = lldwarf.parse_die_siblings(header, abbrev_table, b'\x01\x01\x02\x02\x00')
        self.assertEqual(siblings, [
            lldwarf.DwarfDie(0, 2, DW_TAG.lo_user, None, ((DW_AT.lo_user, DW_FORM.udata, 1),)),
            lldwarf.DwarfDie(2, 2, DW_TAG.lo_user + 1, None, ((DW_AT.lo_user + 1, DW_FORM.sdata, 2),)),
        ])

    def test_siblings_skip(self):
        abbrev_table = {
            1: lldwarf.AbbrevDecl(DW_TAG.lo_user, True, ((DW_AT.sibling, DW_FORM.udata),)),
            2: lldwarf.AbbrevDecl(DW_TAG.lo_user + 1, False, ((DW_AT.lo_user + 1, DW_FORM.sdata),)),
        }
        siblings = lldwarf.parse_die_siblings(header, abbrev_table, b'\x01\x04\x02\x02\x02\x03\x00')
        parent_die = lldwarf.DwarfDie(0, 2, DW_TAG.lo_user, None, ((DW_AT.sibling, DW_FORM.udata, 4),))
        del parent_die.children
        self.assertEqual(siblings, [
            parent_die,
            lldwarf.DwarfDie(4, 2, DW_TAG.lo_user + 1, None, ((DW_AT.lo_user + 1, DW_FORM.sdata, 3),)),
        ])
