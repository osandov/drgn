import drgn.lldwarf as lldwarf
import unittest


class TestAbbrevObject(unittest.TestCase):
    def test_object(self):
        decl = lldwarf.AbbrevDecl(0x11, True, ((0x03, 0x08), (0x0c, 0x0b)))
        self.assertEqual(decl.tag, 0x11)
        self.assertEqual(decl.children, True)
        self.assertEqual(decl[0], (0x03, 0x08))
        self.assertEqual(decl[1], (0x0c, 0x0b))
        self.assertEqual(decl[-1], (0x0c, 0x0b))
        self.assertEqual(decl[-2], (0x03, 0x08))
        with self.assertRaises(IndexError):
            decl[2]
        with self.assertRaises(IndexError):
            decl[-3]

    def test_init_errors(self):
        with self.assertRaises(TypeError):
            lldwarf.AbbrevDecl(0x11, False, None)
        with self.assertRaises(TypeError):
            lldwarf.AbbrevDecl(0x11, False, (None,))
        with self.assertRaises(TypeError):
            lldwarf.AbbrevDecl(0x11, False, ((None, None),))
        with self.assertRaisesRegex(ValueError, 'pair'):
            lldwarf.AbbrevDecl(0x11, False, ((1, 2, 3),))

    def test_init_overflow(self):
        with self.assertRaisesRegex(OverflowError, 'tag'):
            lldwarf.AbbrevDecl(2**64, False, ())
        with self.assertRaisesRegex(OverflowError, 'name'):
            lldwarf.AbbrevDecl(0x11, False, ((2**64, 0x08),))
        with self.assertRaisesRegex(OverflowError, 'form'):
            lldwarf.AbbrevDecl(0x11, False, ((0x03, 2**64),))

    def test_repr(self):
            decl = lldwarf.AbbrevDecl(0x11, False, ())
            self.assertEqual(repr(decl), 'AbbrevDecl(tag=17, children=False, attributes=())')

            decl = lldwarf.AbbrevDecl(0x11, False, ((0x03, 0x08),))
            self.assertEqual(repr(decl), 'AbbrevDecl(tag=17, children=False, attributes=((3, 8),))')


class TestParseAbbrev(unittest.TestCase):
    def test_negative_offset(self):
        with self.assertRaises(ValueError):
            lldwarf.parse_abbrev_table(b'', -1)

    def test_empty_table(self):
        buf = b'\0'
        abbrev_table = {}
        self.assertEqual(lldwarf.parse_abbrev_table(buf), abbrev_table)

    def test_empty_decl(self):
        buf = (b'\x01'  # code = 1
               b'\x11'  # tag = 0x11 (DW_TAG_compile_unit)
               b'\0'    # DW_CHILDREN_no
               b'\0\0'  # null attribute spec
               b'\0')   # null attribute declaration
        abbrev_table = {
            1: lldwarf.AbbrevDecl(0x11, False, ()),
        }
        self.assertEqual(lldwarf.parse_abbrev_table(buf), abbrev_table)

    def test_one_attrib(self):
        buf = (b'\x01'      # code = 1
               b'\x11'      # tag = 0x11 (DW_TAG_compile_unit)
               b'\0'        # DW_CHILDREN_no
               b'\x03\x08'  # name = 0x03 (DW_AT_name), form = 0x08 (DW_FORM_string)
               b'\0\0'      # null attribute spec
               b'\0')       # null attribute declaration
        abbrev_table = {
            1: lldwarf.AbbrevDecl(0x11, False, ((0x03, 0x08),)),
        }
        self.assertEqual(lldwarf.parse_abbrev_table(buf), abbrev_table)

    def test_two_attribs(self):
        buf = (b'\x01'      # code = 1
               b'\x11'      # tag = 0x11 (DW_TAG_compile_unit)
               b'\x01'      # DW_CHILDREN_yes
               b'\x03\x08'  # name = 0x03 (DW_AT_name), form = 0x08 (DW_FORM_string)
               b'\x0c\x0b'  # name = 0x03 (DW_AT_bit_offset), form = 0x0b (DW_FORM_data1)
               b'\0\0'      # null attribute spec
               b'\0')       # null attribute declaration
        abbrev_table = {
            1: lldwarf.AbbrevDecl(0x11, True, ((0x03, 0x08), (0x0c, 0x0b))),
        }
        self.assertEqual(lldwarf.parse_abbrev_table(buf), abbrev_table)

    def test_duplicate_code(self):
        buf = (b'\x01'  # code = 1
               b'\x11'  # tag = 0x11 (DW_TAG_compile_unit)
               b'\0'    # DW_CHILDREN_no
               b'\0\0'  # null attribute spec
               b'\x01'  # code = 1
               b'\x11'  # tag = 0x11 (DW_TAG_compile_unit)
               b'\0'    # DW_CHILDREN_no
               b'\0\0'  # null attribute spec
               b'\0')   # null attribute declaration
        with self.assertRaisesRegex(ValueError, 'duplicate abbreviation code'):
            lldwarf.parse_abbrev_table(buf)

    def test_truncated(self):
        buf = (b'\x01'  # code = 1
               b'\x11'  # tag = 0x11 (DW_TAG_compile_unit)
               b'\0'    # DW_CHILDREN_no
               b'\0\0'  # null attribute spec
               b'\0')   # null attribute declaration
        for i in range(len(buf)):
            with self.assertRaisesRegex(ValueError, 'abbreviation .* truncated'):
                lldwarf.parse_abbrev_table(buf[:i])
