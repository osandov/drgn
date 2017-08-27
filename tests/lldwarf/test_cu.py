import drgn.lldwarf as lldwarf
import unittest


class TestParseCompilationUnitHeader(unittest.TestCase):
    def test_negative_offset(self):
        with self.assertRaises(ValueError):
            lldwarf.parse_compilation_unit_header(b'', -1)

    def test_32bit(self):
        buf = (b'\xc8\x00\x00\x00'  # unit_length
               b'\x02\x00'          # version
               b'\x00\x00\x00\x00'  # debug_abbrev_offset
               b'\x08')             # address_size
        header = lldwarf.CompilationUnitHeader(
            unit_length=200,
            version=2,
            debug_abbrev_offset=0,
            address_size=8,
            is_64_bit=False,
        )

        for i in range(len(buf)):
            with self.assertRaisesRegex(ValueError, 'compilation unit header is truncated'):
                lldwarf.parse_compilation_unit_header(buf[:i])

        self.assertEqual(lldwarf.parse_compilation_unit_header(buf), header)

    def test_64bit(self):
        buf = (b'\xff\xff\xff\xff'
               b'\xc8\x00\x00\x00\x00\x00\x00\x00'  # unit_length
               b'\x02\x00'                          # version
               b'\x00\x00\x00\x00\x00\x00\x00\x00'  # debug_abbrev_offset
               b'\x08')                             # address_size
        header = lldwarf.CompilationUnitHeader(
            unit_length=200,
            version=2,
            debug_abbrev_offset=0,
            address_size=8,
            is_64_bit=True,
        )

        for i in range(len(buf)):
            with self.assertRaisesRegex(ValueError, 'compilation unit header is truncated'):
                lldwarf.parse_compilation_unit_header(buf[:i])

        self.assertEqual(lldwarf.parse_compilation_unit_header(buf), header)

    def test_offset(self):
        buf = (b'\x01'              # padding
               b'\xc8\x00\x00\x00'  # unit_length
               b'\x02\x00'          # version
               b'\x00\x00\x00\x00'  # debug_abbrev_offset
               b'\x08')             # address_size
        header = lldwarf.CompilationUnitHeader(
            unit_length=200,
            version=2,
            debug_abbrev_offset=0,
            address_size=8,
            is_64_bit=False,
        )

        self.assertEqual(lldwarf.parse_compilation_unit_header(buf, 1), header)
