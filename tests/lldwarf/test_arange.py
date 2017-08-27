import drgn.lldwarf as lldwarf
import unittest


class TestParseArangeTableHeader(unittest.TestCase):
    def test_negative_offset(self):
        with self.assertRaises(ValueError):
            lldwarf.parse_arange_table_header(b'', -1)

    def test_32bit(self):
        buf = (b'\xc8\x00\x00\x00'  # unit_length
               b'\x02\x00'          # version
               b'\x00\x00\x00\x00'  # debug_info_offset
               b'\x08'              # address_size
               b'\x00')             # segment_size
        header = lldwarf.ArangeTableHeader(
            unit_length=200,
            version=2,
            debug_info_offset=0,
            address_size=8,
            segment_size=0,
            is_64_bit=False,
        )

        for i in range(len(buf)):
            with self.assertRaisesRegex(ValueError, 'address range table header is truncated'):
                lldwarf.parse_arange_table_header(buf[:i])

        self.assertEqual(lldwarf.parse_arange_table_header(buf), header)

    def test_64bit(self):
        buf = (b'\xff\xff\xff\xff'
               b'\xc8\x00\x00\x00\x00\x00\x00\x00'  # unit_length
               b'\x02\x00'                          # version
               b'\x00\x00\x00\x00\x00\x00\x00\x00'  # debug_info_offset
               b'\x08'              # address_size
               b'\x00')             # segment_size
        header = lldwarf.ArangeTableHeader(
            unit_length=200,
            version=2,
            debug_info_offset=0,
            address_size=8,
            segment_size=0,
            is_64_bit=True,
        )

        for i in range(len(buf)):
            with self.assertRaisesRegex(ValueError, 'address range table header is truncated'):
                lldwarf.parse_arange_table_header(buf[:i])

        self.assertEqual(lldwarf.parse_arange_table_header(buf), header)

    def test_offset(self):
        buf = (b'\x01'              # padding
               b'\xc8\x00\x00\x00'  # unit_length
               b'\x02\x00'          # version
               b'\x00\x00\x00\x00'  # debug_info_offset
               b'\x08'              # address_size
               b'\x00')             # segment_size
        header = lldwarf.ArangeTableHeader(
            unit_length=200,
            version=2,
            debug_info_offset=0,
            address_size=8,
            segment_size=0,
            is_64_bit=False,
        )

        self.assertEqual(lldwarf.parse_arange_table_header(buf, 1), header)
