import drgn.lldwarf as lldwarf
import unittest


class TestArangeTableHeaderObject(unittest.TestCase):
    def test_offset(self):
        header = lldwarf.ArangeTableHeader(
            offset=70,
            unit_length=200,
            version=2,
            debug_info_offset=0,
            address_size=8,
            segment_size=0,
            is_64_bit=False,
        )

        self.assertEqual(header.table_offset(), 96)
        self.assertEqual(header.next_offset(), 274)

        header.is_64_bit = True
        self.assertEqual(header.table_offset(), 96)
        self.assertEqual(header.next_offset(), 282)

    def test_offset_overflow(self):
        header = lldwarf.ArangeTableHeader(
            offset=2**63 - 12,
            unit_length=2**64 - 4,
            version=2,
            debug_info_offset=0,
            address_size=8,
            segment_size=0,
            is_64_bit=False,
        )
        with self.assertRaises(OverflowError):
            header.table_offset()
        with self.assertRaises(OverflowError):
            header.next_offset()

        header.offset = 2**63 - 8
        header.unit_length = 4
        with self.assertRaises(OverflowError):
            header.next_offset()

        header.offset = 2**63 - 24
        header.unit_length = 2**64 - 12
        header.is_64_bit = True
        with self.assertRaises(OverflowError):
            header.table_offset()
        with self.assertRaises(OverflowError):
            header.next_offset()

        header.offset = 2**63 - 16
        header.unit_length = 4
        with self.assertRaises(OverflowError):
            header.next_offset()


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
            offset=0,
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
            offset=0,
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
            offset=1,
            unit_length=200,
            version=2,
            debug_info_offset=0,
            address_size=8,
            segment_size=0,
            is_64_bit=False,
        )

        self.assertEqual(lldwarf.parse_arange_table_header(buf, 1), header)
