from drgn.dwarf import parse_sleb128, parse_uleb128
import unittest


"""
def encode_uleb128(value):
    encoded = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return encoded
"""


class TestLeb128(unittest.TestCase):
    def test_negative_offset(self):
        with self.assertRaises(EOFError):
            parse_uleb128(b'', -1)
        with self.assertRaises(EOFError):
            parse_sleb128(b'', -1)

    def test_truncated(self):
        cases = [
            b'',
            b'\x80',
        ]
        for case in cases:
            with self.subTest(case=case, signed=False), \
                    self.assertRaises(EOFError):
                parse_uleb128(case)
            with self.subTest(case=case, signed=True), \
                    self.assertRaises(EOFError):
                parse_sleb128(case)

    def test_uleb128(self):
        self.assertEqual(parse_uleb128(b'\x00'), 0)
        self.assertEqual(parse_uleb128(b'\x02'), 2)
        self.assertEqual(parse_uleb128(b'\x7f'), 127)
        self.assertEqual(parse_uleb128(b'\x80\x01'), 128)
        self.assertEqual(parse_uleb128(b'\x81\x01'), 129)
        self.assertEqual(parse_uleb128(b'\x82\x01'), 130)
        self.assertEqual(parse_uleb128(b'\xb9\x64'), 12857)
        self.assertEqual(parse_uleb128(b'\xbf\x84\x3d'), 999999)
        self.assertEqual(parse_uleb128(b'\x95\x9a\xef\x3a'), 123456789)
        self.assertEqual(parse_uleb128(b'\xff\xff\xff\xff\x0f'), 0xffffffff)
        self.assertEqual(parse_uleb128(b'\x90\xf1\xd9\xa2\xa3\x02'), 0x1234567890)
        self.assertEqual(parse_uleb128(b'\xff\xff\xff\xff\xff\xff\xff\xff\x7f'),
                         2**63 - 1)
        self.assertEqual(parse_uleb128(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00'),
                         2**63 - 1)
        self.assertEqual(parse_uleb128(b'\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01'),
                         2**63)
        self.assertEqual(parse_uleb128(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01'),
                         2**64 - 1)

    def test_uleb128_overflow(self):
        cases = [
            b'\x80\x80\x80\x80\x80\x80\x80\x80\x80\x02',  # 2**64
            b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x03',  # 2**65 - 1
            b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x03',  # 2**72 - 1
        ]
        for encoded in cases:
            with self.subTest(encoded=encoded), self.assertRaises(OverflowError):
                parse_uleb128(encoded)

    def test_sleb128(self):
        self.assertEqual(parse_sleb128(b'\x00'), 0)
        self.assertEqual(parse_sleb128(b'\x02'), 2)
        self.assertEqual(parse_sleb128(b'\x7e'), -2)
        self.assertEqual(parse_sleb128(b'\xff\x00'), 127)
        self.assertEqual(parse_sleb128(b'\x81\x7f'), -127)
        self.assertEqual(parse_sleb128(b'\x80\x01'), 128)
        self.assertEqual(parse_sleb128(b'\x80\x7f'), -128)
        self.assertEqual(parse_sleb128(b'\x81\x01'), 129)
        self.assertEqual(parse_sleb128(b'\xff\x7e'), -129)
        self.assertEqual(parse_sleb128(b'\xff\xff\xff\xff\x07'), 2**31 - 1)
        self.assertEqual(parse_sleb128(b'\x80\x80\x80\x80\x78'), -2**31)
        self.assertEqual(parse_sleb128(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00'),
                         2**63 - 1)
        self.assertEqual(parse_sleb128(b'\x80\x80\x80\x80\x80\x80\x80\x80\x80\x7f'),
                         -2**63)
        self.assertEqual(parse_sleb128(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f'),
                         -1)

    def test_sleb128_overflow(self):
        cases = [
            b'\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01',  # 2**63
            b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01',  # 2**64 - 1
        ]
        for encoded in cases:
            with self.subTest(encoded=encoded), self.assertRaises(OverflowError):
                parse_sleb128(encoded)
